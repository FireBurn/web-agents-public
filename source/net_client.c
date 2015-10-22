/**
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2014 - 2015 ForgeRock AS.
 */

#ifdef _GNU_SOURCE
#undef _GNU_SOURCE /* prefer strerror_r */
#endif
#include "platform.h"
#include "am.h"
#include "utility.h"
#include "net_client.h"
#include "list.h"

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#define RECV_BUFFER_SZ 1024

#define AM_NET_CONNECT_TIMEOUT 8 /* in sec */

enum {
    HEADER_NONE = 0,
    HEADER_FIELD,
    HEADER_VALUE,
    HEADER_ERROR
};

#ifdef _WIN32
static short connect_ev = POLLWRNORM;
static short connected_ev = POLLWRNORM;
static short read_ev = POLLRDNORM;
static short read_avail_ev = POLLRDNORM | POLLHUP;
#else
static short connect_ev = POLLOUT | POLLNVAL | POLLERR | POLLHUP;
static short connected_ev = POLLOUT;
static short read_ev = POLLIN | POLLNVAL | POLLERR | POLLHUP;
static short read_avail_ev = POLLIN | POLLHUP;
#endif

#ifdef _WIN32
#define net_log_error(i,e) \
    do {\
        LPSTR es = NULL; \
        if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, 0, e, 0, (LPSTR) & es, 0, 0) == 0) { \
            AM_LOG_ERROR(i, "net_error(%s:%d) unknown error code (%X)", __FILE__, __LINE__, e);\
        } else { \
            char *p = strchr(es, '\r'); \
            if (p != NULL) {\
                *p = '\0';\
            }\
            AM_LOG_ERROR(i, "net_error(%s:%d): %s (%X)", __FILE__, __LINE__, es, e); \
            LocalFree(es);\
        }\
    } while(0)
#else
#define net_log_error(i, e) \
    do {\
        size_t size = 1024;\
        char *tmp, *es = malloc(size + 1);\
        if (es != NULL) {\
            while (strerror_r(e, es, size) == -1 && errno == ERANGE) {\
                size *= 2;\
                tmp = realloc(es, size + 1);\
                if (tmp == NULL) {\
                    am_free(es);\
                    es = NULL;\
                    break;\
                }\
                es = tmp;\
            }\
            AM_LOG_ERROR(i, "net_error(%s:%d): %s (%d)", __FILE__, __LINE__, es, e);\
            am_free(es);\
        }\
    } while(0)
#endif

void net_init_ssl();
void net_shutdown_ssl();
void net_connect_ssl(am_net_t *n);
void net_close_ssl(am_net_t *n);
int net_read_ssl(am_net_t *n, const char *buf, int sz);
void net_write_ssl(am_net_t *n);
void net_close_ssl_notify(am_net_t *n);

void am_net_init() {
#ifdef _WIN32
    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
#endif
    net_init_ssl();
}

void am_net_shutdown() {
#ifdef _WIN32
    WSACleanup();
#endif
    net_shutdown_ssl();
}

static int net_error() {
    int e = 0;
#ifdef _WIN32
    e = WSAGetLastError();
#else
    e = errno;
#endif
    return e;
}

static int net_in_progress(int e) {
#ifdef _WIN32
    return (e == WSAEWOULDBLOCK || e == WSAEINPROGRESS);
#else
    return (e == EWOULDBLOCK || e == EINPROGRESS || e == EAGAIN);
#endif
}

static int net_close_socket(
#ifdef _WIN32
        SOCKET
#else
        int
#endif
        s) {
    if (s != INVALID_SOCKET)
#ifdef _WIN32
        shutdown(s, SD_BOTH);
    return closesocket(s);
#else
        shutdown(s, SHUT_RDWR);
    return close(s);
#endif
}

static int set_nonblocking(am_net_t *n, int cmd) {
#ifdef _WIN32
    u_long nonblock = cmd == 1 ? 1 : 0;
    if (ioctlsocket(n->sock, FIONBIO, &nonblock) == SOCKET_ERROR) {
        return -1;
    }
#else
    int ofdflags, fdflags;
    if ((fdflags = ofdflags = fcntl(n->sock, F_GETFL, 0)) == -1) {
        return -1;
    }
    if (cmd == 1) {
        fdflags |= O_NONBLOCK;
    } else {
        fdflags &= ~O_NONBLOCK;
    }
    if (fdflags != ofdflags) {
        if (fcntl(n->sock, F_SETFL, fdflags) == -1) {
            return -1;
        }
    }
#endif
    return 0;
}

#ifdef _WIN32
#define POLLFD WSAPOLLFD
#else
#define POLLFD struct pollfd
#endif

static int on_body_cb(http_parser *parser, const char *at, size_t length) {
    am_net_t *n = (am_net_t *) parser->data;
    if (n->on_data) n->on_data(n->data, at, length, 0);
    return 0;
}

static int on_header_field_cb(http_parser *parser, const char *at, size_t length) {
    am_net_t *n = (am_net_t *) parser->data;
    void *p;
    if (n->header_state == HEADER_ERROR) return 0;
    if (n->header_state != HEADER_FIELD) {
        n->num_headers++;
        p = realloc(n->header_fields, n->num_headers * sizeof (char *));
        if (p != NULL) {
            n->header_fields = p;
            n->header_fields[n->num_headers - 1] = strndup(at, length);
        } else {
            n->header_state = HEADER_ERROR;
            n->num_headers--;
        }
    } else {
        p = realloc(n->header_fields[n->num_headers - 1],
                strlen(n->header_fields[n->num_headers - 1]) + length + 1);
        if (p != NULL) {
            n->header_fields[n->num_headers - 1] = p;
            strncat(n->header_fields[n->num_headers - 1], at, length);
        } else {
            n->header_state = HEADER_ERROR;
        }
    }
    n->header_state = HEADER_FIELD;
    return 0;
}

static int on_header_value_cb(http_parser *parser, const char *at, size_t length) {
    am_net_t *n = (am_net_t *) parser->data;
    void *p;
    if (n->header_state == HEADER_ERROR) return 0;
    if (n->header_state != HEADER_VALUE) {
        n->num_header_values++;
        p = realloc(n->header_values, n->num_headers * sizeof (char *));
        if (p != NULL) {
            n->header_values = p;
            n->header_values[n->num_headers - 1] = strndup(at, length);
        } else {
            n->header_state = HEADER_ERROR;
            n->num_header_values--;
        }
    } else {
        p = realloc(n->header_values[n->num_headers - 1],
                strlen(n->header_values[n->num_headers - 1]) + length + 1);
        if (p != NULL) {
            n->header_values[n->num_headers - 1] = p;
            strncat(n->header_values[n->num_headers - 1], at, length);
        } else {
            n->header_state = HEADER_ERROR;
        }
    }
    n->header_state = HEADER_VALUE;
    return 0;
}

static int on_headers_complete_cb(http_parser *parser) {
    int i;
    am_net_t *n = (am_net_t *) parser->data;
    n->http_status = parser->status_code;
    if (n->num_headers != n->num_header_values || n->header_state == HEADER_ERROR) {
        AM_LOG_WARNING(n->instance_id,
                "on_headers_complete_cb(): response header fields and their values do not match (%d/%d)",
                n->num_headers, n->num_header_values);
        for (i = 0; i < n->num_headers; i++) {
            char *field = n->header_fields[i];
            AM_FREE(field);
        }
        for (i = 0; i < n->num_header_values; i++) {
            char *value = n->header_values[i];
            AM_FREE(value);
        }
        AM_FREE(n->header_fields, n->header_values);
        n->header_fields = NULL;
        n->header_values = NULL;
        n->num_headers = n->num_header_values = 0;
    }
    n->header_state = HEADER_NONE;
    return 0;
}

static int on_message_complete_cb(http_parser *parser) {
    am_net_t *n = (am_net_t *) parser->data;
    if (n->on_complete) n->on_complete(n->data, 0);
    return 0;
}

void am_net_options_create(am_config_t *conf, am_net_options_t *options, void (*log)(const char *, ...)) {
    int i;
    if (conf == NULL || options == NULL) return;

    options->local = conf->local;
    options->lb_enable = conf->lb_enable;
    options->net_timeout = conf->net_timeout;
    options->cert_trust = conf->cert_trust;
    options->keepalive = !conf->keepalive_disable;
    options->cert_key_pass_sz = conf->cert_key_pass_sz;
    options->server_id = NULL; /* server_id is set on request */
    options->notif_url = ISVALID(conf->notif_url) ? strdup(conf->notif_url) : NULL;
    options->ciphers = ISVALID(conf->ciphers) ? strdup(conf->ciphers) : NULL;
    options->cert_ca_file = ISVALID(conf->cert_ca_file) ? strdup(conf->cert_ca_file) : NULL;
    options->cert_file = ISVALID(conf->cert_file) ? strdup(conf->cert_file) : NULL;
    options->cert_key_file = ISVALID(conf->cert_key_file) ? strdup(conf->cert_key_file) : NULL;
    options->cert_key_pass = ISVALID(conf->cert_key_pass) ? strndup(conf->cert_key_pass, conf->cert_key_pass_sz) : NULL;
    options->tls_opts = ISVALID(conf->tls_opts) ? strdup(conf->tls_opts) : NULL;
    options->log = log;
    options->hostmap = NULL;
    options->hostmap_sz = 0;

    if (conf->hostmap_sz > 0 && conf->hostmap != NULL) {
        options->hostmap = malloc(conf->hostmap_sz * sizeof (char *));
        if (options->hostmap != NULL) {
            for (i = 0; i < conf->hostmap_sz; i++) {
                options->hostmap[i] = strdup(conf->hostmap[i]);
            }
            options->hostmap_sz = conf->hostmap_sz;
        }
    }
}

void am_net_options_delete(am_net_options_t *options) {
    int i;
    if (options == NULL) return;

    AM_FREE(options->ciphers, options->cert_ca_file, options->server_id, options->notif_url,
            options->cert_file, options->cert_key_file, options->tls_opts);
    if (options->cert_key_pass != NULL) {
        am_secure_zero_memory(options->cert_key_pass, options->cert_key_pass_sz);
        free(options->cert_key_pass);
    }
    options->notif_url = NULL;
    options->ciphers = NULL;
    options->server_id = NULL;
    options->cert_ca_file = NULL;
    options->cert_file = NULL;
    options->cert_key_file = NULL;
    options->tls_opts = NULL;
    options->cert_key_pass = NULL;
    options->cert_key_pass_sz = 0;
    options->log = NULL;

    if (options->hostmap != NULL) {
        for (i = 0; i < options->hostmap_sz; i++) {
            am_free(options->hostmap[i]);
        }
        free(options->hostmap);
        options->hostmap = NULL;
    }
    options->hostmap_sz = 0;
}


/**
 * Synchronous comms - where one thread creates a connection then
 * iteratively writes to server and reads HTTP response, then closes the connection.
 */


/**
 * poll with a timeout for server response, where the timeout includes includes system interrupts (EINTR) errors
 */
static int poll_with_interrupt(POLLFD fds[], int nfds, int msec) {
    uint64_t start_usec, end_usec;
    int ev;
    
    am_bool_t intr;
    do {
        intr = AM_FALSE;
        am_timer(&start_usec);
        ev = sockpoll(fds, nfds, msec);
        if (ev < 0 && net_error() == EINTR) {
            am_timer(&end_usec);
            msec -= (end_usec - start_usec) / 1000;
            if (msec < 0) {
                msec = 0;
            }
            intr = AM_TRUE;
        }
    } while (intr);
    return ev;
}

/**
 * create a non-blocking socket and connect to remote server
 */
static void sync_connect(am_net_t *n) {
    static const char *thisfunc = "sync_connect():";
    struct in6_addr serveraddr;
    struct addrinfo *rp, hints;
    int i, err = 0, on = 1;
    char port[7];
    am_timer_t tmr;
    int timeout = AM_NET_CONNECT_TIMEOUT;
    char *ip_address = n->uv.host;
    
    if (n->options != NULL) {
        timeout = n->options->net_timeout;
        
        /* try to use com.forgerock.agents.config.hostmap property values to
         * shortcut any host name resolution.
         */
        for (i = 0; i < n->options->hostmap_sz; i++) {
            char *sep = strchr(n->options->hostmap[i], '|');
            if (sep != NULL &&
                strncasecmp(n->options->hostmap[i], n->uv.host, sep - n->options->hostmap[i]) == 0) {
                ip_address = sep++;
                AM_LOG_DEBUG(n->instance_id, "%s found host '%s' (%s) entry in "AM_AGENTS_CONFIG_HOST_MAP,
                             thisfunc, n->uv.host, ip_address);
                break;
            }
        }
    }
    
    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    err = INETPTON(AF_INET, ip_address, &serveraddr);
    if (err == 1) {
        hints.ai_family = AF_INET;
        hints.ai_flags |= AI_NUMERICHOST;
    } else {
        err = INETPTON(AF_INET6, ip_address, &serveraddr);
        if (err == 1) {
            hints.ai_family = AF_INET6;
            hints.ai_flags |= AI_NUMERICHOST;
        }
    }
    
    snprintf(port, sizeof (port), "%d", n->uv.port);
    
    am_timer_start(&tmr);
    if ((err = getaddrinfo(ip_address, port, &hints, &n->ra)) != 0) {
        n->error = AM_EHOSTUNREACH;
        am_timer_stop(&tmr);
        am_timer_report(n->instance_id, &tmr, "getaddrinfo");
        return;
    }
    
    am_timer_stop(&tmr);
    am_timer_report(n->instance_id, &tmr, "getaddrinfo");
    
    for (rp = n->ra; rp != NULL; rp = rp->ai_next) {
        
        if (rp->ai_family != AF_INET && rp->ai_family != AF_INET6 &&
            rp->ai_socktype != SOCK_STREAM && rp->ai_protocol != IPPROTO_TCP) continue;
        
        if ((n->sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == INVALID_SOCKET) {
            AM_LOG_ERROR(n->instance_id,
                         "%s cannot create socket while connecting to %s:%d",
                         thisfunc, n->uv.host, n->uv.port);
            net_log_error(n->instance_id, net_error());
            continue;
        }
        
        if (setsockopt(n->sock, IPPROTO_TCP, TCP_NODELAY, (void *) &on, sizeof (on)) < 0) {
            net_log_error(n->instance_id, net_error());
        }
        if (setsockopt(n->sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof (on)) < 0) {
            net_log_error(n->instance_id, net_error());
        }
#ifdef SO_NOSIGPIPE
        if (setsockopt(n->sock, SOL_SOCKET, SO_NOSIGPIPE, (void *) &on, sizeof (on)) < 0) {
            net_log_error(n->instance_id, net_error());
        }
#endif
        if (set_nonblocking(n, 1) != 0) {
            n->error = AM_EPERM;
            continue;
        }
        
        err = connect(n->sock, rp->ai_addr, (SOCKLEN_T) rp->ai_addrlen);
        if (err == 0) {
            AM_LOG_DEBUG(n->instance_id, "%s connected to %s:%d (%s)",
                         thisfunc, n->uv.host, n->uv.port,
                         rp->ai_family == AF_INET ? "IPv4" : "IPv6");
            n->error = 0;
            if (n->uv.ssl) {
                net_connect_ssl(n);
                if (n->ssl.error != AM_SUCCESS) {
                    AM_LOG_ERROR(n->instance_id,
                                 "%s SSL/TLS connection to %s:%d (%s) failed (%s)",
                                 thisfunc, n->uv.host, n->uv.port,
                                 rp->ai_family == AF_INET ? "IPv4" : "IPv6",
                                 am_strerror(n->ssl.error));
                    net_close_socket(n->sock);
                    n->sock = INVALID_SOCKET;
                    n->error = n->ssl.error;
                    break;
                }
            }
            /* success */
            return;
        }
        
        if (err == INVALID_SOCKET && net_in_progress(net_error())) {
            POLLFD fds[1];
            memset(fds, 0, sizeof (fds));
            fds[0].fd = n->sock;
            fds[0].events = connect_ev;
            fds[0].revents = 0;
            
            err = sockpoll(fds, 1, timeout > 0 ? timeout * 1000 : -1);
            if (err > 0 && fds[0].revents & connected_ev) {
                int pe = 0;
                SOCKLEN_T pe_sz = sizeof (pe);
                err = getsockopt(n->sock, SOL_SOCKET, SO_ERROR, (char *) &pe, &pe_sz);
                if (err == 0 && pe == 0) {
                    AM_LOG_DEBUG(n->instance_id, "%s connected to %s:%d (%s)",
                                 thisfunc, n->uv.host, n->uv.port,
                                 rp->ai_family == AF_INET ? "IPv4" : "IPv6");
                    
                    n->error = 0;
                    if (n->uv.ssl) {
                        net_connect_ssl(n);
                        if (n->ssl.error != AM_SUCCESS) {
                            AM_LOG_ERROR(n->instance_id,
                                         "%s SSL/TLS connection to %s:%d (%s) failed (%s)",
                                         thisfunc, n->uv.host, n->uv.port,
                                         rp->ai_family == AF_INET ? "IPv4" : "IPv6",
                                         am_strerror(n->ssl.error));
                            net_close_socket(n->sock);
                            n->sock = INVALID_SOCKET;
                            n->error = n->ssl.error;
                            break;
                        }
                    }
                    /* success */
                    return;
                }
                net_log_error(n->instance_id, pe);
                n->error = AM_ECONNREFUSED;
            } else if (err == 0) {
                AM_LOG_WARNING(n->instance_id,
                               "%s timeout connecting to %s:%d (%s)",
                               thisfunc, n->uv.host, n->uv.port,
                               rp->ai_family == AF_INET ? "IPv4" : "IPv6");
                n->error = AM_ETIMEDOUT;
            } else {
                int pe = 0;
                SOCKLEN_T pe_sz = sizeof (pe);
                err = getsockopt(n->sock, SOL_SOCKET, SO_ERROR, (char *) &pe, &pe_sz);
                n->error = AM_ETIMEDOUT;
                break;
            }
        }
        
        net_close_socket(n->sock);
        n->sock = INVALID_SOCKET;
    }
}

/**
 * initialise http parser and connect to server
 */
int am_net_sync_connect(am_net_t *n) {
    static const char *thisfunc = "am_net_sync_connect():";

    if (n == NULL) {
        /* fatal - must not happen */
        return AM_EINVAL;
    }
    
    n->error = AM_ENOTSTARTED;
    n->sock = INVALID_SOCKET;
    n->ssl.request_data = NULL;
    n->ssl.ssl_handle = NULL;
    n->ssl.ssl_context = NULL;
    n->ssl.on = AM_FALSE;
    
    if (n->url == NULL) {
        return AM_EINVAL;
    }
    
    if (parse_url(n->url, &n->uv) != 0) {
        AM_LOG_ERROR(n->instance_id,
                     "%s failed to parse url %s", LOGEMPTY(n->url));
        return n->uv.error;
    }
    
    /* allocate memory for http_parser and initialize it */
    n->hs = calloc(1, sizeof (http_parser_settings));
    if (n->hs == NULL) {
        AM_LOG_ERROR(n->instance_id, "%s memory allocation error", thisfunc);
        return AM_ENOMEM;
    }
    
    n->hp = calloc(1, sizeof (http_parser));
    if (n->hp == NULL) {
        AM_LOG_ERROR(n->instance_id, "%s memory allocation error", thisfunc);
        return AM_ENOMEM;
    }
    
    n->hs->on_header_field = on_header_field_cb;
    n->hs->on_header_value = on_header_value_cb;
    n->hs->on_headers_complete = on_headers_complete_cb;
    n->hs->on_body = on_body_cb;
    n->hs->on_message_complete = on_message_complete_cb;
    
    http_parser_init(n->hp, HTTP_RESPONSE);
    n->hp->data = n;
    
    sync_connect(n);
    return n->error;
}

/**
 * write data to remote server
 */
int am_net_write(am_net_t *n, const char *data, size_t data_sz) {
    int status = 0, sent = 0, flags = 0;
    int er = 0, error = 0;
    SOCKLEN_T errlen = sizeof (error);
    if (n != NULL && data != NULL && data_sz > 0) {
        
        size_t len = data_sz;
        const char *buf = data;
        if (n->error != 0) {
            return n->error;
        }
        if (n->ssl.on) {
            n->ssl.request_data_sz = 0;
            am_free(n->ssl.request_data);
            n->ssl.request_data = malloc(data_sz);
            if (n->ssl.request_data == NULL) {
                return AM_ENOMEM;
            }
            memcpy(n->ssl.request_data, data, data_sz);
            n->ssl.request_data_sz = data_sz;
            net_write_ssl(n);
        } else {
#ifdef MSG_NOSIGNAL
            flags |= MSG_NOSIGNAL;
#endif
            er = getsockopt(n->sock, SOL_SOCKET, SO_ERROR, (void *) &error, &errlen);
            while (sent < (int) len) {
                int rv = send(n->sock, buf + sent, (int) len - sent, flags);
                if (rv < 0) {
                    if (net_in_progress(net_error())) {
                        POLLFD fds[1];
                        memset(fds, 0, sizeof (fds));
                        fds[0].fd = n->sock;
                        fds[0].events = connect_ev;
                        fds[0].revents = 0;
                        if (sockpoll(fds, 1, -1) == -1) {
                            break;
                        }
                        continue;
                    }
                    break;
                }
                if (rv == 0) {
                    break;
                }
                sent += rv;
            }
        }
    }
    return status;
}

/**
 * receive and parse http message, returning when message http message is complete
 */
void am_net_sync_recv(am_net_t *n, int timeout_secs) {
    int ev = 0;
    int poll_msec = timeout_secs * 1000;
    POLLFD fds[1];
    char *buffer;

    if (n == NULL) {
        return;
    }

    buffer = malloc(RECV_BUFFER_SZ);
    if (buffer == NULL) {
        n->error = AM_ENOMEM;
        return;
    }

    memset(fds, 0, sizeof (fds));
    n->reset_complete(n->data);
    
    while (ev != -1) {
        fds[0].fd = n->sock;
        fds[0].events = read_ev;
        fds[0].revents = 0;
        
        ev = poll_with_interrupt(fds, 1, poll_msec);
        if (ev == 0) {
            /* timeout */
            AM_LOG_WARNING(n->instance_id,
                           "%s timeout waiting for a response from a server", "am_net_sync_recv()");
            
            n->error = AM_ETIMEDOUT;
            break;
        }
        if (ev < 0) {
            net_log_error(n->instance_id, net_error());
            break;
        }
        if (ev == 1 && fds[0].revents & (POLLNVAL | POLLERR)) {
            if (n->on_close) n->on_close(n->data, 0);
            break;
        }
        if (ev == 1 && fds[0].revents & read_avail_ev) {
            /* read an output from a remote side */
            int got = 0;
            int error = 0;
            SOCKLEN_T errlen = sizeof (error);
            if (getsockopt(n->sock, SOL_SOCKET, SO_ERROR, (void *) &error, &errlen) == 0 && error != 0) {
                net_log_error(n->instance_id, error);
                n->error = error;
                break;
            }
            memset(buffer, 0, RECV_BUFFER_SZ);
            got = recv(n->sock, buffer, RECV_BUFFER_SZ, 0);
            if (n->ssl.on) {
                error = net_read_ssl(n, buffer, got);
                if (error != AM_SUCCESS) {
                    if (error != AM_EAGAIN) {
                        if (n->on_close) n->on_close(n->data, 0);
                        break;
                    }
                }
            } else {
                if (got < 0) {
                    if (!net_in_progress(net_error())) {
                        if (n->on_close) n->on_close(n->data, 0);
                        break;
                    }
                } else if (got == 0) {
                    if (n->on_close) n->on_close(n->data, 0);
                    break;
                } else {
                    http_parser_execute(n->hp, n->hs, buffer, got);
                }
            }
            /* message is complete here */
            if (n->is_complete(n->data)) {
                break;
            }
        }
    }
    AM_FREE(buffer);
}

/**
 * close connection and clear resources
 */
int am_net_close(am_net_t *n) {
    int i;
    if (n == NULL) {
        return AM_EINVAL;
    }
    
    /* close ssl/socket */
    net_close_ssl(n);
    net_close_socket(n->sock);
    n->sock = INVALID_SOCKET;
    
    if (n->ra != NULL) {
        freeaddrinfo(n->ra);
    }
    n->ra = NULL;
    
    AM_FREE(n->req_headers);
    n->req_headers = NULL;
    
    AM_FREE(n->hs, n->hp);
    n->hs = NULL;
    n->hp = NULL;
    
    for (i = 0; i < n->num_headers; i++) {
        char *field = n->header_fields[i];
        char *value = n->header_values[i];
        AM_FREE(field, value);
    }
    AM_FREE(n->header_fields, n->header_values);
    n->header_fields = NULL;
    n->header_values = NULL;
    n->num_headers = n->num_header_values = 0;
    return AM_SUCCESS;
}



