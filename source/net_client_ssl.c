// SPDX-License-Identifier: CDDL-1.0
//
// Copyright 2015-2016 ForgeRock AS.
// Copyright 2018-2026 Open Identity Platform Community.

#include "am.h"
#include "net_client.h"
#include "platform.h"
#include "utility.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#ifdef _WIN32
static INIT_ONCE ssl_lib_initialized = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION *ssl_mutexes = NULL;
#else
static pthread_once_t ssl_lib_initialized = PTHREAD_ONCE_INIT;
static pthread_mutex_t *ssl_mutexes = NULL;
#endif

/* Setup Thread-safety for older OpenSSL 1.0.x (e.g. RHEL 7) */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void ssl_locking_callback(int mode, int mutex_num, const char *file, int line) {
    if (mode & 1) {
#ifdef _WIN32
        EnterCriticalSection(&ssl_mutexes[mutex_num]);
#else
        pthread_mutex_lock(&ssl_mutexes[mutex_num]);
#endif
    } else {
#ifdef _WIN32
        LeaveCriticalSection(&ssl_mutexes[mutex_num]);
#else
        pthread_mutex_unlock(&ssl_mutexes[mutex_num]);
#endif
    }
}

static unsigned long ssl_id_callback(void) {
#ifdef _WIN32
    return (unsigned long)GetCurrentThreadId();
#else
    return (unsigned long)pthread_self();
#endif
}
#endif

static
#ifdef _WIN32
    BOOL CALLBACK
#else
    void
#endif
    init_ssl(
#ifdef _WIN32
        PINIT_ONCE io, PVOID p, PVOID *c
#endif
    ) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    int i, size;
    CRYPTO_set_mem_functions(malloc, realloc, free);
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

#ifdef _WIN32
    size = sizeof(CRITICAL_SECTION) * CRYPTO_num_locks();
    ssl_mutexes = (CRITICAL_SECTION *)malloc(size);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        InitializeCriticalSection(&ssl_mutexes[i]);
    }
#else
    size = sizeof(pthread_mutex_t) * CRYPTO_num_locks();
    ssl_mutexes = (pthread_mutex_t *)malloc(size);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&ssl_mutexes[i], NULL);
    }
#endif
    CRYPTO_set_id_callback(ssl_id_callback);
    CRYPTO_set_locking_callback(ssl_locking_callback);
#else
    /* OpenSSL 1.1.0+ and 3.x handle initialization and threading automatically */
    OPENSSL_init_ssl(0, NULL);
#endif

#ifdef _WIN32
    return TRUE;
#endif
}

void net_init_ssl() {
#ifdef _WIN32
    InitOnceExecuteOnce(&ssl_lib_initialized, init_ssl, NULL, NULL);
#else
    pthread_once(&ssl_lib_initialized, init_ssl);
#endif
}

void am_net_init_ssl_reset() {
#ifdef _WIN32
    INIT_ONCE once = INIT_ONCE_STATIC_INIT;
#else
    pthread_once_t once = PTHREAD_ONCE_INIT;
#endif
    memcpy(&ssl_lib_initialized, &once, sizeof(ssl_lib_initialized));
}

void net_shutdown_ssl() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    int i;
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    if (ssl_mutexes != NULL) {
        for (i = 0; i < CRYPTO_num_locks(); i++) {
#ifdef _WIN32
            DeleteCriticalSection(&ssl_mutexes[i]);
#else
            pthread_mutex_destroy(&ssl_mutexes[i]);
#endif
        }
        free(ssl_mutexes);
    }
    ssl_mutexes = NULL;
#endif
}

static void show_server_cert(am_net_t *net) {
    static const char *thisfunc = "show_server_cert():";
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate((SSL *)net->ssl.ssl_handle);
    if (cert != NULL) {
#define X509_DN_SIZE 1024
        line = calloc(1, X509_DN_SIZE);
        if (line == NULL) {
            AM_LOG_ERROR(net->instance_id, "%s memory allocation error", thisfunc);
            X509_free(cert);
            return;
        }
        X509_NAME_oneline(X509_get_subject_name(cert), line, X509_DN_SIZE - 1);
        AM_LOG_DEBUG(net->instance_id, "%s server certificate subject: %s", thisfunc, LOGEMPTY(line));
        if (net->options != NULL && net->options->log != NULL) {
            net->options->log("%s server certificate subject: %s", thisfunc, LOGEMPTY(line));
        }
        memset(line, 0, X509_DN_SIZE);
        X509_NAME_oneline(X509_get_issuer_name(cert), line, X509_DN_SIZE - 1);
        AM_LOG_DEBUG(net->instance_id, "%s server certificate issuer: %s", thisfunc, LOGEMPTY(line));
        if (net->options != NULL && net->options->log != NULL) {
            net->options->log("%s server certificate issuer: %s", thisfunc, LOGEMPTY(line));
        }
        free(line);
        X509_free(cert);
    }
}

static int password_callback(char *buf, int size, int rwflag, void *passwd) {
    strncpy(buf, (char *)passwd, size);
    buf[size - 1] = '\0';
    return (int)(strlen(buf));
}

static const char *read_ssl_error() {
    static AM_THREAD_LOCAL char err_buff[121];
    unsigned long err = ERR_get_error();
    return err == 0 ? am_strerror(AM_SUCCESS) : LOGEMPTY(ERR_error_string(err, err_buff));
}

static char ssl_is_fatal_error(am_net_t *net, int ssl_error) {
    static const char *thisfunc = "net_ssl_error():";
    char *error_string;
    switch (ssl_error) {
    case SSL_ERROR_NONE:
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        return 0;
    }
    error_string = (char *)read_ssl_error();
    if (net->options != NULL && net->options->log != NULL) {
        net->options->log("%s %s", thisfunc, error_string);
    }
    if (strcmp(error_string, am_strerror(AM_SUCCESS)) != 0) {
        AM_LOG_ERROR(net->instance_id, "%s %s", thisfunc, error_string);
    }
    return 1;
}

static void write_bio_to_socket(am_net_t *n) {
    static const char *thisfunc = "write_bio_to_socket():";
    char *buf, *p;
    int len, remaining, hasread, pending;

    pending = BIO_ctrl_pending((BIO *)n->ssl.write_bio);
    if (pending > 0) {
        buf = malloc(pending);
        if (buf == NULL) {
            return;
        }

        hasread = BIO_read((BIO *)n->ssl.write_bio, buf, pending);
        if (hasread > 0) {
            p = buf;
            remaining = hasread;
            while (remaining) {
                len = send(n->sock, p, remaining, 0);
                if (len <= 0) {
#ifdef _WIN32
                    n->ssl.sys_error = WSAGetLastError();
#else
                    n->ssl.sys_error = errno;
#endif
                    if (n->ssl.sys_error != 0) {
                        if (n->options != NULL && n->options->log != NULL) {
                            n->options->log("%s error %d", thisfunc, n->ssl.sys_error);
                        }
                        AM_LOG_ERROR(n->instance_id, "%s error %d", thisfunc, n->ssl.sys_error);
                    }
                    free(buf);
                    return;
                }
                remaining -= len;
                p += len;
            }
        }
        free(buf);
    }
}

void net_close_ssl_notify(am_net_t *n) {
    if (n->ssl.ssl_handle != NULL) {
        SSL_shutdown((SSL *)n->ssl.ssl_handle);
    }
}

void net_close_ssl(am_net_t *n) {
    if (n->ssl.ssl_handle != NULL) {
        SSL_shutdown((SSL *)n->ssl.ssl_handle);
        SSL_free((SSL *)n->ssl.ssl_handle);
    }
    if (n->ssl.ssl_context != NULL) {
        SSL_CTX_free((SSL_CTX *)n->ssl.ssl_context);
    }
    am_free(n->ssl.request_data);
    n->ssl.request_data = NULL;
    n->ssl.ssl_handle = NULL;
    n->ssl.ssl_context = NULL;
    n->ssl.on = AM_FALSE;
}

static void net_ssl_msg_callback(int writep, int version, int content_type, const void *buf, size_t len, SSL *ssl,
                                 void *arg) {
    static const char *thisfunc = "net_ssl_msg_callback():";
    am_net_t *net = (am_net_t *)arg;
    if (net->options != NULL && net->options->log != NULL) {
        net->options->log("%s %s (%s)", thisfunc, SSL_state_string_long(ssl), SSL_state_string(ssl));
    }
    AM_LOG_DEBUG(net->instance_id, "%s %s (%s)", thisfunc, SSL_state_string_long(ssl), SSL_state_string(ssl));
    if (strstr(SSL_state_string_long(ssl), "read server key exchange") != NULL) {
        show_server_cert(net);
    }
}

void net_connect_ssl(am_net_t *n) {
    static const char *thisfunc = "net_connect_ssl():";
    int status = -1, err = 0;
    am_bool_t cert_ca_file_loaded = AM_FALSE;
    if (n != NULL) {
        n->ssl.on = AM_FALSE;
        n->ssl.error = AM_SUCCESS;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        n->ssl.ssl_context = SSL_CTX_new(TLS_client_method());
#else
        n->ssl.ssl_context = SSL_CTX_new(SSLv23_client_method());
#endif
        if (n->ssl.ssl_context == NULL) {
            AM_LOG_ERROR(n->instance_id, "%s failed to create a new SSL context, error: %s", thisfunc,
                         read_ssl_error());
            n->ssl.error = AM_ENOMEM;
            return;
        }

        SSL_CTX_set_options((SSL_CTX *)n->ssl.ssl_context, SSL_OP_NO_SSLv2);
        SSL_CTX_set_mode((SSL_CTX *)n->ssl.ssl_context,
                         SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        SSL_CTX_set_session_cache_mode((SSL_CTX *)n->ssl.ssl_context, SSL_SESS_CACHE_OFF);

        SSL_CTX_set_msg_callback_arg((SSL_CTX *)n->ssl.ssl_context, n);
        SSL_CTX_set_msg_callback((SSL_CTX *)n->ssl.ssl_context, net_ssl_msg_callback);

        if (n->options != NULL && ISVALID(n->options->tls_opts)) {
            char *v, *t, *c = strdup(n->options->tls_opts);
            if (c != NULL) {
                for ((v = strtok_r(c, AM_SPACE_CHAR, &t)); v; (v = strtok_r(NULL, AM_SPACE_CHAR, &t))) {
                    if (strcasecmp(v, "-SSLv3") == 0) {
                        SSL_CTX_set_options((SSL_CTX *)n->ssl.ssl_context, SSL_OP_NO_SSLv3);
                        continue;
                    }
                    if (strcasecmp(v, "-TLSv1") == 0) {
                        SSL_CTX_set_options((SSL_CTX *)n->ssl.ssl_context, SSL_OP_NO_TLSv1);
                        continue;
                    }
#ifdef SSL_OP_NO_TLSv1_1
                    if (strcasecmp(v, "-TLSv1.1") == 0) {
                        SSL_CTX_set_options((SSL_CTX *)n->ssl.ssl_context, SSL_OP_NO_TLSv1_1);
                        continue;
                    }
#endif
#ifdef SSL_OP_NO_TLSv1_2
                    if (strcasecmp(v, "-TLSv1.2") == 0) {
                        SSL_CTX_set_options((SSL_CTX *)n->ssl.ssl_context, SSL_OP_NO_TLSv1_2);
                    }
#endif
                }
                free(c);
            }
        }

        if (n->options != NULL && ISVALID(n->options->ciphers)) {
            if (!SSL_CTX_set_cipher_list((SSL_CTX *)n->ssl.ssl_context, n->options->ciphers)) {
                AM_LOG_WARNING(n->instance_id, "%s failed to set cipher list \"%s\"", thisfunc, n->options->ciphers);
            }
        }
        if (n->options != NULL && ISVALID(n->options->cert_ca_file)) {
            if (!SSL_CTX_load_verify_locations((SSL_CTX *)n->ssl.ssl_context, n->options->cert_ca_file, NULL)) {
                AM_LOG_WARNING(n->instance_id, "%s failed to load trusted CA certificates file \"%s\"", thisfunc,
                               n->options->cert_ca_file);
            } else {
                cert_ca_file_loaded = AM_TRUE;
            }
        }
        if (n->options != NULL && ISVALID(n->options->cert_file)) {
            if (!SSL_CTX_use_certificate_file((SSL_CTX *)n->ssl.ssl_context, n->options->cert_file, SSL_FILETYPE_PEM)) {
                AM_LOG_WARNING(n->instance_id, "%s failed to load client certificate file \"%s\"", thisfunc,
                               n->options->cert_file);
            }
        }

        if (n->options != NULL && ISVALID(n->options->cert_key_file)) {
            if (ISVALID(n->options->cert_key_pass)) {
                SSL_CTX_set_default_passwd_cb_userdata((SSL_CTX *)n->ssl.ssl_context,
                                                       (void *)n->options->cert_key_pass);
                SSL_CTX_set_default_passwd_cb((SSL_CTX *)n->ssl.ssl_context, password_callback);
            }
            if (!SSL_CTX_use_PrivateKey_file((SSL_CTX *)n->ssl.ssl_context, n->options->cert_key_file,
                                             SSL_FILETYPE_PEM)) {
                AM_LOG_WARNING(n->instance_id, "%s failed to load private key file \"%s\", %s", thisfunc,
                               n->options->cert_key_file,
                               file_exists(n->options->cert_key_file) ? read_ssl_error() : "file is not accessible");
            }
            if (!SSL_CTX_check_private_key((SSL_CTX *)n->ssl.ssl_context)) {
                AM_LOG_WARNING(n->instance_id, "%s private key does not match the public certificate", thisfunc);
            }
        }

        if (n->options == NULL || n->options->cert_trust) {
            SSL_CTX_set_verify((SSL_CTX *)n->ssl.ssl_context, SSL_VERIFY_NONE, NULL);
        } else if (cert_ca_file_loaded) {
            SSL_CTX_set_verify((SSL_CTX *)n->ssl.ssl_context, SSL_VERIFY_PEER, NULL);
            SSL_CTX_set_verify_depth((SSL_CTX *)n->ssl.ssl_context, 100);
        } else {
            AM_LOG_ERROR(n->instance_id, "%s unable to verify peer: trusted CA certificates file \"%s\" not loaded",
                         thisfunc, LOGEMPTY(n->options->cert_ca_file));

            n->ssl.error = AM_EINVAL;
            return;
        }

        n->ssl.ssl_handle = SSL_new((SSL_CTX *)n->ssl.ssl_context);
        if (n->ssl.ssl_handle != NULL) {
            n->ssl.read_bio = BIO_new(BIO_s_mem());
            n->ssl.write_bio = BIO_new(BIO_s_mem());
            if (n->ssl.read_bio != NULL && n->ssl.write_bio != NULL) {
                BIO_set_mem_eof_return((BIO *)n->ssl.read_bio, -1);
                BIO_set_mem_eof_return((BIO *)n->ssl.write_bio, -1);
                SSL_set_bio((SSL *)n->ssl.ssl_handle, (BIO *)n->ssl.read_bio, (BIO *)n->ssl.write_bio);

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
                SSL_set_connect_state((SSL *)n->ssl.ssl_handle);
#else
                SSL_set_connect_state((SSL *)n->ssl.ssl_handle);
#endif
                /* do the handshake */
                status = SSL_do_handshake((SSL *)n->ssl.ssl_handle);
                write_bio_to_socket(n);
                if (status != 1) {
                    err = SSL_get_error((SSL *)n->ssl.ssl_handle, status);
                    if (!ssl_is_fatal_error(n, err)) {
                        write_bio_to_socket(n);
                    }
                }
                n->ssl.on = AM_TRUE;
            }
        } else {
            AM_LOG_ERROR(n->instance_id, "%s failed to create a SSL handle for a connection, error: %s", thisfunc,
                         read_ssl_error());
        }
    }
}

static int read_data_after_handshake(am_net_t *n) {
    char *buf;
    int err, ret = 0, status = AM_SUCCESS;

#define AM_SSL_BUFFER_SZ 1024

    buf = malloc(AM_SSL_BUFFER_SZ);
    if (buf == NULL) {
        return AM_ENOMEM;
    }

    do {
        ret = SSL_read((SSL *)n->ssl.ssl_handle, buf, AM_SSL_BUFFER_SZ);
        if (ret == 0) {
            /* connection closed */
            break;
        }
        if (ret < 0) {
            err = SSL_get_error((SSL *)n->ssl.ssl_handle, ret);
            if (!ssl_is_fatal_error(n, err)) {
                write_bio_to_socket(n);
                free(buf);
                return AM_EAGAIN;
            }
            break;
        }

        http_parser_execute(n->hp, n->hs, buf, ret);
    } while (ret > 0);

    free(buf);
    return status;
}

void net_write_ssl(am_net_t *n) {
    int err, ret = 0, written = 0;
    do {
        ret = SSL_write((SSL *)n->ssl.ssl_handle, n->ssl.request_data + written, (int)n->ssl.request_data_sz - written);
        if (ret == 0) {
            /* connection closed */
            break;
        }
        if (ret < 0) {
            err = SSL_get_error((SSL *)n->ssl.ssl_handle, ret);
            if (!ssl_is_fatal_error(n, err)) {
                write_bio_to_socket(n);
            }
            break;
        }

        written += ret;
        write_bio_to_socket(n);
    } while (ret > 0);
}

int net_read_ssl(am_net_t *n, const char *buf, int sz) {
    int ret, err, status = AM_SUCCESS;
    if (sz == 0) {
        read_data_after_handshake(n);
        return AM_EOF;
    }

    BIO_write((BIO *)n->ssl.read_bio, buf, sz);
    if (!SSL_is_init_finished((SSL *)n->ssl.ssl_handle)) {
        ret = SSL_connect((SSL *)n->ssl.ssl_handle);
        write_bio_to_socket(n);
        if (ret != 1) {
            err = SSL_get_error((SSL *)n->ssl.ssl_handle, ret);
            if (!ssl_is_fatal_error(n, err)) {
                write_bio_to_socket(n);
            }
        } else {
            net_write_ssl(n);
        }
    } else {
        status = read_data_after_handshake(n);
    }

    return status;
}
