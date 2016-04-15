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
 * Copyright 2016 ForgeRock AS.
 */

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <schnlsp.h>
#include "platform.h"
#include "am.h"
#include "utility.h"
#include "net_client.h"

#define INITIAL_BUFFER_SIZE   4096
#define FREE_BUFFER_SIZE      1024

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

struct win_net {
    HANDLE ev_net;

    CtxtHandle ctxt;
    TimeStamp ctxt_timestamp;
    CredHandle cred;
    TimeStamp cred_timestamp;

    unsigned long request_flags;
    unsigned long context_flags;

    unsigned char *enc_buf;
    unsigned int enc_buf_size;
    unsigned int enc_buf_offset;

    unsigned char *dec_buf;
    unsigned int dec_buf_size;
    unsigned int dec_buf_offset;

    SecPkgContext_StreamSizes sizes;

    int connected;
    int connection_closed;
    int sspi_close_notify;

    HCERTSTORE cert_store;
    PCCERT_CONTEXT cert_ctxt;
};

static long net_data_avail(am_net_t *n) {
    u_long len = 0;
    if (ioctlsocket(n->sock, FIONREAD, &len) != 0) {
        n->error = WSAGetLastError();
    }
    return len;
}

static int net_ssl_pending(struct win_net *n) {
    return n->dec_buf_offset;
}

static wchar_t *from_utf8(const char *string) {
    wchar_t *out;
    size_t newsize;
    if (string == NULL) return NULL;
    newsize = mbstowcs(NULL, string, 0);
    out = calloc(1, (newsize + 1) * sizeof (wchar_t));
    if (out == NULL) return NULL;
    if (mbstowcs(out, string, newsize + 1) == -1) {
        free(out);
        out = NULL;
    }
    return out;
}

static void init_sec_buffer(SecBuffer *buffer, unsigned long type,
        void *data, unsigned long size) {
    buffer->cbBuffer = size;
    buffer->BufferType = type;
    buffer->pvBuffer = data;
}

static void init_sec_buffer_desc(SecBufferDesc *desc, SecBuffer *buffers,
        unsigned long buffer_count) {
    desc->ulVersion = SECBUFFER_VERSION;
    desc->pBuffers = buffers;
    desc->cBuffers = buffer_count;
}

static int net_write(am_net_t *net, const char *buf, int len) {
    static const char *thisfunc = "net_write():";
    struct win_net *n = (struct win_net *) net->ssl.ssl_handle;
    int sent = 0, rv, error;
    int timeout = net->options && net->options->net_timeout > AM_NET_POOL_TIMEOUT ?
            net->options->net_timeout : AM_NET_POOL_TIMEOUT;

    while (sent < len) {
        rv = send(net->sock, buf + sent, len - sent, 0);
        error = WSAGetLastError();
        if (rv < 0) {
            if (error == WSAEWOULDBLOCK) {
                WSANETWORKEVENTS events;

                rv = WSAWaitForMultipleEvents(1, &n->ev_net, FALSE, timeout * 1000, FALSE);
                if (rv == WSA_WAIT_EVENT_0 + 1) {
                    AM_LOG_DEBUG(net->instance_id, "%s socket aborted", thisfunc);
                    return -1;
                }
                if (rv != WSA_WAIT_EVENT_0) {
                    AM_LOG_DEBUG(net->instance_id, "%s socket timed out", thisfunc);
                    return -1;
                }

                rv = WSAEnumNetworkEvents(net->sock, n->ev_net, &events);
                if (rv == SOCKET_ERROR) {
                    net_log_error(net->instance_id, WSAGetLastError());
                    return rv;
                }

                if (events.lNetworkEvents & FD_CLOSE) {
                    return 0;
                }

                if (events.lNetworkEvents & FD_WRITE) {
                    continue;
                }

                if (events.iErrorCode[FD_WRITE_BIT] != 0) {
                    AM_LOG_DEBUG(net->instance_id, "%s socket error %d", thisfunc, events.iErrorCode[FD_WRITE_BIT]);
                    return -1;
                }
            }
            AM_LOG_DEBUG(net->instance_id, "%s socket write error %d", thisfunc, error);
            break;
        }
        if (rv == 0) {
            break;
        }
        sent += rv;
    }
    return !sent ? rv : sent;
}

void wnet_close_ssl(am_net_t *net) {
    static const char *thisfunc = "wnet_close_ssl():";
    struct win_net *n = (struct win_net *) net->ssl.ssl_handle;
    if (n->connected) {
        SecBufferDesc buff_desc;
        SecBuffer buffer;
        SECURITY_STATUS sspi_ret;
        SecBuffer outbuf;
        SecBufferDesc outbuf_desc;
        int ret;
        DWORD dwshut = SCHANNEL_SHUTDOWN;

        init_sec_buffer(&buffer, SECBUFFER_TOKEN, &dwshut, sizeof (dwshut));
        init_sec_buffer_desc(&buff_desc, &buffer, 1);

        sspi_ret = ApplyControlToken(&n->ctxt, &buff_desc);
        if (sspi_ret != SEC_E_OK) {
            AM_LOG_ERROR(net->instance_id, "%s ApplyControlToken failed (0x%lx)",
                    thisfunc, sspi_ret);
        }

        init_sec_buffer(&outbuf, SECBUFFER_EMPTY, NULL, 0);
        init_sec_buffer_desc(&outbuf_desc, &outbuf, 1);

        sspi_ret = InitializeSecurityContext(&n->cred, &n->ctxt, net->uv.host,
                n->request_flags, 0, 0, NULL, 0, &n->ctxt,
                &outbuf_desc, &n->context_flags, &n->ctxt_timestamp);
        if (sspi_ret == SEC_E_OK || sspi_ret == SEC_I_CONTEXT_EXPIRED) {
            ret = net_write(net, outbuf.pvBuffer, outbuf.cbBuffer);
            FreeContextBuffer(outbuf.pvBuffer);
            if (ret < 0 || ret != outbuf.cbBuffer) {
                AM_LOG_ERROR(net->instance_id, "%s failed to send close message", thisfunc);
            }
        }
        n->connected = 0;
    }

    WSACloseEvent(n->ev_net);

    if (SecIsValidHandle(&n->ctxt)) {
        DeleteSecurityContext(&n->ctxt);
        SecInvalidateHandle(&n->ctxt);
    }
    if (SecIsValidHandle(&n->cred)) {
        FreeCredentialsHandle(&n->cred);
        SecInvalidateHandle(&n->cred);
    }

    if (n->cert_ctxt) CertFreeCertificateContext(n->cert_ctxt);
    if (n->cert_store) CertCloseStore(n->cert_store, 0);

    n->enc_buf_size = n->enc_buf_offset = 0;
    n->dec_buf_size = n->dec_buf_offset = 0;

    AM_FREE(n->enc_buf, n->dec_buf);
}

static int net_read(am_net_t *net, char *buf, int len) {
    static const char *thisfunc = "net_read():";
    struct win_net *n = (struct win_net *) net->ssl.ssl_handle;
    int rv, error;
    WSANETWORKEVENTS events;
    int timeout = net->options && net->options->net_timeout > AM_NET_POOL_TIMEOUT ?
            net->options->net_timeout : AM_NET_POOL_TIMEOUT;

    rv = recv(net->sock, buf, len, 0);
    error = WSAGetLastError();
    if (rv >= 0) return rv;
    if (error == WSAECONNRESET) return 0;
    if (error != WSAEWOULDBLOCK) {
        net_log_error(net->instance_id, error);
        return rv;
    }

    while (1) {
        rv = WSAWaitForMultipleEvents(1, &n->ev_net, TRUE, timeout * 1000, FALSE);
        if (rv == WSA_WAIT_EVENT_0 + 1) {
            AM_LOG_DEBUG(net->instance_id, "%s socket aborted", thisfunc);
            return -1;
        }
        if (rv != WSA_WAIT_EVENT_0) {
            AM_LOG_DEBUG(net->instance_id, "%s socket timed out", thisfunc);
            return -1;
        }
        rv = WSAEnumNetworkEvents(net->sock, n->ev_net, &events);
        if (rv == SOCKET_ERROR) {
            net_log_error(net->instance_id, WSAGetLastError());
            return -1;
        }

        if (!events.lNetworkEvents) {
            continue;
        }
        if (events.lNetworkEvents & FD_READ) {
            rv = recv(net->sock, buf, len, 0);
            error = WSAGetLastError();
            if (rv >= 0) return rv;
            if (error != WSAEWOULDBLOCK) {
                net_log_error(net->instance_id, error);
                return rv;
            }
        } else if (events.lNetworkEvents & FD_CLOSE) {
            return 0;
        }
    }

    return rv;
}

static int net_write_ssl(am_net_t *net, const char *buf, int len) {
    static const char *thisfunc = "net_write_ssl():";
    struct win_net *n = (struct win_net *) net->ssl.ssl_handle;
    SECURITY_STATUS sspi_ret;
    int ret = 0, data_size;
    uint8_t *data = NULL;
    SecBuffer outbuf[4];
    SecBufferDesc outbuf_desc;

    if (n->sizes.cbMaximumMessage == 0) {
        sspi_ret = QueryContextAttributesA(&n->ctxt, SECPKG_ATTR_STREAM_SIZES, &n->sizes);
        if (sspi_ret != SEC_E_OK) {
            AM_LOG_ERROR(net->instance_id, "%s query context attributes failed (0x%lx)",
                    thisfunc, sspi_ret);
            return AM_EFAULT;
        }
    }

    /* limit how much data we can consume */
    len = min((unsigned int) len, n->sizes.cbMaximumMessage);

    data_size = n->sizes.cbHeader + len + n->sizes.cbTrailer;
    data = malloc(data_size);
    if (data == NULL) {
        return AM_ENOMEM;
    }

    init_sec_buffer(&outbuf[0], SECBUFFER_STREAM_HEADER,
            data, n->sizes.cbHeader);
    init_sec_buffer(&outbuf[1], SECBUFFER_DATA,
            data + n->sizes.cbHeader, len);
    init_sec_buffer(&outbuf[2], SECBUFFER_STREAM_TRAILER,
            data + n->sizes.cbHeader + len, n->sizes.cbTrailer);
    init_sec_buffer(&outbuf[3], SECBUFFER_EMPTY, NULL, 0);
    init_sec_buffer_desc(&outbuf_desc, outbuf, 4);

    memcpy(outbuf[1].pvBuffer, buf, len);

    do {
        sspi_ret = EncryptMessage(&n->ctxt, 0, &outbuf_desc, 0);
        if (sspi_ret == SEC_E_OK) {
            len = outbuf[0].cbBuffer + outbuf[1].cbBuffer + outbuf[2].cbBuffer;
            ret = net_write(net, data, len);
            if (ret < 0 || ret != len) {
                ret = AM_EFAULT;
                AM_LOG_ERROR(net->instance_id, "%s error writing encrypted data to socket",
                        thisfunc);
                break;
            }
        } else {
            AM_LOG_ERROR(net->instance_id, "%s data encryption failed (0x%lx)",
                    thisfunc, sspi_ret);
            if (sspi_ret == SEC_E_INSUFFICIENT_MEMORY)
                ret = AM_ENOMEM;
            else
                ret = AM_EFAULT;
            break;
        }
    } while (0);

    AM_FREE(data);
    return ret < 0 ? ret : outbuf[1].cbBuffer;
}

static int net_read_ssl_cleanup(struct win_net *n, char *buf, int len, int ret) {
    int size = min((unsigned int) len, n->dec_buf_offset);
    int rv = ret;
    if (size) {
        memcpy(buf, n->dec_buf, size);
        memmove(n->dec_buf, n->dec_buf + size, n->dec_buf_offset - size);
        n->dec_buf_offset -= size;
        return size;
    }
    if (rv == 0 && !n->connection_closed) {
        rv = AM_EAGAIN;
    }
    return rv < 0 ? rv : 0;
}

static int net_client_handshake_loop(am_net_t *net, int initial) {
    static const char *thisfunc = "net_client_handshake_loop():";
    struct win_net *n = (struct win_net *) net->ssl.ssl_handle;
    SECURITY_STATUS sspi_ret;
    SecBuffer outbuf[3];
    SecBufferDesc outbuf_desc;
    SecBuffer inbuf[2];
    SecBufferDesc inbuf_desc;
    int i, ret = 0, read_data = initial;

#define HANDSHAKE_CLEANUP_RETURN(s) do {\
    int j;\
    for (j = 0; j < 3; j++) {\
        if (outbuf[j].pvBuffer != NULL) {\
            FreeContextBuffer(outbuf[j].pvBuffer);\
            outbuf[j].pvBuffer = NULL;\
        }\
    }\
    return s;\
} while(0)

    /* output buffers */
    init_sec_buffer(&outbuf[0], SECBUFFER_TOKEN, NULL, 0);
    init_sec_buffer(&outbuf[1], SECBUFFER_ALERT, NULL, 0);
    init_sec_buffer(&outbuf[2], SECBUFFER_EMPTY, NULL, 0);
    init_sec_buffer_desc(&outbuf_desc, outbuf, 3);

    if (n->enc_buf == NULL) {
        n->enc_buf_offset = 0;
        n->enc_buf = malloc(INITIAL_BUFFER_SIZE);
        if (n->enc_buf == NULL) {
            HANDSHAKE_CLEANUP_RETURN(AM_ENOMEM);
        }
        n->enc_buf_size = INITIAL_BUFFER_SIZE;
    }

    if (n->dec_buf == NULL) {
        n->dec_buf_offset = 0;
        n->dec_buf = malloc(INITIAL_BUFFER_SIZE);
        if (n->dec_buf == NULL) {
            HANDSHAKE_CLEANUP_RETURN(AM_ENOMEM);
        }
        n->dec_buf_size = INITIAL_BUFFER_SIZE;
    }

    while (1) {
        if (n->enc_buf_size - n->enc_buf_offset < FREE_BUFFER_SIZE) {
            n->enc_buf_size = n->enc_buf_offset + FREE_BUFFER_SIZE;
            n->enc_buf = realloc(n->enc_buf, n->enc_buf_size);
            if (n->enc_buf == NULL) {
                n->enc_buf_size = n->enc_buf_offset = 0;
                HANDSHAKE_CLEANUP_RETURN(AM_ENOMEM);
            }
        }

        if (read_data) {
            ret = net_read(net, n->enc_buf + n->enc_buf_offset,
                    n->enc_buf_size - n->enc_buf_offset);
            if (ret < 0) {
                AM_LOG_ERROR(net->instance_id, "%s error reading handshake response", thisfunc);
                HANDSHAKE_CLEANUP_RETURN(AM_EFAULT);
            }
            n->enc_buf_offset += ret;
        }

        /* input buffers */
        init_sec_buffer(&inbuf[0], SECBUFFER_TOKEN, malloc(n->enc_buf_offset), n->enc_buf_offset);
        init_sec_buffer(&inbuf[1], SECBUFFER_EMPTY, NULL, 0);
        init_sec_buffer_desc(&inbuf_desc, inbuf, 2);

        if (inbuf[0].pvBuffer == NULL) {
            AM_LOG_ERROR(net->instance_id, "%s failed to allocate input buffer", thisfunc);
            HANDSHAKE_CLEANUP_RETURN(AM_ENOMEM);
        }

        memcpy(inbuf[0].pvBuffer, n->enc_buf, n->enc_buf_offset);

        /* output buffers */
        init_sec_buffer(&outbuf[0], SECBUFFER_TOKEN, NULL, 0);
        init_sec_buffer(&outbuf[1], SECBUFFER_ALERT, NULL, 0);
        init_sec_buffer(&outbuf[2], SECBUFFER_EMPTY, NULL, 0);
        init_sec_buffer_desc(&outbuf_desc, outbuf, 3);

        sspi_ret = InitializeSecurityContextA(&n->cred, &n->ctxt, net->uv.host, n->request_flags,
                0, 0, &inbuf_desc, 0, NULL, &outbuf_desc, &n->context_flags,
                &n->ctxt_timestamp);

        if (inbuf[0].pvBuffer) free(inbuf[0].pvBuffer);
        inbuf[0].pvBuffer = NULL;

        if (sspi_ret == SEC_E_INCOMPLETE_MESSAGE) {
            AM_LOG_DEBUG(net->instance_id, "%s received incomplete handshake, need more data", thisfunc);
            read_data = 1;
            continue;
        }

        /* remote requests a client certificate - attempt to continue without one anyway */
        if (sspi_ret == SEC_I_INCOMPLETE_CREDENTIALS && !(n->request_flags & ISC_REQ_USE_SUPPLIED_CREDS)) {
            AM_LOG_DEBUG(net->instance_id, "%s client certificate has been requested, ignoring", thisfunc);
            n->request_flags |= ISC_REQ_USE_SUPPLIED_CREDS;
            read_data = 0;
            continue;
        }

        /* continue handshake */
        if (sspi_ret == SEC_I_CONTINUE_NEEDED || sspi_ret == SEC_E_OK) {
            for (i = 0; i < 3; i++) {
                if (outbuf[i].BufferType == SECBUFFER_TOKEN && outbuf[i].cbBuffer > 0) {
                    ret = net_write(net, outbuf[i].pvBuffer, outbuf[i].cbBuffer);
                    if (ret < 0 || ret != outbuf[i].cbBuffer) {
                        AM_LOG_ERROR(net->instance_id, "%s failed to send handshake data",
                                thisfunc);
                        HANDSHAKE_CLEANUP_RETURN(AM_EFAULT);
                    }
                }

                if (outbuf[i].pvBuffer != NULL) {
                    FreeContextBuffer(outbuf[i].pvBuffer);
                    outbuf[i].pvBuffer = NULL;
                }
            }
        } else {
            if (sspi_ret == SEC_E_WRONG_PRINCIPAL) {
                AM_LOG_ERROR(net->instance_id, "%s SNI or certificate check failed",
                        thisfunc);
            } else {
                AM_LOG_ERROR(net->instance_id, "%s creating security context failed (0x%lx)",
                        thisfunc, sspi_ret);
            }
            HANDSHAKE_CLEANUP_RETURN(AM_EFAULT);
        }

        if (inbuf[1].BufferType == SECBUFFER_EXTRA && inbuf[1].cbBuffer > 0) {
            if (n->enc_buf_offset > inbuf[1].cbBuffer) {
                memmove(n->enc_buf, (n->enc_buf + n->enc_buf_offset) - inbuf[1].cbBuffer,
                        inbuf[1].cbBuffer);
                n->enc_buf_offset = inbuf[1].cbBuffer;
                if (sspi_ret == SEC_I_CONTINUE_NEEDED) {
                    read_data = 0;
                    continue;
                }
            }
        } else {
            n->enc_buf_offset = 0;
        }

        if (sspi_ret == SEC_I_CONTINUE_NEEDED) {
            read_data = 1;
            continue;
        }

        break;
    }

    AM_LOG_DEBUG(net->instance_id, "%s handshake finished", thisfunc);
    return AM_SUCCESS;
}

static int net_read_ssl(am_net_t *net, char *buf, int len) {
    static const char *thisfunc = "net_read_ssl():";
    struct win_net *n = (struct win_net *) net->ssl.ssl_handle;
    SECURITY_STATUS sspi_ret = SEC_E_OK;
    SecBuffer inbuf[4];
    SecBufferDesc inbuf_desc;
    unsigned int size;
    int ret = 0;
    unsigned int min_enc_buf_size = len + FREE_BUFFER_SIZE;

    /* if we've got some data already, put that in the buffer */
    if (n->dec_buf_offset > 0 || n->sspi_close_notify) {
        return net_read_ssl_cleanup(n, buf, len, ret);
    }

    if (!n->connection_closed) {
        size = n->enc_buf_size - n->enc_buf_offset;
        if (size < FREE_BUFFER_SIZE || n->enc_buf_size < min_enc_buf_size) {
            n->enc_buf_size = n->enc_buf_offset + FREE_BUFFER_SIZE;
            if (n->enc_buf_size < min_enc_buf_size)
                n->enc_buf_size = min_enc_buf_size;
            n->enc_buf = realloc(n->enc_buf, n->enc_buf_size);
            if (n->enc_buf == NULL) {
                n->enc_buf_size = n->enc_buf_offset = 0;
                return AM_ENOMEM;
            }
        }

        ret = net_read(net, n->enc_buf + n->enc_buf_offset,
                n->enc_buf_size - n->enc_buf_offset);
        if (ret < 0) {
            return ret;
        }
        if (ret == 0) {
            AM_LOG_DEBUG(net->instance_id, "%s connection closed", thisfunc);
            n->connection_closed = 1;
        }

        n->enc_buf_offset += ret;
    }

    while (n->enc_buf_offset > 0 && sspi_ret == SEC_E_OK && n->dec_buf_offset < (unsigned int) len) {

        /*  input buffer */
        init_sec_buffer(&inbuf[0], SECBUFFER_DATA, n->enc_buf, n->enc_buf_offset);

        /* additional buffers for possible output */
        init_sec_buffer(&inbuf[1], SECBUFFER_EMPTY, NULL, 0);
        init_sec_buffer(&inbuf[2], SECBUFFER_EMPTY, NULL, 0);
        init_sec_buffer(&inbuf[3], SECBUFFER_EMPTY, NULL, 0);
        init_sec_buffer_desc(&inbuf_desc, inbuf, 4);

        sspi_ret = DecryptMessage(&n->ctxt, &inbuf_desc, 0, NULL);

        switch (sspi_ret) {
            case SEC_E_OK:
            case SEC_I_RENEGOTIATE:
            case SEC_I_CONTEXT_EXPIRED:
                /* handle decrypted data */
                if (inbuf[1].BufferType == SECBUFFER_DATA) {
                    /* grow buffer if needed */
                    size = inbuf[1].cbBuffer > FREE_BUFFER_SIZE ? inbuf[1].cbBuffer : FREE_BUFFER_SIZE;
                    if (n->dec_buf_size - n->dec_buf_offset < size || n->dec_buf_size < (unsigned int) len) {
                        n->dec_buf_size = n->dec_buf_offset + size;
                        if (n->dec_buf_size < (unsigned int) len)
                            n->dec_buf_size = len;
                        n->dec_buf = realloc(n->dec_buf, n->dec_buf_size);
                        if (n->dec_buf == NULL) {
                            n->dec_buf_size = n->dec_buf_offset = 0;
                            return AM_ENOMEM;
                        }
                    }

                    /* copy decrypted data to buffer */
                    size = inbuf[1].cbBuffer;
                    if (size) {
                        memcpy(n->dec_buf + n->dec_buf_offset, inbuf[1].pvBuffer, size);
                        n->dec_buf_offset += size;
                    }
                }

                if (inbuf[3].BufferType == SECBUFFER_EXTRA && inbuf[3].cbBuffer > 0) {
                    if (n->enc_buf_offset > inbuf[3].cbBuffer) {
                        memmove(n->enc_buf, (n->enc_buf + n->enc_buf_offset) - inbuf[3].cbBuffer,
                                inbuf[3].cbBuffer);
                        n->enc_buf_offset = inbuf[3].cbBuffer;
                    }
                } else {
                    n->enc_buf_offset = 0;
                }

                if (sspi_ret == SEC_I_RENEGOTIATE) {
                    if (n->enc_buf_offset) {
                        AM_LOG_DEBUG(net->instance_id, "%s cannot renegotiate, encrypted data buffer not empty",
                                thisfunc);
                        return net_read_ssl_cleanup(n, buf, len, AM_EFAULT);
                    }

                    AM_LOG_DEBUG(net->instance_id, "%s re-negotiating security context", thisfunc);
                    ret = net_client_handshake_loop(net, 0);
                    if (ret < 0) {
                        return net_read_ssl_cleanup(n, buf, len, ret);
                    }
                    sspi_ret = SEC_E_OK;
                    continue;
                }

                if (sspi_ret == SEC_I_CONTEXT_EXPIRED) {
                    n->sspi_close_notify = 1;
                    if (!n->connection_closed) {
                        n->connection_closed = 1;
                        AM_LOG_DEBUG(net->instance_id, "%s server closed the connection", thisfunc);
                    }
                    return net_read_ssl_cleanup(n, buf, len, 0);
                }

                break;
            case SEC_E_INCOMPLETE_MESSAGE:
                return net_read_ssl_cleanup(n, buf, len, AM_EAGAIN);
            default:
                AM_LOG_ERROR(net->instance_id, "%s unable to decrypt message (0x%lx)",
                        thisfunc, sspi_ret);
                return net_read_ssl_cleanup(n, buf, len, AM_EFAULT);
        }
    }

    return net_read_ssl_cleanup(n, buf, len, AM_SUCCESS);
}

int wnet_write(am_net_t *net, const char *buf, int len) {
    static const char *thisfunc = "wnet_write():";
    struct win_net *n = (struct win_net *) net->ssl.ssl_handle;

    if (net->uv.ssl && !n->connected) {
        AM_LOG_ERROR(net->instance_id, "%s SSL/TLS not connected", thisfunc);
        return AM_ENOSSL;
    }
    return net->uv.ssl && n->connected ?
            net_write_ssl(net, buf, len) :
            net_write(net, buf, len);
}

void wnet_read(am_net_t *net) {
    static const char *thisfunc = "wnet_read():";
    struct win_net *n = (struct win_net *) net->ssl.ssl_handle;
    long available = 0;
    int rv, ssl_pending;
#define NET_READ_BUFFER_LEN 1024
    char *buf = malloc(NET_READ_BUFFER_LEN);

    if (buf == NULL) {
        net->error = AM_ENOMEM;
        return;
    }

    if (net->uv.ssl && !n->connected) {
        free(buf);
        AM_LOG_ERROR(net->instance_id, "%s SSL/TLS not connected", thisfunc);
        net->error = AM_ENOSSL;
        return;
    }

    net->reset_complete(net->data);

    do {
        rv = net->uv.ssl && n->connected ?
                net_read_ssl(net, buf, NET_READ_BUFFER_LEN) :
                net_read(net, buf, NET_READ_BUFFER_LEN);
        if (rv == AM_EAGAIN) continue;
        if (rv < 0) {
            if (net->on_close) net->on_close(net->data, 0);
            break;
        }

        http_parser_execute(net->hp, net->hs, buf, rv);
        if (rv == 0) {
            if (!net->is_complete(net->data)) continue;
            if (net->on_close) net->on_close(net->data, 0);
            break;
        }

        ssl_pending = net_ssl_pending(n);
        available = net_data_avail(net);

        if (ssl_pending <= 0 && available <= 0) {
            if (net->on_close) net->on_close(net->data, 0);
            break;
        }

    } while (1);

    free(buf);
}

static int net_client_handshake(am_net_t *net) {
    static const char *thisfunc = "net_client_handshake():";
    struct win_net *n = (struct win_net *) net->ssl.ssl_handle;
    SecBuffer outbuf;
    SecBufferDesc outbuf_desc;
    SECURITY_STATUS sspi_ret;
    int ret;

    init_sec_buffer(&outbuf, SECBUFFER_EMPTY, NULL, 0);
    init_sec_buffer_desc(&outbuf_desc, &outbuf, 1);

    n->request_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
            ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
            ISC_REQ_STREAM | ISC_RET_EXTENDED_ERROR;

    sspi_ret = InitializeSecurityContextA(&n->cred, NULL, net->uv.host, n->request_flags, 0, 0,
            NULL, 0, &n->ctxt, &outbuf_desc, &n->context_flags, &n->ctxt_timestamp);

    if (sspi_ret != SEC_I_CONTINUE_NEEDED) {
        AM_LOG_ERROR(net->instance_id, "%s unable to create initial security context (0x%lx)",
                thisfunc, sspi_ret);
        DeleteSecurityContext(&n->ctxt);
        return AM_ENOSSL;
    }

    ret = net_write(net, outbuf.pvBuffer, outbuf.cbBuffer);
    FreeContextBuffer(outbuf.pvBuffer);
    if (ret < 0 || ret != outbuf.cbBuffer) {
        AM_LOG_ERROR(net->instance_id, "%s failed to send initial handshake data",
                thisfunc);
        DeleteSecurityContext(&n->ctxt);
        return AM_EFAULT;
    }
    return net_client_handshake_loop(net, 1);
}

static int is_ca_cert(PCCERT_CONTEXT ctxt) {
    BYTE key_usage;
    return (CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            ctxt->pCertInfo, &key_usage, 1) && (key_usage & CERT_KEY_CERT_SIGN_KEY_USAGE));
}

static PCCERT_CONTEXT net_ssl_init_creds(am_net_t *net, const char *cert_file, const char *cert_pass) {
    static const char *thisfunc = "net_ssl_init_creds():";
    struct win_net *n = (struct win_net *) net->ssl.ssl_handle;
    PCCERT_CONTEXT cert_ctxt = NULL;
    char name[256];

    if (cert_file != NULL && cert_pass != NULL) {
        CRYPT_DATA_BLOB blob;
        DWORD prop_id = CERT_KEY_PROV_INFO_PROP_ID;
        FILE_STANDARD_INFO finfo;
        wchar_t *cert_pass_w;

        /* get certificate from a local pkcs12 file */

        HANDLE filemap, file = CreateFileA(cert_file, FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
        if (file == INVALID_HANDLE_VALUE) {
            return NULL;
        }
        ZeroMemory(&finfo, sizeof (finfo));
        if (GetFileInformationByHandleEx(file, FileStandardInfo, &finfo, sizeof (finfo)) == 0) {
            CloseHandle(file);
            return NULL;
        }

        filemap = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, (DWORD) finfo.EndOfFile.QuadPart, NULL);
        if (filemap == NULL) {
            CloseHandle(file);
            return NULL;
        }

        ZeroMemory(&blob, sizeof (blob));
        blob.cbData = finfo.EndOfFile.QuadPart;
        blob.pbData = (BYTE *) MapViewOfFile(filemap, FILE_MAP_READ, 0, 0, 0);

        if (blob.pbData == NULL || !PFXIsPFXBlob(&blob)) {
            if (blob.pbData) UnmapViewOfFile(blob.pbData);
            CloseHandle(filemap);
            CloseHandle(file);
            return NULL;
        }

        cert_pass_w = from_utf8(cert_pass);
        n->cert_store = PFXImportCertStore(&blob, cert_pass_w, CRYPT_MACHINE_KEYSET | CRYPT_EXPORTABLE);
        if (cert_pass_w) free(cert_pass_w);
        if (n->cert_store != NULL) {
            cert_ctxt = CertFindCertificateInStore(n->cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0, CERT_FIND_PROPERTY, &prop_id, NULL);
            if (cert_ctxt == NULL) {
                CertCloseStore(n->cert_store, 0);
                if (blob.pbData) UnmapViewOfFile(blob.pbData);
                CloseHandle(filemap);
                CloseHandle(file);
                n->cert_store = NULL;
                return NULL;
            }

            if (CertGetNameStringA(cert_ctxt, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, sizeof (name))) {
                AM_LOG_DEBUG(net->instance_id, "%s found certificate \"%s\"", name);
            }
        }

        UnmapViewOfFile(blob.pbData);
        CloseHandle(filemap);
        CloseHandle(file);

    } else if (cert_file != NULL) {
        DWORD size = 0;
        PBYTE friendly_name;

        /* look for certifiate in system keystore */

        wchar_t *cert_name_w = from_utf8(cert_file);
        if (cert_name_w == NULL) {
            return NULL;
        }

        n->cert_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV) NULL,
                CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG, L"MY");
        if (n->cert_store == NULL) {
            free(cert_name_w);
            return NULL;
        }

        while ((cert_ctxt = CertEnumCertificatesInStore(n->cert_store, cert_ctxt)) != NULL) {
            if (!CertGetCertificateContextProperty(cert_ctxt, CERT_FRIENDLY_NAME_PROP_ID,
                    NULL, &size)) {
                continue;
            }

            friendly_name = malloc(size);
            if (friendly_name == NULL) {
                CertFreeCertificateContext(cert_ctxt);
                cert_ctxt = NULL;
                break;
            }
            if (!CertGetCertificateContextProperty(cert_ctxt, CERT_FRIENDLY_NAME_PROP_ID,
                    friendly_name, &size)) {
                free(friendly_name);
                continue;
            }

            if (_wcsicmp(cert_name_w, (const wchar_t *) friendly_name) == 0) {
                free(friendly_name);
                break;
            }
            free(friendly_name);
        }
        free(cert_name_w);

        if (cert_ctxt == NULL) {
            AM_LOG_WARNING(net->instance_id, "%s unable to locate certificate by friendly name \"%s\"",
                    thisfunc, cert_file);
            return NULL;
        }

        if (!CertGetCertificateContextProperty(cert_ctxt, CERT_KEY_PROV_INFO_PROP_ID, NULL, &size)) {
            AM_LOG_WARNING(net->instance_id, "%s unable to locate corresponding private key", thisfunc);
            CertFreeCertificateContext(cert_ctxt);
            return NULL;
        }

        if (CertGetNameStringA(cert_ctxt, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, sizeof (name))) {
            AM_LOG_DEBUG(net->instance_id, "%s found certificate \"%s\" (friendly name: \"%s\")", name, cert_file);
        }
    }
    return cert_ctxt;
}

static void net_display_cert_chain(am_net_t *net, PCCERT_CONTEXT cert_ctxt) {
    static const char *thisfunc = "net_display_cert_chain():";
    char name[512];
    PCCERT_CONTEXT current_cert;
    PCCERT_CONTEXT issuer_cert;
    DWORD verify_flags;
    const char *time_valid = NULL;

    if (!CertNameToStr(cert_ctxt->dwCertEncodingType, &cert_ctxt->pCertInfo->Subject,
            CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG, name, sizeof (name))) {
        AM_LOG_ERROR(net->instance_id, "%s error 0x%x building subject name", thisfunc, GetLastError());
    }
    switch (CertVerifyTimeValidity(NULL, cert_ctxt->pCertInfo)) {
        case -1: time_valid = "not valid yet";
            break;
        case 1: time_valid = "expired";
            break;
        case 0: time_valid = "valid";
            break;
    }
    AM_LOG_DEBUG(net->instance_id, "%s server cert subject: \"%s\" (%s)", thisfunc, name, LOGEMPTY(time_valid));

    if (!CertNameToStr(cert_ctxt->dwCertEncodingType, &cert_ctxt->pCertInfo->Issuer,
            CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG, name, sizeof (name))) {
        AM_LOG_ERROR(net->instance_id, "%s error 0x%x building issuer name", thisfunc, GetLastError());
    }
    AM_LOG_DEBUG(net->instance_id, "%s server cert issuer: \"%s\"", thisfunc, name);

    current_cert = cert_ctxt;
    while (current_cert != NULL) {
        verify_flags = 0;
        issuer_cert = CertGetIssuerCertificateFromStore(cert_ctxt->hCertStore,
                current_cert, NULL, &verify_flags);
        if (issuer_cert == NULL) {
            if (current_cert != cert_ctxt) {
                CertFreeCertificateContext(current_cert);
            }
            break;
        }

        if (!CertNameToStr(issuer_cert->dwCertEncodingType, &issuer_cert->pCertInfo->Subject,
                CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG, name, sizeof (name))) {
            AM_LOG_ERROR(net->instance_id, "%s error 0x%x building subject name", thisfunc, GetLastError());
        }
        AM_LOG_DEBUG(net->instance_id, "%s CA subject: \"%s\"", thisfunc, name);

        if (!CertNameToStr(issuer_cert->dwCertEncodingType, &issuer_cert->pCertInfo->Issuer,
                CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG, name, sizeof (name))) {
            AM_LOG_ERROR(net->instance_id, "%s error 0x%x building issuer name", thisfunc, GetLastError());
        }
        AM_LOG_DEBUG(net->instance_id, "%s CA issuer: \"%s\"", thisfunc, name);

        if (current_cert != cert_ctxt) {
            CertFreeCertificateContext(current_cert);
        }
        current_cert = issuer_cert;
        issuer_cert = NULL;
    }
}

static const char *net_cert_verify_status(DWORD status) {
    switch (status) {
        case TRUST_E_CERT_SIGNATURE: return "The signature of the certificate cannot be verified";
        case CRYPT_E_REVOKED: return "The certificate or signature has been revoked";
        case CERT_E_UNTRUSTEDROOT: return "A certification chain processed correctly but terminated in a root certificate that is not trusted by the trust provider";
        case CERT_E_UNTRUSTEDTESTROOT: return "The root certificate is a testing certificate, and policy settings disallow test certificates";
        case CERT_E_CHAINING: return "A chain of certificates was not correctly created";
        case CERT_E_WRONG_USAGE: return "The certificate is not valid for the requested usage";
        case CERT_E_EXPIRED: return "A required certificate is not within its validity period";
        case CERT_E_INVALID_NAME: return "The certificate has an invalid name";
        case CERT_E_INVALID_POLICY: return "The certificate has an invalid policy";
        case TRUST_E_BASIC_CONSTRAINTS: return "The basic constraints of the certificate are not valid, or they are missing";
        case CERT_E_CRITICAL: return "The certificate is being used for a purpose other than the purpose specified by its CA";
        case CERT_E_VALIDITYPERIODNESTING: return "The validity periods of the certification chain do not nest correctly";
        case CRYPT_E_NO_REVOCATION_CHECK: return "The revocation function was unable to check revocation for the certificate";
        case CRYPT_E_REVOCATION_OFFLINE: return "The revocation function was unable to check revocation because the revocation server was offline";
        case CERT_E_CN_NO_MATCH: return "The certificate's CN name does not match the passed value";
        case CERT_E_PURPOSE: return "The certificate is being used for a purpose other than the purposes specified by its CA";
        case CERT_E_ROLE: return "A certificate that can only be used as an end-entity is being used as a CA or vice versa";
        default: return "Unknown error code";
    }
}

static DWORD net_verify_server_certificate(am_net_t *net, PCCERT_CONTEXT server_cert_handle, DWORD cert_flags) {
    static const char *thisfunc = "net_verify_server_certificate():";
    struct win_net *n = (struct win_net *) net->ssl.ssl_handle;
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA https_policy;
    CERT_CHAIN_POLICY_PARA policy_para;
    CERT_CHAIN_POLICY_STATUS policy_status;
    CERT_CHAIN_PARA chain_para;
    PCCERT_CHAIN_CONTEXT chain_context = NULL;
    LPSTR usages[] = {szOID_PKIX_KP_SERVER_AUTH,
        szOID_SERVER_GATED_CRYPTO, szOID_SGC_NETSCAPE};
    DWORD status = SEC_E_OK,
            cusages = sizeof (usages) / sizeof (LPSTR);

    ZeroMemory(&chain_para, sizeof (chain_para));
    chain_para.cbSize = sizeof (chain_para);
    chain_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    chain_para.RequestedUsage.Usage.cUsageIdentifier = cusages;
    chain_para.RequestedUsage.Usage.rgpszUsageIdentifier = usages;

    ZeroMemory(&https_policy, sizeof (https_policy));
    https_policy.cbStruct = sizeof (https_policy);
    https_policy.dwAuthType = AUTHTYPE_SERVER;
    https_policy.fdwChecks = cert_flags;

    ZeroMemory(&policy_status, sizeof (policy_status));
    policy_status.cbSize = sizeof (policy_status);

    if (server_cert_handle != NULL && ISVALID(net->uv.host)) {
        if (CertGetCertificateChain(NULL, server_cert_handle, NULL, n->cert_store, &chain_para, 0, NULL, &chain_context)) {
            https_policy.pwszServerName = from_utf8(net->uv.host);
            ZeroMemory(&policy_para, sizeof (policy_para));
            policy_para.cbSize = sizeof (policy_para);
            policy_para.pvExtraPolicyPara = &https_policy;
            if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain_context, &policy_para, &policy_status)) {
                status = GetLastError();
                AM_LOG_ERROR(net->instance_id, "%s CertVerifyCertificateChainPolicy failed 0x%lx", thisfunc, status);
            }

            if (policy_status.dwError) {
                status = policy_status.dwError;
                AM_LOG_ERROR(net->instance_id, "%s error \"%s\" (0x%lx)", thisfunc, net_cert_verify_status(status), status);
            } else {
                AM_LOG_DEBUG(net->instance_id, "%s verification succeeded", thisfunc);
            }

            if (https_policy.pwszServerName) {
                free(https_policy.pwszServerName);
            }
        } else {
            status = GetLastError();
            AM_LOG_ERROR(net->instance_id, "%s CertGetCertificateChain failed 0x%lx", thisfunc, status);
        }
    } else {
        status = SEC_E_WRONG_PRINCIPAL;
    }
    if (chain_context) {
        CertFreeCertificateChain(chain_context);
    }
    return status;
}

static int net_connect_ssl(am_net_t *net) {
    static const char *thisfunc = "net_connect_ssl():";
    struct win_net *n = (struct win_net *) net->ssl.ssl_handle;
    SECURITY_STATUS sspi_ret;
    SCHANNEL_CRED schannel_cred;
    PCCERT_CONTEXT server_cert_handle;

    ZeroMemory(&schannel_cred, sizeof (schannel_cred));
    schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;

    schannel_cred.grbitEnabledProtocols = SP_PROT_SSL3_CLIENT | SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT;

    if (net->options != NULL && ISVALID(net->options->tls_opts)) {
        char *v, *t, *c = strdup(net->options->tls_opts);
        if (c != NULL) {
            for ((v = strtok_r(c, AM_SPACE_CHAR, &t)); v; (v = strtok_r(NULL, AM_SPACE_CHAR, &t))) {
                if (strcasecmp(v, "-SSLv3") == 0) {
                    schannel_cred.grbitEnabledProtocols &= ~SP_PROT_SSL3_CLIENT;
                    continue;
                }
                if (strcasecmp(v, "-TLSv1") == 0) {
                    schannel_cred.grbitEnabledProtocols &= ~SP_PROT_TLS1_0_CLIENT;
                    continue;
                }
                if (strcasecmp(v, "-TLSv1.1") == 0) {
                    schannel_cred.grbitEnabledProtocols &= ~SP_PROT_TLS1_1_CLIENT;
                    continue;
                }
                if (strcasecmp(v, "-TLSv1.2") == 0) {
                    schannel_cred.grbitEnabledProtocols &= ~SP_PROT_TLS1_2_CLIENT;
                }
            }
            free(c);
        }
    }

    schannel_cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION |
            SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
            SCH_CRED_IGNORE_REVOCATION_OFFLINE |
            SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
            SCH_CRED_NO_DEFAULT_CREDS;

    if (net->options->cert_trust) {
        schannel_cred.dwFlags |= SCH_CRED_NO_SERVERNAME_CHECK;
    }

    n->cert_ctxt = net_ssl_init_creds(net, net->options->cert_file, net->options->cert_key_pass);
    if (n->cert_ctxt != NULL) {
        schannel_cred.cCreds = 1;
        schannel_cred.paCred = &n->cert_ctxt;
    }

    sspi_ret = AcquireCredentialsHandleA(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND,
            NULL, &schannel_cred, NULL, NULL, &n->cred, &n->cred_timestamp);
    if (sspi_ret != SEC_E_OK) {
        AM_LOG_ERROR(net->instance_id, "%s unable to acquire security credentials (0x%lx)",
                thisfunc, sspi_ret);
        wnet_close_ssl(net);
        return AM_ENOSSL;
    }

    if (net_client_handshake(net) < 0) {
        wnet_close_ssl(net);
        return AM_ENOSSL;
    }

    n->connected = TRUE;

    sspi_ret = QueryContextAttributesA(&n->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT,
            (VOID *) & server_cert_handle);
    if (sspi_ret != SEC_E_OK) {
        AM_LOG_ERROR(net->instance_id, "%s unable to query security context attributes (0x%lx)",
                thisfunc, sspi_ret);
        wnet_close_ssl(net);
        return AM_ENOSSL;
    }

    net_display_cert_chain(net, server_cert_handle);

    if (!net->options->cert_trust) {
        sspi_ret = net_verify_server_certificate(net, server_cert_handle, 0);
        if (sspi_ret != SEC_E_OK) {
            AM_LOG_ERROR(net->instance_id, "%s unable to verify server certificate (0x%lx)",
                    thisfunc, sspi_ret);
            wnet_close_ssl(net);
            CertFreeCertificateContext(server_cert_handle);
            return AM_ENOSSL;
        }
    } else {
        AM_LOG_DEBUG(net->instance_id, "net_verify_server_certificate(): verification disabled");
    }

    net->ssl.on = AM_TRUE;
    CertFreeCertificateContext(server_cert_handle);
    return AM_SUCCESS;
}

void sync_connect_win(am_net_t *net) {
    static const char *thisfunc = "sync_connect_win():";
    struct win_net *wnet;
    int rv;
    char *ip_address = net->uv.host;
    u_long nonblock = 0;

    net->ssl.ssl_handle = wnet = (struct win_net *) calloc(1, sizeof (struct win_net));
    if (wnet == NULL) {
        net->error = AM_ENOMEM;
        return;
    }

    wnet->ev_net = WSACreateEvent();

    if (net->sock == INVALID_SOCKET) {
        AM_LOG_WARNING(net->instance_id,
                "%s connection to %s:%d failed",
                thisfunc, net->uv.host, net->uv.port);
        net->error = AM_ERROR;
        return;
    }

    ioctlsocket(net->sock, FIONBIO, &nonblock);

    rv = WSAEventSelect(net->sock, wnet->ev_net, FD_READ | FD_WRITE | FD_CLOSE);
    if (rv != 0) {
        net_log_error(net->instance_id, WSAGetLastError());
        closesocket(net->sock);
        net->sock = INVALID_SOCKET;
        net->error = AM_ERROR;
        return;
    }

    net->error = AM_SUCCESS;

    if (net->uv.ssl) {
        net->error = net_connect_ssl(net);
    }

    if (net->error == AM_SUCCESS) {
        AM_LOG_DEBUG(net->instance_id, "%s connected to %s:%d",
                thisfunc, net->uv.host, net->uv.port);
    } else {
        AM_LOG_ERROR(net->instance_id, "%s failed to connect to %s:%d, error: %d",
                thisfunc, net->uv.host, net->uv.port, net->error);
    }
}

#else

/* not used on this platform */
static void unused_module() {

}
#endif
