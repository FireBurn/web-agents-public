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

#include "platform.h"
#include "am.h"
#include "version.h"
#include "utility.h"
#include "net_client.h"
#include "list.h"

#define AM_NET_CONNECT_TIMEOUT 8 /*in sec*/

struct request_data {
    char *rd;
    size_t sz;
    int error;
    am_event_t *rf;
};

static void on_agent_request_data_cb(void *udata, const char *data, size_t data_sz, int status) {
    struct request_data *ld = (struct request_data *) udata;
    if (ld->rd == NULL) {
        ld->rd = malloc(data_sz + 1);
        if (ld->rd == NULL) {
            ld->error = AM_ENOMEM;
            return;
        }
        memcpy(ld->rd, data, data_sz);
        ld->rd[data_sz] = 0;
        ld->sz = data_sz;
    } else {
        char *rd_tmp = realloc(ld->rd, ld->sz + data_sz + 1);
        if (rd_tmp == NULL) {
            am_free(ld->rd);
            ld->error = AM_ENOMEM;
            return;
        } else {
            ld->rd = rd_tmp;
        }
        memcpy(ld->rd + ld->sz, data, data_sz);
        ld->sz += data_sz;
        ld->rd[ld->sz] = 0;
    }
}

static void on_connected_cb(void *udata, int status) {
}

static void on_close_cb(void *udata, int status) {
    struct request_data *ld = (struct request_data *) udata;
    set_event(ld->rf);
}

static void on_complete_cb(void *udata, int status) {
    struct request_data *ld = (struct request_data *) udata;
    set_event(ld->rf);
}

static int send_authcontext_request(am_net_t *conn, const char *realm, char **token) {
    static const char *thisfunc = "send_authcontext_request():";
    size_t post_sz, post_data_sz;
    char *post = NULL, *post_data = NULL;
    int status = AM_ERROR;
    struct request_data *req_data;

    if (conn == NULL || conn->data == NULL || token == NULL ||
            !ISVALID(realm)) return AM_EINVAL;

    req_data = (struct request_data *) conn->data;

    post_data_sz = am_asprintf(&post_data,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<RequestSet vers=\"1.0\" svcid=\"auth\" reqid=\"0\">"
            "<Request><![CDATA["
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><AuthContext version=\"1.0\">"
            "<Request authIdentifier=\"0\">"
            "<NewAuthContext orgName=\"%s\"/></Request></AuthContext>]]>"
            "</Request></RequestSet>",
            realm);
    if (post_data == NULL) return AM_ENOMEM;

    post_sz = am_asprintf(&post, "POST %s/authservice HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: "MODINFO"\r\n"
            "Accept: text/xml\r\n"
            "Content-Language: UTF-8\r\n"
            "Connection: Keep-Alive\r\n"
            "Content-Type: text/xml; charset=UTF-8\r\n"
            "Content-Length: %d\r\n\r\n"
            "%s", conn->uv.path, conn->uv.host, conn->uv.port, post_data_sz, post_data);
    if (post == NULL) {
        free(post_data);
        return AM_ENOMEM;
    }

#ifdef DEBUG
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes", thisfunc, post_sz);
#endif
    if (conn->log != NULL) {
#ifdef DEBUG
        conn->log("%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
        conn->log("%s sending %d bytes", thisfunc, post_sz);
#endif                
    }

    status = am_net_write(conn, post, post_sz);
    free(post_data);
    free(post);

    if (status == AM_SUCCESS) {
        wait_for_event(req_data->rf, 0);
    }

    AM_LOG_DEBUG(conn->instance_id, "%s response status code: %d\n%s",
            thisfunc, conn->http_status, LOGEMPTY(req_data->rd));
    if (conn->log != NULL) {
        conn->log("%s response status code: %d\n%s", thisfunc,
                conn->http_status, LOGEMPTY(req_data->rd));
    }

    if (status == AM_SUCCESS && conn->http_status == 200 && ISVALID(req_data->rd)) {
        char *begin = strstr(req_data->rd, "Response authIdentifier=\"");
        if (begin != NULL) {
            char *end = strstr(begin + 25, "\"");
            if (end != NULL) {
                *token = strndup(begin + 25, end - begin - 25);
            }
        }
        if (!ISVALID(*token)) status = AM_NOT_FOUND;
    }

    AM_LOG_DEBUG(conn->instance_id, "%s status: %s", thisfunc, am_strerror(status));
    am_free(req_data->rd);
    req_data->rd = NULL;
    return status;
}

static int send_login_request(am_net_t *conn, char **token, const char *user,
        const char *password) {
    static const char *thisfunc = "send_login_request():";
    size_t post_sz, post_data_sz;
    char *post = NULL, *post_data = NULL;
    int status = AM_ERROR;
    struct request_data *req_data;

    if (conn == NULL || conn->data == NULL || token == NULL ||
            !ISVALID(*token) || !ISVALID(user)) return AM_EINVAL;

    req_data = (struct request_data *) conn->data;

    post_data_sz = am_asprintf(&post_data,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<RequestSet vers=\"1.0\" svcid=\"auth\" reqid=\"0\">"
            "<Request><![CDATA["
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><AuthContext version=\"1.0\">"
            "<Request authIdentifier=\"%s\"><Login>"
            "<IndexTypeNamePair indexType=\"moduleInstance\"><IndexName>Application</IndexName>"
            "</IndexTypeNamePair></Login></Request></AuthContext>]]>"
            "</Request>"
            "<Request><![CDATA["
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><AuthContext version=\"1.0\">"
            "<Request authIdentifier=\"%s\"><SubmitRequirements>"
            "<Callbacks length=\"2\"><NameCallback><Prompt>Enter application name.</Prompt>"
            "<Value>%s</Value>"
            "</NameCallback><PasswordCallback echoPassword=\"true\"><Prompt>Enter secret string.</Prompt>"
            "<Value>%s</Value>"
            "</PasswordCallback></Callbacks>"
            "</SubmitRequirements></Request></AuthContext>]]>"
            "</Request>"
            "</RequestSet>",
            *token, *token, user, NOTNULL(password));
    if (post_data == NULL) return AM_ENOMEM;

    post_sz = am_asprintf(&post, "POST %s/authservice HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: "MODINFO"\r\n"
            "Accept: text/xml\r\n"
            "Content-Language: UTF-8\r\n"
            "Connection: Keep-Alive\r\n"
            "Content-Type: text/xml; charset=UTF-8\r\n"
            "Content-Length: %d\r\n\r\n"
            "%s", conn->uv.path, conn->uv.host, conn->uv.port, post_data_sz, post_data);
    if (post == NULL) {
        free(post_data);
        return AM_ENOMEM;
    }

#ifdef DEBUG
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes", thisfunc, post_sz);
#endif
    if (conn->log != NULL) {
#ifdef DEBUG
        conn->log("%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
        conn->log("%s sending %d bytes", thisfunc, post_sz);
#endif                
    }

    status = am_net_write(conn, post, post_sz);
    free(post_data);
    free(post);
    free(*token); /* delete pre-login/authcontext token */
    *token = NULL;

    if (status == AM_SUCCESS) {
        wait_for_event(req_data->rf, 0);
    }

    AM_LOG_DEBUG(conn->instance_id, "%s authenticate response status code: %d\n%s",
            thisfunc, conn->http_status, LOGEMPTY(req_data->rd));
    if (conn->log != NULL) {
        conn->log("%s authenticate response status code: %d\n%s", thisfunc,
                conn->http_status, LOGEMPTY(req_data->rd));
    }

    status = AM_ERROR;

    if (ISVALID(req_data->rd)) {
        char *begin = strstr(req_data->rd, "LoginStatus status=\"success\" ssoToken=\"");
        if (begin != NULL) {
            char *end = strstr(begin + 39, "\"");
            if (end != NULL) {
                *token = strndup(begin + 39, end - begin - 39);
                if (ISVALID(*token)) status = AM_SUCCESS;
            }
        }
    }

    AM_LOG_DEBUG(conn->instance_id, "%s status: %s", thisfunc, am_strerror(status));
    am_free(req_data->rd);
    req_data->rd = NULL;
    return status;
}

static int send_attribute_request(am_net_t *conn, char **token, char **pxml, size_t *pxsz,
        const char *user, const char *realm) {
    static const char *thisfunc = "send_attribute_request():";
    size_t post_sz;
    char *post = NULL;
    int status = AM_ERROR;
    struct request_data *req_data;
    char *token_enc;
    char *realm_enc = url_encode(realm);
    char *user_enc = url_encode(user);

    if (conn == NULL || conn->data == NULL || token == NULL ||
            !ISVALID(*token) || !ISVALID(realm) || !ISVALID(user)) return AM_EINVAL;

    token_enc = url_encode(*token);
    req_data = (struct request_data *) conn->data;

    post_sz = am_asprintf(&post, "GET %s/identity/xml/read?"
            "name=%s&attributes_names=realm&attributes_values_realm=%s&attributes_names=objecttype"
            "&attributes_values_objecttype=Agent&admin=%s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: "MODINFO"\r\n"
            "Accept: text/xml\r\n"
            "Connection: Keep-Alive\r\n\r\n",
            conn->uv.path,
            user_enc, realm_enc, token_enc,
            conn->uv.host, conn->uv.port);
    if (post == NULL) {
        AM_FREE(realm_enc, user_enc, token_enc);
        return AM_ENOMEM;
    }

#ifdef DEBUG
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes", thisfunc, post_sz);
#endif
    if (conn->log != NULL) {
#ifdef DEBUG
        conn->log("%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
        conn->log("%s sending %d bytes", thisfunc, post_sz);
#endif                
    }

    status = am_net_write(conn, post, post_sz);
    free(post);

    if (status == AM_SUCCESS) {
        wait_for_event(req_data->rf, 0);
    }

    AM_LOG_DEBUG(conn->instance_id, "%s response status code: %d\n%s",
            thisfunc, conn->http_status, LOGEMPTY(req_data->rd));
    if (conn->log != NULL) {
        conn->log("%s response status code: %d\n%s", thisfunc,
                conn->http_status, LOGEMPTY(req_data->rd));
    }

    if (status == AM_SUCCESS && conn->http_status == 200 && ISVALID(req_data->rd)) {
        if (stristr(req_data->rd, "exception") != NULL) {
            status = AM_ERROR;
        } else {
            if (pxml != NULL) {
                *pxml = malloc(req_data->sz + 1);
                if (*pxml != NULL) {
                    memcpy(*pxml, req_data->rd, req_data->sz);
                    (*pxml)[req_data->sz] = 0;
                } else {
                    status = AM_ENOMEM;
                }
            }
            if (pxsz != NULL) *pxsz = req_data->sz;
        }
    }

    AM_LOG_DEBUG(conn->instance_id, "%s status: %s", thisfunc, am_strerror(status));
    AM_FREE(req_data->rd, realm_enc, user_enc, token_enc);
    req_data->rd = NULL;
    return status;
}

static int send_session_request(am_net_t *conn, char **token, const char *notifyurl,
        struct am_namevalue **session_list) {
    static const char *thisfunc = "send_session_request():";
    size_t post_sz, post_data_sz, token_sz;
    char *post = NULL, *post_data = NULL, *token_in = NULL, *token_b64;
    int status = AM_ERROR;
    struct request_data *req_data;

    if (conn == NULL || conn->data == NULL || token == NULL ||
            !ISVALID(*token)) return AM_EINVAL;

    token_sz = am_asprintf(&token_in, "token:%s", *token);
    token_b64 = base64_encode(token_in, &token_sz);

    req_data = (struct request_data *) conn->data;

    post_data_sz = am_asprintf(&post_data,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<RequestSet vers=\"1.0\" svcid=\"Session\" reqid=\"0\">"
            "<Request><![CDATA["
            "<SessionRequest vers=\"1.0\" reqid=\"1\" requester=\"%s\">"
            "<GetSession reset=\"true\">"
            "<SessionID>%s</SessionID>"
            "</GetSession>"
            "</SessionRequest>]]>"
            "</Request>"
            "<Request><![CDATA["
            "<SessionRequest vers=\"1.0\" reqid=\"2\" requester=\"%s\">"
            "<AddSessionListener>"
            "<URL>%s</URL>"
            "<SessionID>%s</SessionID>"
            "</AddSessionListener>"
            "</SessionRequest>]]>"
            "</Request>"
            "</RequestSet>",
            NOTNULL(token_b64), *token, NOTNULL(token_b64), notifyurl, *token);
    if (post_data == NULL) {
        am_free(token_b64);
        return AM_ENOMEM;
    }

    post_sz = am_asprintf(&post, "POST %s/sessionservice HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: "MODINFO"\r\n"
            "Accept: text/xml\r\n"
            "Content-Language: UTF-8\r\n"
            "Connection: Keep-Alive\r\n"
            "Content-Type: text/xml; charset=UTF-8\r\n"
            "Content-Length: %d\r\n\r\n"
            "%s", conn->uv.path, conn->uv.host, conn->uv.port, post_data_sz, post_data);
    if (post == NULL) {
        free(post_data);
        am_free(token_b64);
        return AM_ENOMEM;
    }

#ifdef DEBUG
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes", thisfunc, post_sz);
#endif
    if (conn->log != NULL) {
#ifdef DEBUG
        conn->log("%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
        conn->log("%s sending %d bytes", thisfunc, post_sz);
#endif                
    }

    status = am_net_write(conn, post, post_sz);
    free(post_data);
    free(post);
    am_free(token_b64);

    if (status == AM_SUCCESS) {
        wait_for_event(req_data->rf, 0);
    }

    AM_LOG_DEBUG(conn->instance_id, "%s response status code: %d\n%s",
            thisfunc, conn->http_status, LOGEMPTY(req_data->rd));
    if (conn->log != NULL) {
        conn->log("%s response status code: %d\n%s", thisfunc,
                conn->http_status, LOGEMPTY(req_data->rd));
    }

    if (status == AM_SUCCESS && conn->http_status == 200 && ISVALID(req_data->rd)) {
        if (session_list != NULL) {
            *session_list = am_parse_session_xml(conn->instance_id, req_data->rd, req_data->sz);
        }
    }

    AM_LOG_DEBUG(conn->instance_id, "%s status: %s", thisfunc, am_strerror(status));
    am_free(req_data->rd);
    req_data->rd = NULL;
    return status;
}

static int send_policychange_request(am_net_t *conn, char **token, const char *notifyurl) {
    static const char *thisfunc = "send_policychange_request():";
    size_t post_sz, post_data_sz;
    char *post = NULL, *post_data = NULL;
    int status = AM_ERROR;
    struct request_data *req_data;

    if (conn == NULL || conn->data == NULL || token == NULL ||
            !ISVALID(*token) || !ISVALID(notifyurl)) return AM_EINVAL;

    req_data = (struct request_data *) conn->data;

    post_data_sz = am_asprintf(&post_data,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<RequestSet vers=\"1.0\" svcid=\"Policy\" reqid=\"1\">"
            "<Request><![CDATA["
            "<PolicyService version=\"1.0\">"
            "<PolicyRequest requestId=\"1\" appSSOToken=\"%s\">"
            "<RemovePolicyListener notificationURL=\"%s\" serviceName=\"iPlanetAMWebAgentService\"/>"
            "</PolicyRequest>"
            "</PolicyService>]]>"
            "</Request>"
            "<Request><![CDATA["
            "<PolicyService version=\"1.0\">"
            "<PolicyRequest requestId=\"2\" appSSOToken=\"%s\">"
            "<AddPolicyListener notificationURL=\"%s\" serviceName=\"iPlanetAMWebAgentService\"/>"
            "</PolicyRequest>"
            "</PolicyService>]]>"
            "</Request>"
            "</RequestSet>",
            *token, notifyurl, *token, notifyurl);
    if (post_data == NULL) return AM_ENOMEM;

    post_sz = am_asprintf(&post, "POST %s/policyservice HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: "MODINFO"\r\n"
            "Accept: text/xml\r\n"
            "Content-Language: UTF-8\r\n"
            "Connection: Close\r\n"
            "Content-Type: text/xml; charset=UTF-8\r\n"
            "Content-Length: %d\r\n\r\n"
            "%s", conn->uv.path, conn->uv.host, conn->uv.port, post_data_sz, post_data);
    if (post == NULL) {
        free(post_data);
        return AM_ENOMEM;
    }

#ifdef DEBUG
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes", thisfunc, post_sz);
#endif
    if (conn->log != NULL) {
#ifdef DEBUG
        conn->log("%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
        conn->log("%s sending %d bytes", thisfunc, post_sz);
#endif                
    }

    status = am_net_write(conn, post, post_sz);
    free(post_data);
    free(post);

    if (status == AM_SUCCESS) {
        wait_for_event(req_data->rf, 0);
    }

    AM_LOG_DEBUG(conn->instance_id, "%s authenticate response status code: %d\n%s",
            thisfunc, conn->http_status, LOGEMPTY(req_data->rd));
    if (conn->log != NULL) {
        conn->log("%s authenticate response status code: %d\n%s", thisfunc,
                conn->http_status, LOGEMPTY(req_data->rd));
    }

    AM_LOG_DEBUG(conn->instance_id, "%s status: %s", thisfunc, am_strerror(status));
    am_free(req_data->rd);
    req_data->rd = NULL;
    return status;
}

int am_agent_login(unsigned long instance_id, const char *openam, const char *notifyurl,
        const char *user, const char *pass, const char *realm, int is_local,
        struct am_ssl_options *info,
        char **agent_token, char **pxml, size_t *pxsz, struct am_namevalue **session_list,
        void(*log)(const char *, ...)) {
    static const char *thisfunc = "am_agent_login():";
    am_net_t conn;
    int status = AM_ERROR;
    struct request_data req_data;

    if (!ISVALID(realm) || !ISVALID(user) ||
            !ISVALID(pass) || !ISVALID(openam)) return AM_EINVAL;

    memset(&req_data, 0, sizeof (struct request_data));

    memset(&conn, 0, sizeof (am_net_t));
    conn.log = log;
    conn.instance_id = instance_id;
    conn.timeout = AM_NET_CONNECT_TIMEOUT;
    conn.url = openam;
    if (info != NULL) {
        memcpy(&conn.ssl.info, info, sizeof (struct am_ssl_options));
    }

    req_data.rf = create_event();
    if (req_data.rf == NULL) return AM_ENOMEM;

    conn.data = &req_data;
    conn.on_connected = on_connected_cb;
    conn.on_close = on_close_cb;
    conn.on_data = on_agent_request_data_cb;
    conn.on_complete = on_complete_cb;

    if (am_net_connect(&conn) == 0) {

        do {
            /* authenticate with agent profile/password and module Application (PLL endpoint) */
            status = send_authcontext_request(&conn, realm, agent_token);
            if (status != AM_SUCCESS) break;

            status = send_login_request(&conn, agent_token, user, pass);
            if (status != AM_SUCCESS) break;

            if (!is_local) {
                /* send agent attribute request (/identity/xml/read REST endpoint);
                 * no interest in a remote profile in case of a local-only configuration
                 */
                status = send_attribute_request(&conn, agent_token, pxml, pxsz, user, realm);
                if (status != AM_SUCCESS) break;
            }

            /* send session request (PLL endpoint) */
            status = send_session_request(&conn, agent_token, notifyurl, session_list);
            if (status != AM_SUCCESS) break;

            /* subscribe to a policy change notification (PLL endpoint) */
            status = send_policychange_request(&conn, agent_token, notifyurl);
        } while (0);

        if (status != AM_SUCCESS) {
            AM_LOG_DEBUG(instance_id, "%s disconnecting", thisfunc);
            if (log != NULL) {
                log("%s disconnecting", thisfunc);
            }
            am_net_diconnect(&conn);
        }
    }

    am_net_close(&conn);
    close_event(req_data.rf);

    am_free(req_data.rd);
    return status;
}

int am_agent_logout(unsigned long instance_id, const char *openam,
        const char *token, struct am_ssl_options *info, void(*log)(const char *, ...)) {
    static const char *thisfunc = "am_agent_logout():";
    am_net_t conn;
    int status = AM_ERROR;
    size_t post_sz, post_data_sz;
    char *post = NULL, *post_data = NULL;
    struct request_data req_data;

    if (!ISVALID(token) || !ISVALID(openam)) return AM_EINVAL;

    memset(&req_data, 0, sizeof (struct request_data));
    memset(&conn, 0, sizeof (am_net_t));
    conn.log = log;
    conn.instance_id = instance_id;
    conn.timeout = AM_NET_CONNECT_TIMEOUT;
    conn.url = openam;
    if (info != NULL) {
        memcpy(&conn.ssl.info, info, sizeof (struct am_ssl_options));
    }

    req_data.rf = create_event();
    if (req_data.rf == NULL) return AM_ENOMEM;

    conn.data = &req_data;
    conn.on_connected = on_connected_cb;
    conn.on_close = on_close_cb;
    conn.on_data = on_agent_request_data_cb;
    conn.on_complete = on_complete_cb;

    if (am_net_connect(&conn) == 0) {
        post_data_sz = am_asprintf(&post_data,
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<RequestSet vers=\"1.0\" svcid=\"auth\" reqid=\"0\">"
                "<Request><![CDATA["
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><AuthContext version=\"1.0\">"
                "<Request authIdentifier=\"%s\">"
                "<Logout/></Request></AuthContext>]]>"
                "</Request></RequestSet>",
                token);
        if (post_data != NULL) {
            post_sz = am_asprintf(&post, "POST %s/authservice HTTP/1.1\r\n"
                    "Host: %s:%d\r\n"
                    "User-Agent: "MODINFO"\r\n"
                    "Accept: text/xml\r\n"
                    "Content-Language: UTF-8\r\n"
                    "Connection: Close\r\n"
                    "Content-Type: text/xml; charset=UTF-8\r\n"
                    "Content-Length: %d\r\n\r\n"
                    "%s", conn.uv.path, conn.uv.host, conn.uv.port, post_data_sz, post_data);
            if (post != NULL) {
                AM_LOG_DEBUG(instance_id, "%s sending request:\n%s", thisfunc, post);
                if (log != NULL) {
                    log("%s sending request:\n%s", thisfunc, post);
                }
                status = am_net_write(&conn, post, post_sz);
                free(post);
            }
            free(post_data);
        }
    }

    if (status == AM_SUCCESS) {
        wait_for_event(req_data.rf, 0);
    } else {
        AM_LOG_DEBUG(instance_id, "%s disconnecting", thisfunc);
        if (log != NULL) {
            log("%s disconnecting", thisfunc);
        }
        am_net_diconnect(&conn);
    }

    AM_LOG_DEBUG(instance_id, "%s response status code: %d", thisfunc, conn.http_status);
    if (log != NULL) {
        log("%s response status code: %d", thisfunc, conn.http_status);
    }

    am_net_close(&conn);
    close_event(req_data.rf);

    am_free(req_data.rd);
    return status;
}

int am_agent_naming_request(unsigned long instance_id, const char *openam, const char *token) {
    char *post = NULL, *post_data = NULL;
    am_net_t n;
    size_t post_sz;
    int status = AM_ERROR;

    struct request_data ld;

    if (!ISVALID(token) || !ISVALID(openam)) return AM_EINVAL;

    memset(&ld, 0, sizeof (struct request_data));

    memset(&n, 0, sizeof (am_net_t));
    n.instance_id = instance_id;
    n.timeout = AM_NET_CONNECT_TIMEOUT;
    n.url = openam;

    ld.rf = create_event();
    if (ld.rf == NULL) return AM_ENOMEM;

    n.data = &ld;
    n.on_connected = on_connected_cb;
    n.on_close = on_close_cb;
    n.on_data = on_agent_request_data_cb;
    n.on_complete = on_complete_cb;

    if (am_net_connect(&n) == 0) {
        size_t post_data_sz = am_asprintf(&post_data,
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<RequestSet vers=\"1.0\" svcid=\"com.iplanet.am.naming\" reqid=\"0\">"
                "<Request><![CDATA["
                "<NamingRequest vers=\"3.0\" reqid=\"1\" sessid=\"%s\">"
                "<GetNamingProfile>"
                "</GetNamingProfile>"
                "</NamingRequest>]]>"
                "</Request>"
                "</RequestSet>",
                token);
        if (post_data != NULL) {
            post_sz = am_asprintf(&post, "POST %s/namingservice HTTP/1.1\r\n"
                    "Host: %s:%d\r\n"
                    "User-Agent: "MODINFO"\r\n"
                    "Accept: text/xml\r\n"
                    "Content-Language: UTF-8\r\n"
                    "Connection: close\r\n"
                    "Content-Type: text/xml; charset=UTF-8\r\n"
                    "Content-Length: %d\r\n\r\n"
                    "%s", n.uv.path, n.uv.host, n.uv.port, post_data_sz, post_data);
            if (post != NULL) {
                status = am_net_write(&n, post, post_sz);
                free(post);
                post = NULL;
            }
            free(post_data);
            post_data = NULL;
        }
    }

    if (status == AM_SUCCESS) {
        wait_for_event(ld.rf, 0);
    } else {
        am_net_diconnect(&n);
    }

    am_net_close(&n);
    close_event(ld.rf);

    am_free(ld.rd);
    return status;
}

int am_agent_session_request(unsigned long instance_id, const char *openam,
        const char *token, const char *user_token, const char *notif_url) {
    char *post = NULL, *post_data = NULL;
    am_net_t n;
    size_t post_sz;
    int status = AM_ERROR;

    struct request_data ld;

    if (!ISVALID(token) || !ISVALID(user_token) ||
            !ISVALID(openam) || !ISVALID(notif_url)) return AM_EINVAL;

    memset(&ld, 0, sizeof (struct request_data));

    memset(&n, 0, sizeof (am_net_t));
    n.instance_id = instance_id;
    n.timeout = AM_NET_CONNECT_TIMEOUT;
    n.url = openam;

    ld.rf = create_event();
    if (ld.rf == NULL) return AM_ENOMEM;

    n.data = &ld;
    n.on_connected = on_connected_cb;
    n.on_close = on_close_cb;
    n.on_data = on_agent_request_data_cb;
    n.on_complete = on_complete_cb;

    if (am_net_connect(&n) == 0) {
        char *token_in = NULL;
        size_t token_sz = am_asprintf(&token_in, "token:%s", token);
        char *token_b64 = base64_encode(token_in, &token_sz);

        size_t post_data_sz = am_asprintf(&post_data,
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<RequestSet vers=\"1.0\" svcid=\"Session\" reqid=\"0\">"
                "<Request><![CDATA["
                "<SessionRequest vers=\"1.0\" reqid=\"1\" requester=\"%s\">"
                "<GetSession reset=\"true\">"
                "<SessionID>%s</SessionID>"
                "</GetSession>"
                "</SessionRequest>]]>"
                "</Request>"
                "<Request><![CDATA["
                "<SessionRequest vers=\"1.0\" reqid=\"2\" requester=\"%s\">"
                "<AddSessionListener>"
                "<URL>%s</URL>"
                "<SessionID>%s</SessionID>"
                "</AddSessionListener>"
                "</SessionRequest>]]>"
                "</Request>"
                "</RequestSet>",
                NOTNULL(token_b64), user_token, NOTNULL(token_b64), notif_url, user_token);

        AM_FREE(token_in, token_b64);

        if (post_data != NULL) {
            post_sz = am_asprintf(&post, "POST %s/sessionservice HTTP/1.1\r\n"
                    "Host: %s:%d\r\n"
                    "User-Agent: "MODINFO"\r\n"
                    "Accept: text/xml\r\n"
                    "Content-Language: UTF-8\r\n"
                    "Connection: close\r\n"
                    "Content-Type: text/xml; charset=UTF-8\r\n"
                    "Content-Length: %d\r\n\r\n"
                    "%s", n.uv.path, n.uv.host, n.uv.port, post_data_sz, post_data);
            if (post != NULL) {
                status = am_net_write(&n, post, post_sz);
                free(post);
                post = NULL;
            }
            free(post_data);
            post_data = NULL;
        }

    }

    if (status == AM_SUCCESS) {
        wait_for_event(ld.rf, 0);
    } else {
        am_net_diconnect(&n);
    }

    am_net_close(&n);
    close_event(ld.rf);

    am_free(ld.rd);
    return status;
}

int am_agent_policy_request(unsigned long instance_id, const char *openam,
        const char *token, const char *user_token, const char *req_url,
        const char *notif_url, const char *scope, const char *cip, const char *pattr,
        struct am_ssl_options *info,
        struct am_namevalue **session_list,
        struct am_policy_result **policy_list) {
    static const char *thisfunc = "am_agent_policy_request():";
    char *post = NULL, *post_data = NULL;
    am_net_t n;
    size_t post_sz;
    int status = AM_ERROR;
    int session_status = AM_SUCCESS;

    struct request_data ld;

    if (!ISVALID(token) || !ISVALID(user_token) || !ISVALID(notif_url) || !ISVALID(scope) ||
            !ISVALID(req_url) || !ISVALID(openam) || !ISVALID(cip)) return AM_EINVAL;

    memset(&ld, 0, sizeof (struct request_data));

    memset(&n, 0, sizeof (am_net_t));
    n.instance_id = instance_id;
    n.timeout = AM_NET_CONNECT_TIMEOUT;
    n.url = openam;
    if (info != NULL) {
        memcpy(&n.ssl.info, info, sizeof (struct am_ssl_options));
    }

    ld.rf = create_event();
    if (ld.rf == NULL) return AM_ENOMEM;

    n.data = &ld;
    n.on_connected = on_connected_cb;
    n.on_close = on_close_cb;
    n.on_data = on_agent_request_data_cb;
    n.on_complete = on_complete_cb;

    if (am_net_connect(&n) == 0) {
        char *token_in = NULL;
        size_t token_sz = am_asprintf(&token_in, "token:%s", token);
        char *token_b64 = base64_encode(token_in, &token_sz);

        size_t post_data_sz = am_asprintf(&post_data,
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<RequestSet vers=\"1.0\" svcid=\"Session\" reqid=\"0\">"
                "<Request><![CDATA["
                "<SessionRequest vers=\"1.0\" reqid=\"1\" requester=\"%s\">"
                "<GetSession reset=\"true\">" /*reset the idle timeout*/
                "<SessionID>%s</SessionID>"
                "</GetSession>"
                "</SessionRequest>]]>"
                "</Request>"
                "<Request><![CDATA["
                "<SessionRequest vers=\"1.0\" reqid=\"2\" requester=\"%s\">"
                "<AddSessionListener>"
                "<URL>%s</URL>"
                "<SessionID>%s</SessionID>"
                "</AddSessionListener>"
                "</SessionRequest>]]>"
                "</Request>"
                "</RequestSet>",
                NOTNULL(token_b64), user_token, NOTNULL(token_b64), notif_url, user_token);

        AM_FREE(token_in, token_b64);

        if (post_data != NULL) {
            post_sz = am_asprintf(&post, "POST %s/sessionservice HTTP/1.1\r\n"
                    "Host: %s:%d\r\n"
                    "User-Agent: "MODINFO"\r\n"
                    "Accept: text/xml\r\n"
                    "Content-Language: UTF-8\r\n"
                    "Connection: Keep-Alive\r\n"
                    "Content-Type: text/xml; charset=UTF-8\r\n"
                    "Content-Length: %d\r\n\r\n"
                    "%s", n.uv.path, n.uv.host, n.uv.port, post_data_sz, post_data);
            if (post != NULL) {
                AM_LOG_DEBUG(instance_id, "%s sending request:\n%s", thisfunc, post);
                status = am_net_write(&n, post, post_sz);
                free(post);
                post = NULL;
            }
            free(post_data);
            post_data = NULL;
        }

        if (status == AM_SUCCESS)
            wait_for_event(ld.rf, 0);

        AM_LOG_DEBUG(instance_id, "%s response status code: %d", thisfunc, n.http_status);

        if (status == AM_SUCCESS && n.http_status == 200 && ISVALID(ld.rd)) {
            size_t req_url_sz = strlen(req_url);
            char *req_url_escaped = malloc(req_url_sz * 6 + 1); /*worst case*/
            if (req_url_escaped != NULL) {
                memcpy(req_url_escaped, req_url, req_url_sz);
                xml_entity_escape(req_url_escaped, req_url_sz);
            }

            AM_LOG_DEBUG(instance_id, "%s response:\n%s", thisfunc, ld.rd);

            if (strstr(ld.rd, "<Exception>") != NULL && strstr(ld.rd, "Invalid session ID") != NULL) {
                session_status = AM_INVALID_SESSION;
            }
            if (strstr(ld.rd, "<Exception>") != NULL && strstr(ld.rd, "Application token passed in") != NULL) {
                session_status = AM_INVALID_AGENT_SESSION;
            }

            if (session_status == AM_SUCCESS && session_list != NULL)
                *session_list = am_parse_session_xml(instance_id, ld.rd, ld.sz);

            ld.sz = 0;
            free(ld.rd);
            ld.rd = NULL;

            /* TODO:
             * <AttributeValuePair><Attribute name=\"requestDnsName\"/><Value>%s</Value></AttributeValuePair>
             */
            post_data_sz = am_asprintf(&post_data,
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    "<RequestSet vers=\"1.0\" svcid=\"Policy\" reqid=\"3\">"
                    "<Request><![CDATA[<PolicyService version=\"1.0\">"
                    "<PolicyRequest requestId=\"4\" appSSOToken=\"%s\">"
                    "<GetResourceResults userSSOToken=\"%s\" serviceName=\"iPlanetAMWebAgentService\" resourceName=\"%s\" resourceScope=\"%s\">"
                    "<EnvParameters><AttributeValuePair><Attribute name=\"requestIp\"/><Value>%s</Value></AttributeValuePair></EnvParameters>"
                    "<GetResponseDecisions>"
                    "%s"
                    "</GetResponseDecisions>"
                    "</GetResourceResults>"
                    "</PolicyRequest>"
                    "</PolicyService>]]>"
                    "</Request>"
                    "</RequestSet>",
                    token, user_token, NOTNULL(req_url_escaped), scope,
                    cip, NOTNULL(pattr));

            am_free(req_url_escaped);

            post_sz = am_asprintf(&post, "POST %s/policyservice HTTP/1.1\r\n"
                    "Host: %s:%d\r\n"
                    "User-Agent: "MODINFO"\r\n"
                    "Accept: text/xml\r\n"
                    "Content-Language: UTF-8\r\n"
                    "Content-Type: text/xml; charset=UTF-8\r\n"
                    "Content-Length: %d\r\n"
                    "Connection: close\r\n\r\n"
                    "%s", n.uv.path, n.uv.host, n.uv.port,
                    post_data_sz, post_data);

            if (post != NULL) {
                AM_LOG_DEBUG(instance_id, "%s sending request:\n%s", thisfunc, post);
                status = am_net_write(&n, post, post_sz);
                free(post);
            }
        } else {
            status = n.error != AM_SUCCESS ? n.error : AM_ERROR;
        }
    }

    if (status == AM_SUCCESS) {
        wait_for_event(ld.rf, 0);
    } else {
        AM_LOG_DEBUG(instance_id, "%s disconnecting", thisfunc);
        am_net_diconnect(&n);
    }

    AM_LOG_DEBUG(instance_id, "%s response status code: %d", thisfunc, n.http_status);

    if (status == AM_SUCCESS && n.http_status == 200 && ISVALID(ld.rd)) {
        AM_LOG_DEBUG(instance_id, "%s response:\n%s", thisfunc, ld.rd);

        if (strstr(ld.rd, "<Exception>") != NULL && strstr(ld.rd, "SSO token is invalid") != NULL) {
            session_status = AM_INVALID_SESSION;
        }
        if (strstr(ld.rd, "<Exception>") != NULL && strstr(ld.rd, "Application sso token is invalid") != NULL) {
            session_status = AM_INVALID_AGENT_SESSION;
        }

        if (session_status == AM_SUCCESS && policy_list != NULL)
            *policy_list = am_parse_policy_xml(instance_id, ld.rd, ld.sz,
                am_scope_to_num(scope));
    }

    am_net_close(&n);
    close_event(ld.rf);

    am_free(ld.rd);
    return session_status != AM_SUCCESS ? session_status : status;
}

int am_url_validate(unsigned long instance_id, const char *url, struct am_ssl_options *info, int *httpcode) {
    static const char *thisfunc = "am_url_validate():";
    char *get = NULL;
    am_net_t n;
    size_t get_sz;
    int status = AM_ERROR;
    struct request_data ld;

    if (!ISVALID(url)) return AM_EINVAL;

    memset(&ld, 0, sizeof (struct request_data));
    memset(&n, 0, sizeof (am_net_t));
    n.log = NULL;
    n.instance_id = instance_id;
    n.timeout = AM_NET_CONNECT_TIMEOUT;
    n.url = url;
    if (info != NULL) {
        memcpy(&n.ssl.info, info, sizeof (struct am_ssl_options));
    }

    ld.rf = create_event();
    if (ld.rf == NULL) return AM_ENOMEM;

    n.data = &ld;
    n.on_connected = on_connected_cb;
    n.on_close = on_close_cb;
    n.on_data = on_agent_request_data_cb;
    n.on_complete = on_complete_cb;

    if (am_net_connect(&n) == 0) {
        get_sz = am_asprintf(&get, "HEAD %s HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "User-Agent: "MODINFO"\r\n"
                "Accept: text/plain\r\n"
                "Connection: close\r\n\r\n",
                n.uv.path, n.uv.host, n.uv.port);
        if (get != NULL) {
            AM_LOG_DEBUG(instance_id, "%s sending request:\n%s", thisfunc, get);
            status = am_net_write(&n, get, get_sz);
            free(get);
        }
    }

    if (status == AM_SUCCESS) {
        wait_for_event(ld.rf, 0);
    } else {
        AM_LOG_DEBUG(instance_id, "%s disconnecting", thisfunc);
        am_net_diconnect(&n);
    }

    AM_LOG_DEBUG(instance_id, "%s response status code: %d", thisfunc, n.http_status);
    if (httpcode) *httpcode = n.http_status;

    am_net_close(&n);
    close_event(ld.rf);

    am_free(ld.rd);
    return status;
}
