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

#define AM_LB_COOKIE "amlbcookie"

struct request_data {
    char *data;
    size_t data_size;
    int error;
    am_event_t *event;
};

static void on_agent_request_data_cb(void *udata, const char *data, size_t data_sz, int status) {
    struct request_data *ld = (struct request_data *) udata;
    if (ld->data == NULL) {
        ld->data = malloc(data_sz + 1);
        if (ld->data == NULL) {
            ld->error = AM_ENOMEM;
            return;
        }
        memcpy(ld->data, data, data_sz);
        ld->data[data_sz] = 0;
        ld->data_size = data_sz;
    } else {
        char *rd_tmp = realloc(ld->data, ld->data_size + data_sz + 1);
        if (rd_tmp == NULL) {
            am_free(ld->data);
            ld->error = AM_ENOMEM;
            return;
        } else {
            ld->data = rd_tmp;
        }
        memcpy(ld->data + ld->data_size, data, data_sz);
        ld->data_size += data_sz;
        ld->data[ld->data_size] = 0;
    }
}

static void on_connected_cb(void *udata, int status) {
}

static void on_close_cb(void *udata, int status) {
    struct request_data *ld = (struct request_data *) udata;
    set_event(ld->event);
}

static void on_complete_cb(void *udata, int status) {
    struct request_data *ld = (struct request_data *) udata;
    set_event(ld->event);
}

static void create_cookie_header(am_net_t *conn, const char *token) {
    static const char *thisfunc = "create_cookie_header():";
    int i;
    am_bool_t cookies_set = AM_FALSE;

#define AM_COOKIE_HEADER "Cookie: "

    /* look into response headers and get the Cookie header ready for the subsequent requests */
    if (conn->num_headers > 0) {
        conn->req_headers = strdup(AM_COOKIE_HEADER);
        if (conn->req_headers != NULL) {
            for (i = 0; i < conn->num_headers; i++) {
                if (strcasecmp("Set-Cookie", conn->header_fields[i]) == 0) {
                    char *cookie = conn->header_values[i];
                    char *sep = strchr(cookie, ';'); /* Cookie request header needs only "cookie_name=value" pair */
                    if (sep != NULL) {
                        *sep = '\0';
                    }
                    am_asprintf(&conn->req_headers, "%s%s; ", conn->req_headers, cookie);
                    cookies_set = AM_TRUE;
                }
            }

            if (cookies_set) {
                char *sep = strrchr(conn->req_headers, ';'); /* trim the trailing "; " */
                if (sep != NULL) {
                    *sep = '\0';
                }
                am_asprintf(&conn->req_headers, "%s\r\n", conn->req_headers);
            }
        }
    }

    /* in case load.balancer.enable is set but the header list above does not contain AM_LB_COOKIE already,
     * create (or attach) AM_LB_COOKIE with the value parsed out of the token
     */
    if (conn->options != NULL && conn->options->lb_enable && ISVALID(token) &&
            (ISINVALID(conn->req_headers) || stristr(conn->req_headers, AM_LB_COOKIE) == NULL)) {
        am_request_t req_temp;
        int decode_status;

        memset(&req_temp, 0, sizeof (am_request_t));
        req_temp.token = strdup(token);

        decode_status = am_session_decode(&req_temp);
        if (decode_status == AM_SUCCESS && req_temp.session_info.error == AM_SUCCESS &&
                ISVALID(req_temp.session_info.si)) {

            if (ISINVALID(conn->req_headers)) {
                am_asprintf(&conn->req_headers, "Cookie: "AM_LB_COOKIE"=%s\r\n", req_temp.session_info.si);
            } else {
                size_t len = strlen(conn->req_headers);
                conn->req_headers[len - 2] = '\0'; /* trim the trailing "\r\n" */
                am_asprintf(&conn->req_headers, "%s; "AM_LB_COOKIE"=%s\r\n",
                        conn->req_headers, req_temp.session_info.si);
            }

            AM_LOG_DEBUG(conn->instance_id, "%s app token SI: %s, S1: %s", thisfunc,
                    LOGEMPTY(req_temp.session_info.si), LOGEMPTY(req_temp.session_info.s1));
        }
        am_request_free(&req_temp);
    }

    if (conn->options != NULL && ISVALID(conn->options->server_id) &&
            (ISINVALID(conn->req_headers) || stristr(conn->req_headers, AM_LB_COOKIE) == NULL)) {
        if (ISINVALID(conn->req_headers)) {
            am_asprintf(&conn->req_headers, "Cookie: "AM_LB_COOKIE"=%s\r\n", conn->options->server_id);
        } else {
            size_t len = strlen(conn->req_headers);
            conn->req_headers[len - 2] = '\0'; /* trim the trailing "\r\n" */
            am_asprintf(&conn->req_headers, "%s; "AM_LB_COOKIE"=%s\r\n",
                    conn->req_headers, conn->options->server_id);
        }
    }

    if (ISVALID(conn->req_headers) && strcmp(conn->req_headers, AM_COOKIE_HEADER) == 0) {
        /* nothing is set, clear req_headers */
        free(conn->req_headers);
        conn->req_headers = NULL;
    }

    if (ISVALID(conn->req_headers)) {
        AM_LOG_DEBUG(conn->instance_id, "%s request header: %s", thisfunc, conn->req_headers);
        if (conn->options != NULL && conn->options->log != NULL) {
            conn->options->log("%s request header: %s", thisfunc, conn->req_headers);
        }
    }
}

static int send_authcontext_request(am_net_t *conn, const char *realm, char **token) {
    static const char *thisfunc = "send_authcontext_request():";
    size_t post_sz, post_data_sz;
    char *post = NULL, *post_data = NULL;
    int status = AM_ERROR;
    struct request_data *req_data;
    char *keepalive = "Keep-Alive";

    if (conn == NULL || conn->data == NULL || token == NULL ||
            !ISVALID(realm)) return AM_EINVAL;

    req_data = (struct request_data *) conn->data;

    if (conn->options != NULL && !conn->options->keepalive) {
        keepalive = "Close";
    }

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
            "Connection: %s\r\n"
            "Content-Type: text/xml; charset=UTF-8\r\n"
            "Content-Length: %d\r\n\r\n"
            "%s", conn->uv.path, conn->uv.host, conn->uv.port, keepalive, post_data_sz, post_data);
    if (post == NULL) {
        free(post_data);
        return AM_ENOMEM;
    }

#ifdef DEBUG
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes", thisfunc, post_sz);
#endif
    if (conn->options != NULL && conn->options->log != NULL) {
#ifdef DEBUG
        conn->options->log("%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
        conn->options->log("%s sending %d bytes", thisfunc, post_sz);
#endif                
    }

    status = am_net_write(conn, post, post_sz);
    free(post_data);
    free(post);

    if (status == AM_SUCCESS) {
        wait_for_event(req_data->event, 0);
    }

    AM_LOG_DEBUG(conn->instance_id, "%s response status code: %d\n%s",
            thisfunc, conn->http_status, LOGEMPTY(req_data->data));
    if (conn->options != NULL && conn->options->log != NULL) {
        conn->options->log("%s response status code: %d\n%s", thisfunc,
                conn->http_status, LOGEMPTY(req_data->data));
    }

    if (status == AM_SUCCESS && conn->http_status == 200 && ISVALID(req_data->data)) {
        char *begin = strstr(req_data->data, "Response authIdentifier=\"");
        if (begin != NULL) {
            char *end = strstr(begin + 25, "\"");
            if (end != NULL) {
                *token = strndup(begin + 25, end - begin - 25);
            }
        }
        if (ISINVALID(*token)) {
            status = AM_NOT_FOUND;
        }
        if (status == AM_SUCCESS) {
            create_cookie_header(conn, *token);
        }
    }

    AM_LOG_DEBUG(conn->instance_id, "%s status: %s", thisfunc, am_strerror(status));
    am_free(req_data->data);
    req_data->data = NULL;
    req_data->data_size = 0;
    return status;
}

static int send_login_request(am_net_t *conn, char **token, const char *user, const char *password) {
    static const char *thisfunc = "send_login_request():";
    size_t post_sz, post_data_sz, xml_esc_sz;
    char *post = NULL, *post_data = NULL;
    int status = AM_ERROR;
    struct request_data *req_data;
    char *user_xml_esc = NULL, *pass_xml_esc = NULL;
    char *keepalive = "Keep-Alive";

    if (conn == NULL || conn->data == NULL || token == NULL ||
            !ISVALID(*token) || !ISVALID(user)) return AM_EINVAL;

    if (conn->options != NULL && !conn->options->keepalive) {
        keepalive = "Close";
    }

    /* do xml-escape */
    xml_esc_sz = strlen(user);
    user_xml_esc = malloc(xml_esc_sz * 6 + 1); /* worst case */
    if (user_xml_esc != NULL) {
        memcpy(user_xml_esc, user, xml_esc_sz);
        xml_entity_escape(user_xml_esc, xml_esc_sz);
    } else {
        return AM_ENOMEM;
    }

    if (ISVALID(password)) {
        xml_esc_sz = strlen(password);
        pass_xml_esc = malloc(xml_esc_sz * 6 + 1); /* worst case */
        if (pass_xml_esc != NULL) {
            memcpy(pass_xml_esc, password, xml_esc_sz);
            xml_entity_escape(pass_xml_esc, xml_esc_sz);
        } else {
            free(user_xml_esc);
            return AM_ENOMEM;
        }
    }

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
            *token, *token, user_xml_esc, NOTNULL(pass_xml_esc));

    AM_FREE(user_xml_esc, pass_xml_esc);
    if (post_data == NULL) {
        return AM_ENOMEM;
    }

    post_sz = am_asprintf(&post, "POST %s/authservice HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: "MODINFO"\r\n"
            "Accept: text/xml\r\n"
            "Connection: %s\r\n"
            "Content-Type: text/xml; charset=UTF-8\r\n"
            "%s"
            "Content-Length: %d\r\n\r\n"
            "%s", conn->uv.path, conn->uv.host, conn->uv.port, keepalive,
            NOTNULL(conn->req_headers), post_data_sz, post_data);
    if (post == NULL) {
        free(post_data);
        return AM_ENOMEM;
    }

#ifdef DEBUG
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes", thisfunc, post_sz);
#endif
    if (conn->options != NULL && conn->options->log != NULL) {
#ifdef DEBUG
        conn->options->log("%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
        conn->options->log("%s sending %d bytes", thisfunc, post_sz);
#endif                
    }

    status = am_net_write(conn, post, post_sz);
    free(post_data);
    free(post);
    free(*token); /* delete pre-login/authcontext token */
    *token = NULL;

    if (status == AM_SUCCESS) {
        wait_for_event(req_data->event, 0);
    }

    AM_LOG_DEBUG(conn->instance_id, "%s authenticate response status code: %d\n%s",
            thisfunc, conn->http_status, LOGEMPTY(req_data->data));
    if (conn->options != NULL && conn->options->log != NULL) {
        conn->options->log("%s authenticate response status code: %d\n%s", thisfunc,
                conn->http_status, LOGEMPTY(req_data->data));
    }

    status = AM_ERROR;

    if (ISVALID(req_data->data)) {
        char *begin = strstr(req_data->data, "LoginStatus status=\"success\" ssoToken=\"");
        if (begin != NULL) {
            char *end = strstr(begin + 39, "\"");
            if (end != NULL) {
                *token = strndup(begin + 39, end - begin - 39);
                if (ISVALID(*token)) status = AM_SUCCESS;
            }
        }
    }

    AM_LOG_DEBUG(conn->instance_id, "%s status: %s", thisfunc, am_strerror(status));
    am_free(req_data->data);
    req_data->data = NULL;
    req_data->data_size = 0;
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
    char *keepalive = "Keep-Alive";

    if (conn == NULL || conn->data == NULL || token == NULL ||
            !ISVALID(*token) || !ISVALID(realm) || !ISVALID(user)) return AM_EINVAL;

    token_enc = url_encode(*token);
    req_data = (struct request_data *) conn->data;
    if (conn->options != NULL && !conn->options->keepalive) {
        keepalive = "Close";
    }

    post_sz = am_asprintf(&post, "GET %s/identity/xml/read?"
            "name=%s&attributes_names=realm&attributes_values_realm=%s&attributes_names=objecttype"
            "&attributes_values_objecttype=Agent&admin=%s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: "MODINFO"\r\n"
            "Accept: text/xml\r\n"
            "%s"
            "Connection: %s\r\n\r\n",
            conn->uv.path,
            NOTNULL(user_enc), NOTNULL(realm_enc), NOTNULL(token_enc),
            conn->uv.host, conn->uv.port, NOTNULL(conn->req_headers), keepalive);
    if (post == NULL) {
        AM_FREE(realm_enc, user_enc, token_enc);
        return AM_ENOMEM;
    }

#ifdef DEBUG
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes", thisfunc, post_sz);
#endif
    if (conn->options != NULL && conn->options->log != NULL) {
#ifdef DEBUG
        conn->options->log("%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
        conn->options->log("%s sending %d bytes", thisfunc, post_sz);
#endif                
    }

    status = am_net_write(conn, post, post_sz);
    free(post);

    if (status == AM_SUCCESS) {
        wait_for_event(req_data->event, 0);
    }

    AM_LOG_DEBUG(conn->instance_id, "%s response status code: %d\n%s",
            thisfunc, conn->http_status, LOGEMPTY(req_data->data));
    if (conn->options != NULL && conn->options->log != NULL) {
        conn->options->log("%s response status code: %d\n%s", thisfunc,
                conn->http_status, LOGEMPTY(req_data->data));
    }

    if (status == AM_SUCCESS && conn->http_status == 200 && ISVALID(req_data->data)) {
        if (stristr(req_data->data, "exception") != NULL) {
            status = AM_ERROR;
        } else {
            if (pxml != NULL) {
                *pxml = malloc(req_data->data_size + 1);
                if (*pxml != NULL) {
                    memcpy(*pxml, req_data->data, req_data->data_size);
                    (*pxml)[req_data->data_size] = 0;
                } else {
                    status = AM_ENOMEM;
                }
            }
            if (pxsz != NULL) *pxsz = req_data->data_size;
        }
    }

    AM_LOG_DEBUG(conn->instance_id, "%s status: %s", thisfunc, am_strerror(status));
    AM_FREE(req_data->data, realm_enc, user_enc, token_enc);
    req_data->data = NULL;
    req_data->data_size = 0;
    return status;
}

static int send_session_request(am_net_t *conn, char **token, const char *user_token,
        struct am_namevalue **session_list) {
    static const char *thisfunc = "send_session_request():";
    size_t post_sz, post_data_sz, token_sz;
    char *post = NULL, *post_data = NULL, *token_in = NULL, *token_b64;
    int status = AM_ERROR;
    struct request_data *req_data;
    char *keepalive = "Keep-Alive";

    if (conn == NULL || conn->data == NULL ||
            token == NULL || !ISVALID(*token)) return AM_EINVAL;

    token_sz = am_asprintf(&token_in, "token:%s", *token);
    token_b64 = base64_encode(token_in, &token_sz);

    if (conn->options != NULL && !conn->options->keepalive) {
        keepalive = "Close";
    }

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
            NOTNULL(token_b64), ISVALID(user_token) ? user_token : *token, NOTNULL(token_b64),
            (conn->options != NULL && ISVALID(conn->options->notif_url) ? conn->options->notif_url : ""),
            ISVALID(user_token) ? user_token : *token);
    if (post_data == NULL) {
        AM_FREE(token_b64, token_in);
        return AM_ENOMEM;
    }

    post_sz = am_asprintf(&post, "POST %s/sessionservice HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: "MODINFO"\r\n"
            "Accept: text/xml\r\n"
            "Connection: %s\r\n"
            "Content-Type: text/xml; charset=UTF-8\r\n"
            "%s"
            "Content-Length: %d\r\n\r\n"
            "%s", conn->uv.path, conn->uv.host, conn->uv.port, keepalive,
            NOTNULL(conn->req_headers), post_data_sz, post_data);
    if (post == NULL) {
        AM_FREE(post_data, token_b64, token_in);
        return AM_ENOMEM;
    }

#ifdef DEBUG
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes", thisfunc, post_sz);
#endif
    if (conn->options != NULL && conn->options->log != NULL) {
#ifdef DEBUG
        conn->options->log("%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
        conn->options->log("%s sending %d bytes", thisfunc, post_sz);
#endif                
    }

    status = am_net_write(conn, post, post_sz);
    AM_FREE(post, post_data, token_b64, token_in);

    if (status == AM_SUCCESS) {
        wait_for_event(req_data->event, 0);
    }

    AM_LOG_DEBUG(conn->instance_id, "%s response status code: %d\n%s",
            thisfunc, conn->http_status, LOGEMPTY(req_data->data));
    if (conn->options != NULL && conn->options->log != NULL) {
        conn->options->log("%s response status code: %d\n%s", thisfunc,
                conn->http_status, LOGEMPTY(req_data->data));
    }

    if (status == AM_SUCCESS && conn->http_status == 200 && ISVALID(req_data->data)) {
        if (strstr(req_data->data, "<Exception>") != NULL) {
            status = AM_ERROR;
            if (strstr(req_data->data, "Invalid session ID") != NULL) {
                status = AM_INVALID_SESSION;
            }
            if (strstr(req_data->data, "Application token passed in") != NULL) {
                status = AM_INVALID_AGENT_SESSION;
            }
        }
        if (status == AM_SUCCESS && session_list != NULL) {
            *session_list = am_parse_session_xml(conn->instance_id, req_data->data, req_data->data_size);
        }
    }

    AM_LOG_DEBUG(conn->instance_id, "%s status: %s", thisfunc, am_strerror(status));
    if (conn->options != NULL && conn->options->log != NULL) {
        conn->options->log("%s status: %s", thisfunc, am_strerror(status));
    }

    am_free(req_data->data);
    req_data->data = NULL;
    req_data->data_size = 0;
    return status;
}

static int send_policychange_request(am_net_t *conn, char **token) {
    static const char *thisfunc = "send_policychange_request():";
    size_t post_sz, post_data_sz;
    char *post = NULL, *post_data = NULL;
    int status = AM_ERROR;
    struct request_data *req_data;
    char *notifyurl;

    if (conn == NULL || conn->data == NULL || token == NULL ||
            !ISVALID(*token)) return AM_EINVAL;

    notifyurl = conn->options != NULL && ISVALID(conn->options->notif_url) ? conn->options->notif_url : "";
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
            "Connection: Close\r\n"
            "Content-Type: text/xml; charset=UTF-8\r\n"
            "%s"
            "Content-Length: %d\r\n\r\n"
            "%s", conn->uv.path, conn->uv.host, conn->uv.port,
            NOTNULL(conn->req_headers), post_data_sz, post_data);
    if (post == NULL) {
        free(post_data);
        return AM_ENOMEM;
    }

#ifdef DEBUG
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes", thisfunc, post_sz);
#endif
    if (conn->options != NULL && conn->options->log != NULL) {
#ifdef DEBUG
        conn->options->log("%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
        conn->options->log("%s sending %d bytes", thisfunc, post_sz);
#endif                
    }

    status = am_net_write(conn, post, post_sz);
    free(post_data);
    free(post);

    if (status == AM_SUCCESS) {
        wait_for_event(req_data->event, 0);
    }

    AM_LOG_DEBUG(conn->instance_id, "%s authenticate response status code: %d\n%s",
            thisfunc, conn->http_status, LOGEMPTY(req_data->data));
    if (conn->options != NULL && conn->options->log != NULL) {
        conn->options->log("%s authenticate response status code: %d\n%s", thisfunc,
                conn->http_status, LOGEMPTY(req_data->data));
    }

    AM_LOG_DEBUG(conn->instance_id, "%s status: %s", thisfunc, am_strerror(status));
    am_free(req_data->data);
    req_data->data = NULL;
    req_data->data_size = 0;
    return status;
}

static int send_policy_request(am_net_t *conn, const char *token, const char *user_token,
        const char *req_url, const char *scope, const char *cip, const char *pattr,
        struct am_policy_result **policy_list) {
    static const char *thisfunc = "send_policy_request():";
    size_t post_sz, post_data_sz;
    char *post = NULL, *post_data = NULL;
    int status = AM_ERROR;
    struct request_data *req_data;
    size_t req_url_sz;
    char *req_url_escaped;

    if (conn == NULL || conn->data == NULL || !ISVALID(token) || !ISVALID(user_token) ||
            !ISVALID(req_url) || !ISVALID(scope) || !ISVALID(cip)) return AM_EINVAL;

    req_data = (struct request_data *) conn->data;

    /* do xml-escape */
    req_url_sz = strlen(req_url);
    req_url_escaped = malloc(req_url_sz * 6 + 1); /* worst case */
    if (req_url_escaped == NULL) return AM_ENOMEM;
    memcpy(req_url_escaped, req_url, req_url_sz);
    xml_entity_escape(req_url_escaped, req_url_sz);

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
            token, user_token, req_url_escaped, scope, cip, NOTNULL(pattr));

    if (post_data == NULL) {
        free(req_url_escaped);
        return AM_ENOMEM;
    }

    post_sz = am_asprintf(&post, "POST %s/policyservice HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: "MODINFO"\r\n"
            "Accept: text/xml\r\n"
            "Connection: Close\r\n"
            "Content-Type: text/xml; charset=UTF-8\r\n"
            "%s"
            "Content-Length: %d\r\n\r\n"
            "%s", conn->uv.path, conn->uv.host, conn->uv.port,
            NOTNULL(conn->req_headers), post_data_sz, post_data);
    if (post == NULL) {
        AM_FREE(post_data, req_url_escaped);
        return AM_ENOMEM;
    }

#ifdef DEBUG
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
    AM_LOG_DEBUG(conn->instance_id, "%s sending %d bytes", thisfunc, post_sz);
#endif
    if (conn->options != NULL && conn->options->log != NULL) {
#ifdef DEBUG
        conn->options->log("%s sending %d bytes:\n%s", thisfunc, post_sz, post);
#else
        conn->options->log("%s sending %d bytes", thisfunc, post_sz);
#endif                
    }

    status = am_net_write(conn, post, post_sz);
    AM_FREE(post_data, post, req_url_escaped);

    if (status == AM_SUCCESS) {
        wait_for_event(req_data->event, 0);
    }

    AM_LOG_DEBUG(conn->instance_id, "%s authenticate response status code: %d\n%s",
            thisfunc, conn->http_status, LOGEMPTY(req_data->data));
    if (conn->options != NULL && conn->options->log != NULL) {
        conn->options->log("%s authenticate response status code: %d\n%s", thisfunc,
                conn->http_status, LOGEMPTY(req_data->data));
    }

    if (status == AM_SUCCESS && conn->http_status == 200 && ISVALID(req_data->data)) {
        if (strstr(req_data->data, "<Exception>") != NULL) {
            status = AM_ERROR;
            if (strstr(req_data->data, "Invalid session ID") != NULL) {
                status = AM_INVALID_SESSION;
            }
            if (strstr(req_data->data, "Application token passed in") != NULL) {
                status = AM_INVALID_AGENT_SESSION;
            }
        }
        if (status == AM_SUCCESS && policy_list != NULL) {
            *policy_list = am_parse_policy_xml(conn->instance_id, req_data->data, req_data->data_size,
                    am_scope_to_num(scope));
        }
    }

    AM_LOG_DEBUG(conn->instance_id, "%s status: %s", thisfunc, am_strerror(status));
    am_free(req_data->data);
    req_data->data = NULL;
    req_data->data_size = 0;
    return status;
}

static int do_net_connect(am_net_t *conn, struct request_data *req_data,
        unsigned long instance_id, const char *openam, am_net_options_t *options) {
    memset(req_data, 0, sizeof (struct request_data));
    memset(conn, 0, sizeof (am_net_t));
    conn->options = options;
    conn->instance_id = instance_id;
    conn->url = openam;

    req_data->event = create_event();
    if (req_data->event == NULL) return AM_ENOMEM;

    conn->data = req_data;
    conn->on_connected = on_connected_cb;
    conn->on_close = on_close_cb;
    conn->on_data = on_agent_request_data_cb;
    conn->on_complete = on_complete_cb;

    return am_net_connect(conn);
}

int am_agent_login(unsigned long instance_id, const char *openam,
        const char *user, const char *pass, const char *realm, am_net_options_t *options,
        char **agent_token, char **pxml, size_t *pxsz, struct am_namevalue **session_list) {
    static const char *thisfunc = "am_agent_login():";
    am_net_t conn;
    int status = AM_ERROR;
    struct request_data req_data;
    am_bool_t keepalive = options == NULL || options->keepalive;

    enum {
        login_auth_ctx = 0, login_request, login_attributes, login_session, login_policychange, login_done
    } state = login_auth_ctx;

    if (!ISVALID(realm) || !ISVALID(user) || !ISVALID(pass) || !ISVALID(openam)) {
        return AM_EINVAL;
    }

    while (state != login_done) {

        status = do_net_connect(&conn, &req_data, instance_id, openam, options);
        if (status != AM_SUCCESS) {
            AM_LOG_ERROR(instance_id, "%s error %d (%s) connecting to %s", thisfunc, status, am_strerror(status), openam);
            if (options != NULL && options->log != NULL) {
                options->log("%s error %d (%s) connecting to %s", thisfunc, status, am_strerror(status), openam);
            }
            break;
        }

        switch (state) {
            case login_auth_ctx:
                /* create a new AuthContext request (PLL endpoint) */
                status = send_authcontext_request(&conn, realm, agent_token);
                if (status != AM_SUCCESS) {
                    state = login_done;
                    break;
                }
                if (!keepalive) {
                    am_net_close(&conn);
                    close_event(&req_data.event);
                    am_free(req_data.data);
                    state = login_request;
                    break;
                }
            case login_request:
                /* send agent profile, password and module Application (PLL endpoint) */
                status = send_login_request(&conn, agent_token, user, pass);
                if (status != AM_SUCCESS) {
                    state = login_done;
                    break;
                }
                if (!keepalive) {
                    am_net_close(&conn);
                    close_event(&req_data.event);
                    am_free(req_data.data);
                    state = login_attributes;
                    break;
                }
            case login_attributes:
                /* send agent attribute request (/identity/xml/read REST endpoint);
                 * no interest in a remote profile in case of a local-only configuration
                 */
                if (options != NULL && !options->local) {
                    status = send_attribute_request(&conn, agent_token, pxml, pxsz, user, realm);
                    if (status != AM_SUCCESS) {
                        state = login_done;
                        break;
                    }
                    if (!keepalive) {
                        am_net_close(&conn);
                        close_event(&req_data.event);
                        am_free(req_data.data);
                        state = login_session;
                        break;
                    }
                } else {
                    if (!keepalive) {
                        state = login_session;
                    }
                }
            case login_session:
                /* send session request (PLL endpoint) */
                status = send_session_request(&conn, agent_token, NULL, session_list);
                if (status != AM_SUCCESS) {
                    state = login_done;
                    break;
                }
                if (!keepalive) {
                    am_net_close(&conn);
                    close_event(&req_data.event);
                    am_free(req_data.data);
                    state = login_policychange;
                    break;
                }
            case login_policychange:
                /* subscribe to a policy change notification (PLL endpoint) */
                status = send_policychange_request(&conn, agent_token);
            default:
                state = login_done;
                break;
        }
    }

    if (status != AM_SUCCESS) {
        AM_LOG_DEBUG(instance_id, "%s disconnecting", thisfunc);
        if (options != NULL && options->log != NULL) {
            options->log("%s disconnecting", thisfunc);
        }
        am_net_diconnect(&conn);
    }

    am_net_close(&conn);
    close_event(&req_data.event);
    am_free(req_data.data);

    return status;
}

int am_agent_logout(unsigned long instance_id, const char *openam, const char *token, am_net_options_t *options) {
    static const char *thisfunc = "am_agent_logout():";
    am_net_t conn;
    int status = AM_ERROR;
    size_t post_sz, post_data_sz;
    char *post = NULL, *post_data = NULL;
    struct request_data req_data;

    if (!ISVALID(token) || !ISVALID(openam)) return AM_EINVAL;

    memset(&req_data, 0, sizeof (struct request_data));
    memset(&conn, 0, sizeof (am_net_t));
    conn.options = options;
    conn.instance_id = instance_id;
    conn.url = openam;

    if (options != NULL && ISVALID(options->server_id)) {
        am_asprintf(&conn.req_headers, "Cookie: amlbcookie=%s\r\n", options->server_id);
    }

    req_data.event = create_event();
    if (req_data.event == NULL) return AM_ENOMEM;

    conn.data = &req_data;
    conn.on_connected = on_connected_cb;
    conn.on_close = on_close_cb;
    conn.on_data = on_agent_request_data_cb;
    conn.on_complete = on_complete_cb;

    if ((status = am_net_connect(&conn)) == AM_SUCCESS) {
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
                    "Connection: Close\r\n"
                    "Content-Type: text/xml; charset=UTF-8\r\n"
                    "%s"
                    "Content-Length: %d\r\n\r\n"
                    "%s", conn.uv.path, conn.uv.host, conn.uv.port,
                    NOTNULL(conn.req_headers), post_data_sz, post_data);
            if (post != NULL) {
                AM_LOG_DEBUG(instance_id, "%s sending request:\n%s", thisfunc, post);
                if (options != NULL && options->log != NULL) {
                    options->log("%s sending request:\n%s", thisfunc, post);
                }
                status = am_net_write(&conn, post, post_sz);
                free(post);
            }
            free(post_data);
        }
    } else {
        AM_LOG_ERROR(instance_id, "%s error %d (%s) connecting to %s", thisfunc, status, am_strerror(status), openam);
        if (options != NULL && options->log != NULL) {
            options->log("%s error %d (%s) connecting to %s", thisfunc, status, am_strerror(status), openam);
        }
    }

    if (status == AM_SUCCESS) {
        wait_for_event(req_data.event, 0);
    } else {
        AM_LOG_DEBUG(instance_id, "%s disconnecting", thisfunc);
        if (options != NULL && options->log != NULL) {
            options->log("%s disconnecting", thisfunc);
        }
        am_net_diconnect(&conn);
    }

    AM_LOG_DEBUG(instance_id, "%s response status code: %d", thisfunc, conn.http_status);
    if (options != NULL && options->log != NULL) {
        options->log("%s response status code: %d", thisfunc, conn.http_status);
    }

    am_net_close(&conn);
    close_event(&req_data.event);

    am_free(req_data.data);
    return status;
}

int am_agent_policy_request(unsigned long instance_id, const char *openam,
        const char *token, const char *user_token, const char *req_url,
        const char *scope, const char *cip, const char *pattr,
        am_net_options_t *options, struct am_namevalue **session_list, struct am_policy_result **policy_list) {
    static const char *thisfunc = "am_agent_policy_request():";
    am_net_t conn;
    int status = AM_ERROR;
    struct request_data req_data;
    am_bool_t keepalive = options == NULL || options->keepalive;
    char *token_ptr = (char *) token;

    enum {
        policy_session = 0, policy_request, policy_done
    } state = policy_session;

    if (!ISVALID(token) || !ISVALID(user_token) || !ISVALID(scope) ||
            !ISVALID(req_url) || !ISVALID(openam) || !ISVALID(cip)) {
        return AM_EINVAL;
    }

    while (state != policy_done) {

        status = do_net_connect(&conn, &req_data, instance_id, openam, options);
        if (status != AM_SUCCESS) {
            AM_LOG_ERROR(instance_id, "%s error %d (%s) connecting to %s", thisfunc,
                    status, am_strerror(status), openam);
            break;
        }

        switch (state) {
            case policy_session:
                /* send session request (PLL endpoint)  */
                status = send_session_request(&conn, &token_ptr, user_token, session_list);
                if (status != AM_SUCCESS) {
                    state = policy_done;
                    break;
                }

                create_cookie_header(&conn, NULL);

                if (!keepalive) {
                    am_net_close(&conn);
                    close_event(&req_data.event);
                    am_free(req_data.data);
                    state = policy_request;
                    break;
                }
            case policy_request:
                /* send policy request (PLL endpoint)  */
                status = send_policy_request(&conn, token, user_token, req_url, scope, cip,
                        pattr, policy_list);
            default:
                state = policy_done;
                break;
        }
    }

    if (status != AM_SUCCESS) {
        AM_LOG_DEBUG(instance_id, "%s disconnecting", thisfunc);
        if (options != NULL && options->log != NULL) {
            options->log("%s disconnecting", thisfunc);
        }
        am_net_diconnect(&conn);
    }

    am_net_close(&conn);
    close_event(&req_data.event);
    am_free(req_data.data);

    return status;
}

/**
 * Validate the specified URL by using HTTP HEAD request.
 */
int am_url_validate(unsigned long instance_id, const char* url, am_net_options_t *options, int* httpcode) {
    static const char* thisfunc = "am_url_validate():";
    char* get = NULL;
    am_net_t conn;
    size_t get_sz;
    int status = AM_ERROR;
    struct request_data request_data;

    AM_LOG_DEBUG(instance_id, "%s%s", thisfunc, LOGEMPTY(url));

    if (!ISVALID(url)) {
        return AM_EINVAL;
    }

    memset(&request_data, 0, sizeof (struct request_data));
    memset(&conn, 0, sizeof (am_net_t));
    conn.options = options;
    conn.instance_id = instance_id;
    conn.url = url;

    request_data.event = create_event();
    if (request_data.event == NULL) {
        return AM_ENOMEM;
    }

    conn.data = &request_data;
    conn.on_connected = on_connected_cb;
    conn.on_close = on_close_cb;
    conn.on_data = on_agent_request_data_cb;
    conn.on_complete = on_complete_cb;

    if ((status = am_net_connect(&conn)) == AM_SUCCESS) {
        get_sz = am_asprintf(&get, "HEAD %s HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "User-Agent: "MODINFO"\r\n"
                "Accept: text/plain\r\n"
                "Connection: Close\r\n\r\n",
                conn.uv.path, conn.uv.host, conn.uv.port);
        if (get != NULL) {
            AM_LOG_DEBUG(instance_id, "%s sending request:\n%s", thisfunc, get);
            if (options != NULL && options->log != NULL) {
                options->log("%s sending request:\n%s", thisfunc, get);
            }
            status = am_net_write(&conn, get, get_sz);
            free(get);
        }
    } else {
        AM_LOG_ERROR(instance_id, "%s error %d (%s) connecting to %s", thisfunc, status, am_strerror(status), url);
        if (options != NULL && options->log != NULL) {
            options->log("%s error %d (%s) connecting to %s", thisfunc, status, am_strerror(status), url);
        }
    }

    AM_LOG_DEBUG(instance_id, "%s status is set to %d", thisfunc, status);
    if (options != NULL && options->log != NULL) {
        options->log("%s status is set to %d", thisfunc, status);
    }

    if (status == AM_SUCCESS) {
        wait_for_event(request_data.event, 0);
    } else {
        AM_LOG_DEBUG(instance_id, "%s disconnecting", thisfunc);
        if (options != NULL && options->log != NULL) {
            options->log("%s disconnecting", thisfunc);
        }
        am_net_diconnect(&conn);
    }

    AM_LOG_DEBUG(instance_id, "%s response status code: %d", thisfunc, conn.http_status);
    if (options != NULL && options->log != NULL) {
        options->log("%s response status code: %d", thisfunc, conn.http_status);
    }
    if (httpcode) {
        *httpcode = conn.http_status;
    }

    am_net_close(&conn);
    close_event(&request_data.event);

    am_free(request_data.data);
    return status;
}

int am_agent_audit_request(unsigned long instance_id, const char *openam, const char *logdata, am_net_options_t *options) {
    static const char *thisfunc = "am_agent_audit_request():";
    am_net_t conn;
    int status = AM_ERROR;
    size_t post_sz, post_data_sz;
    char *post = NULL, *post_data = NULL;
    struct request_data req_data;

    if (!ISVALID(logdata) || !ISVALID(openam)) return AM_EINVAL;

    memset(&req_data, 0, sizeof (struct request_data));
    memset(&conn, 0, sizeof (am_net_t));
    conn.options = options;
    conn.instance_id = instance_id;
    conn.url = openam;

    if (options != NULL && ISVALID(options->server_id)) {
        am_asprintf(&conn.req_headers, "Cookie: amlbcookie=%s\r\n", options->server_id);
    }

    req_data.event = create_event();
    if (req_data.event == NULL) return AM_ENOMEM;

    conn.data = &req_data;
    conn.on_connected = on_connected_cb;
    conn.on_close = on_close_cb;
    conn.on_data = on_agent_request_data_cb;
    conn.on_complete = on_complete_cb;

    if ((status = am_net_connect(&conn)) == AM_SUCCESS) {
        post_data_sz = am_asprintf(&post_data,
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<RequestSet vers=\"1.0\" svcid=\"Logging\" reqid=\"0\">%s</RequestSet>",
                logdata);
        if (post_data != NULL) {
            post_sz = am_asprintf(&post, "POST %s/loggingservice HTTP/1.1\r\n"
                    "Host: %s:%d\r\n"
                    "User-Agent: "MODINFO"\r\n"
                    "Accept: text/xml\r\n"
                    "Connection: Close\r\n"
                    "Content-Type: text/xml; charset=UTF-8\r\n"
                    "%s"
                    "Content-Length: %d\r\n\r\n"
                    "%s", conn.uv.path, conn.uv.host, conn.uv.port,
                    NOTNULL(conn.req_headers), post_data_sz, post_data);
            if (post != NULL) {
                AM_LOG_DEBUG(instance_id, "%s sending request:\n%s", thisfunc, post);
                status = am_net_write(&conn, post, post_sz);
                free(post);
            }
            free(post_data);
        }
    } else {
        AM_LOG_ERROR(instance_id, "%s error %d (%s) connecting to %s", thisfunc, status, am_strerror(status), openam);
    }

    if (status == AM_SUCCESS) {
        wait_for_event(req_data.event, 0);
    } else {
        AM_LOG_DEBUG(instance_id, "%s disconnecting", thisfunc);
        am_net_diconnect(&conn);
    }

    AM_LOG_DEBUG(instance_id, "%s response status code: %d", thisfunc, conn.http_status);

    am_net_close(&conn);
    close_event(&req_data.event);

    am_free(req_data.data);
    return status;
}
