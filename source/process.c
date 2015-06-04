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
#include "utility.h"
#include "list.h"
#include "net_client.h"

#define POST_PRESERVE_URI           "/dummypost/ampostpreserve"
#define COMPOSITE_ADVICE_KEY        "sunamcompositeadvice"
#define AUDIT_ALLOW_USER_MESSAGE    "user %s (%s) was allowed access to %s"
#define AUDIT_DENY_USER_MESSAGE     "user %s (%s) was denied access to %s"

enum {
    AM_SESSION_ATTRIBUTE = 0,
    AM_POLICY_ATTRIBUTE,
    AM_RESPONSE_ATTRIBUTE,
};

enum {
    AM_SCOPE_SELF = 0,
    AM_SCOPE_SUBTREE,
    AM_SCOPE_RESPONSE_ATTRIBUTE_ONLY
};

typedef enum {
    ok = 0, fail, retry, quit
} am_return_t;

typedef am_return_t(*am_state_func_t)(am_request_t *);

typedef enum {
    setup_request_data_c,
    validate_url_c,
    handle_notification_c,
    validate_token_c,
    validate_fqdn_access_c,
    handle_not_enforced_c,
    validate_policy_c,
    handle_exit_c
} am_state_t;

struct transition {
    am_state_t src_state;
    am_return_t ret_code;
    am_state_t dst_state;
};

static struct transition state_transitions[] = {
    {setup_request_data_c, ok, validate_url_c},
    {setup_request_data_c, fail, handle_exit_c},

    {validate_url_c, ok, handle_notification_c},
    {validate_url_c, fail, handle_exit_c},

    {handle_notification_c, ok, handle_exit_c},
    {handle_notification_c, fail, validate_fqdn_access_c},

    {validate_fqdn_access_c, ok, validate_token_c},
    {validate_fqdn_access_c, fail, handle_exit_c},

    {handle_not_enforced_c, ok, validate_policy_c},
    {handle_not_enforced_c, quit, handle_exit_c},

    {validate_token_c, ok, handle_not_enforced_c},
    {validate_token_c, fail, handle_exit_c},

    {validate_policy_c, retry, validate_policy_c},
    {validate_policy_c, ok, handle_exit_c}
};

#define EXIT_STATE handle_exit_c
#define ENTRY_STATE setup_request_data_c

static am_state_t lookup_transition(am_state_t c, am_return_t r) {
    int i, s = sizeof (state_transitions) / sizeof (state_transitions[0]);
    for (i = 0; i < s; i++) {
        if (state_transitions[i].src_state == c
                && state_transitions[i].ret_code == r) {
            return state_transitions[i].dst_state;
        }
    }
    return EXIT_STATE;
}

static am_bool_t is_json_request(am_request_t *request) {
    int i, compare_status;
    if (request->conf->json_url_map_sz <= 0) {
        return AM_FALSE;
    }
    for (i = 0; i < request->conf->json_url_map_sz; i++) {
        am_config_map_t *m = &request->conf->json_url_map[i];
        if (!ISVALID(m->value)) continue;

        compare_status = policy_compare_url(request, m->value, request->overridden_url);
        if (compare_status == AM_EXACT_MATCH || compare_status == AM_EXACT_PATTERN_MATCH) {
            return AM_TRUE;
        }

        /*compare_status = match(request->instance_id, request->overridden_url, m->value);
        if (compare_status == AM_SUCCESS) {
            return AM_TRUE;
        }*/
    }
    return AM_FALSE;
}

static am_return_t setup_request_data(am_request_t *r) {
    static const char *thisfunc = "setup_request_data():";
    am_status_t status = AM_ERROR, status_token_query = AM_ERROR;
    char *s, *v;
    struct url u, au;

    if (r == NULL || r->ctx == NULL || r->conf == NULL) {
        return fail;
    }

    AM_LOG_DEBUG(r->instance_id, "%s", thisfunc);

    if (r->am_get_request_url_f == NULL) {
        AM_LOG_ERROR(r->instance_id, "%s could not get request url", thisfunc);
        return fail;
    }

    if (!ISVALID(r->client_ip)) {
        AM_LOG_ERROR(r->instance_id, "%s could not get client ip address", thisfunc);
        return fail;
    }

    s = strstr(r->client_ip, AM_COMMA_CHAR);
    /* if the client ip header contains more than one value, use only the first one */
    v = s != NULL ? strndup(r->client_ip, s - r->client_ip) : strdup(r->client_ip);
    if (v == NULL) {
        AM_LOG_ERROR(r->instance_id, "%s memory allocation failure", thisfunc);
        r->status = AM_ENOMEM;
        return fail;
    }
    r->client_ip = v;

    AM_LOG_DEBUG(r->instance_id, "%s client ip: %s", thisfunc, LOGEMPTY(r->client_ip));

    //TODO: client_host is not used in a policy call?
    if (ISVALID(r->client_host)) {
        s = strstr(r->client_host, AM_COMMA_CHAR);
        /* if the client host header contains more than one value, use only the first one */
        v = s != NULL ? strndup(r->client_host, s - r->client_host) : strdup(r->client_host);
        if (v != NULL) {
            s = strstr(v, ":");
            /* if client_host contains the port number, remove it */
            if (s != NULL) *s = 0;
        }
        r->client_host = v;
    }
    if (r->conf->resolve_client_host && ISVALID(r->client_ip)) {
        int errcode;
        struct addrinfo hints, *res = NULL;
        SOCKLEN_T slen;
        char client_host[NI_MAXHOST + 1];
        memset(&hints, 0, sizeof (hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        errcode = getaddrinfo(r->client_ip, NULL, &hints, &res);
        if (errcode == 0) {
            while (res) {
                slen = res->ai_family == AF_INET ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
                errcode = getnameinfo((struct sockaddr *) res->ai_addr, slen,
                        client_host, sizeof (client_host), NULL, 0, NI_NAMEREQD);
                if (errcode == 0) {
                    am_free(r->client_host);
                    r->client_host = strdup(client_host);
                    break;
                }
                res = res->ai_next;
            }
            if (res != NULL) freeaddrinfo(res);
        }
    }
    AM_LOG_DEBUG(r->instance_id, "%s client hostname: %s", thisfunc, LOGEMPTY(r->client_host));

    status = r->am_get_request_url_f(r);
    if (status != AM_SUCCESS) {
        AM_LOG_ERROR(r->instance_id, "%s failed to get request url", thisfunc);
        return fail;
    }
    if (parse_url(r->orig_url, &r->url)) {
        AM_LOG_ERROR(r->instance_id, "%s failed to normalize request url: %s (%s)",
                thisfunc, r->orig_url, am_strerror(r->url.error));
        return fail;
    }

    am_asprintf(&r->normalized_url, "%s://%s:%d%s%s", r->url.proto, r->url.host,
            r->url.port, r->url.path, r->url.query);
    if (r->normalized_url == NULL) {
        AM_LOG_ERROR(r->instance_id, "%s memory allocation failure", thisfunc);
        r->status = AM_ENOMEM;
        return fail;
    }

    /*re-format normalized request url depending on override parameter values*/
    memcpy(&u, &r->url, sizeof (struct url));
    if (parse_url(r->conf->agenturi, &au) == 0) {
        if (r->conf->override_protocol) {
            strncpy(u.proto, au.proto, sizeof (u.proto) - 1);
        }
        if (r->conf->override_host) {
            strncpy(u.host, au.host, sizeof (u.host) - 1);
        }
        if (r->conf->override_port) {
            u.port = au.port;
        }
    } else {
        AM_LOG_WARNING(r->instance_id, "%s failed to parse agenturi.prefix %s",
                thisfunc, LOGEMPTY(r->conf->agenturi));
    }

    am_asprintf(&r->overridden_url, "%s://%s:%d%s%s", u.proto, u.host, u.port, u.path, u.query);
    if (r->overridden_url == NULL) {
        AM_LOG_ERROR(r->instance_id, "%s memory allocation failure", thisfunc);
        r->status = AM_ENOMEM;
        return fail;
    }

    /* check if this request url (normalized) matches any of 
     * org.forgerock.agents.config.json.url[] configuration parameter values
     */
    r->is_json_url = is_json_request(r);

    /* do an early check for a session token in query parameters,
     * remove if found (url evaluation later on 
     * should not contain session token value; aka cookie-less mode,
     * applies also to LARES sent as GET parameter)
     */
    status_token_query = get_token_from_url(r);
    if (status_token_query == AM_SUCCESS) {
        AM_LOG_DEBUG(r->instance_id, "%s found session token '%s' in query parameters", thisfunc, r->token);
    } else {
        AM_LOG_DEBUG(r->instance_id, "%s no token in query parameters", thisfunc);
    }

    AM_LOG_DEBUG(r->instance_id, "%s method: %s, original url: %s, normalized:\n"
            "proto: %s\nhost: %s\nport: %d\npath: %s\nquery: %s\ncomplete: %s\noverridden: %s", thisfunc,
            am_method_num_to_str(r->method), r->orig_url,
            r->url.proto, r->url.host, r->url.port, r->url.path, r->url.query, r->normalized_url,
            r->overridden_url);

    if (r->method == AM_REQUEST_POST && !ISVALID(r->content_type)) {
        AM_LOG_ERROR(r->instance_id, "%s HTTP POST requires a valid Content-Type header value", thisfunc);
        return fail;
    }

    r->status = status;
    return ok;
}

static am_return_t validate_url(am_request_t *r) {
    static const char *thisfunc = "validate_url():";

    AM_LOG_DEBUG(r->instance_id, "%s", thisfunc);

    if (ISVALID(r->conf->url_check_regex)) {
        int s = match(r->instance_id, r->normalized_url, r->conf->url_check_regex);
        if (s != 0) {
            AM_LOG_ERROR(r->instance_id, "%s request url validation failed", thisfunc);
            r->status = AM_FORBIDDEN;
            return fail;
        }
        AM_LOG_DEBUG(r->instance_id, "%s request url validation succeeded", thisfunc);
        return ok;
    }
    AM_LOG_DEBUG(r->instance_id, "%s request url validation feature is not enabled", thisfunc);
    return ok;
}

static am_return_t handle_notification(am_request_t *r) {
    static const char *thisfunc = "handle_notification():";
    am_return_t status = fail;

    AM_LOG_DEBUG(r->instance_id, "%s", thisfunc);

    /*check if notifications are enabled*/
    if (r->method == AM_REQUEST_POST && r->conf->notif_enable && ISVALID(r->conf->notif_url)) {
        struct notification_worker_data *wd;
        /* is override.notification.url set? */
        const char *url = r->conf->override_notif_url ? r->overridden_url : r->normalized_url;
        //TODO: asp.net eurl.axd/xyz ?
        int compare_status = r->conf->url_eval_case_ignore ?
                strcasecmp(url, r->conf->notif_url) : strcmp(url, r->conf->notif_url);
        /*int compare_status = r->conf->url_eval_case_ignore == AM_TRUE ?
                (stristr((char *) url, r->conf->notif_url) != NULL ? 0 : 1) :
                (strstr(url, r->conf->notif_url) != NULL ? 0 : 1);*/
        if (compare_status != 0) {
            AM_LOG_DEBUG(r->instance_id, "%s %s is not an agent notification url %s", thisfunc, url, r->conf->notif_url);
            return status;
        }

        wd = malloc(sizeof (struct notification_worker_data));

        AM_LOG_DEBUG(r->instance_id, "%s %s is an agent notification url", thisfunc, url);

        /* read post data (blocking) */
        if (r->am_get_post_data_f != NULL) {
            r->am_get_post_data_f(r);
        }
        /* set up notification_worker argument list */
        if (wd != NULL) {
            wd->instance_id = r->instance_id;
            /* original r->post_data inside a worker might not be available already */
            wd->post_data = r->post_data != NULL ? strdup(r->post_data) : NULL;
            wd->post_data_sz = r->post_data_sz;
        }
        status = ok;
        /* process notification message */
        if (am_worker_dispatch(notification_worker, wd) != 0) {
            am_free(wd->post_data);
            free(wd);
            r->status = AM_ERROR;
            AM_LOG_WARNING(r->instance_id, "%s failed to dispatch notification worker", thisfunc);
            return status;
        }
        if (r->am_set_custom_response_f != NULL) {
            /* OpenAM needs 'OK' message in the body with a successful notification */
            r->am_set_custom_response_f(r, "OK", "text/html");
        }
        r->status = AM_NOTIFICATION_DONE;
    }
    return status;
}

static am_return_t validate_fqdn_access(am_request_t *r) {
    static const char *thisfunc = "validate_fqdn_access():";
    int i;
    am_return_t status = ok;

    AM_LOG_DEBUG(r->instance_id, "%s", thisfunc);

    if (!r->conf->fqdn_check_enable) {
        AM_LOG_DEBUG(r->instance_id, "%s feature is not enabled", thisfunc);
        return ok;
    }

    if (!ISVALID(r->conf->fqdn_default)) {
        AM_LOG_WARNING(r->instance_id,
                "%s failed - default fqdn value is not set", thisfunc);
        return fail;
    }

    status = fail;

    /* check if its the default fqdn */
    if (r->conf->url_eval_case_ignore) {
        status = (strcasecmp(r->url.host, r->conf->fqdn_default) == 0) ? ok : fail;
    } else {
        status = (strcmp(r->url.host, r->conf->fqdn_default) == 0) ? ok : fail;
    }

    if (status == ok) {
        r->client_fqdn = r->conf->fqdn_default;
    }

    /* if not, check if its another valid fqdn */
    if (status != ok && r->conf->fqdn_map_sz > 0) {
        for (i = 0; i < r->conf->fqdn_map_sz; i++) {
            am_config_map_t *m = &r->conf->fqdn_map[i];
            AM_LOG_DEBUG(r->instance_id, "%s comparing a valid host name %s with %s",
                    thisfunc, LOGEMPTY(m->value), r->url.host);
            if (r->conf->url_eval_case_ignore) {
                status = (strcasecmp(r->url.host, NOTNULL(m->value)) == 0) ? ok : fail;
            } else {
                status = (strcmp(r->url.host, NOTNULL(m->value)) == 0) ? ok : fail;
            }

            /* still no match? look into a key value ('invalid') */
            if (status != ok) {
                AM_LOG_DEBUG(r->instance_id,
                        "%s comparing an invalid host name %s with %s",
                        thisfunc, LOGEMPTY(m->name), r->url.host);
                if (r->conf->url_eval_case_ignore) {
                    status = (strcasecmp(r->url.host, NOTNULL(m->name)) == 0) ? ok : fail;
                } else {
                    status = (strcmp(r->url.host, NOTNULL(m->name)) == 0) ? ok : fail;
                }
            }

            if (status == ok) {
                r->client_fqdn = m->value;
                break;
            }
        }
    }

    if (status == ok) {
        AM_LOG_DEBUG(r->instance_id, "%s host name %s is valid (maps to %s)",
                thisfunc, r->url.host, LOGEMPTY(r->client_fqdn));
        return ok;
    }

    AM_LOG_WARNING(r->instance_id,
            "%s host name %s is not valid (no corresponding map value) ",
            thisfunc, r->url.host);
    r->status = AM_INVALID_FQDN_ACCESS;

    return status;
}

static am_bool_t url_matches_pattern(am_request_t *r, const char *pattern,
        const char *url, am_bool_t regex_enable) {
    if (regex_enable) {
        return match(r->instance_id, url, pattern) == AM_SUCCESS;
    } else {
        return policy_compare_url(r, pattern, url) != AM_NO_MATCH;
    }
}

static am_return_t handle_not_enforced(am_request_t *r) {
    static const char *thisfunc = "handle_not_enforced():";
    int i;
    const char *url = r->normalized_url;
    char *pdp_path = NULL;

    AM_LOG_DEBUG(r->instance_id, "%s", thisfunc);

    /* post preservation url is not enforced 
     * (will use com.forgerock.agents.config.pdpuri.prefix value if set) 
     */
    am_asprintf(&pdp_path, "%s%s%s",
            ISVALID(r->conf->pdp_uri_prefix) && r->conf->pdp_uri_prefix[0] != '/' ? "/" : "",
            NOTNULL(r->conf->pdp_uri_prefix), POST_PRESERVE_URI);
    if (ISVALID(pdp_path) && ISVALID(r->url.query) && strcmp(r->url.path, pdp_path) == 0) {
        const char *error = NULL;
        int erroroffset;
        /* all other query parameters, apart from the pdp key, are removed. 
         * pdp key format: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x 
         * generated by uuid() utility method
         */
        size_t slen = strlen(r->url.query);
        pcre *x = pcre_compile(".+([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}).*",
                0, &error, &erroroffset, NULL);
        if (x != NULL) {
            char *key = match_group(x, 1, r->url.query, &slen);
            if (key != NULL) {
                strncpy(r->url.query, "?", sizeof (r->url.query) - 1);
                strcat(r->url.query, key);
                free(key);
            }
            pcre_free(x);
        }

        AM_LOG_DEBUG(r->instance_id, "%s post preserve url is not enforced", thisfunc);
        r->is_dummypost_url = r->not_enforced = AM_TRUE;
        r->status = AM_SUCCESS;
        free(pdp_path);
        return ok;
    }
    am_free(pdp_path);

    /* check if the request url (normalized) is in an application logout url list */
    if (r->conf->logout_map_sz > 0) {
        for (i = 0; i < r->conf->logout_map_sz; i++) {
            am_config_map_t *m = &r->conf->logout_map[i];
            if (url_matches_pattern(r, m->value, url, r->conf->logout_regex_enable)) {
                AM_LOG_DEBUG(r->instance_id, "%s %s is an application logout url (not enforced)", thisfunc, url);
                r->not_enforced = r->is_logout_url = AM_TRUE;
                if (!r->conf->not_enforced_fetch_attr) {
                    r->status = AM_SUCCESS;
                    return quit;
                }
                return ok;
            }
        }
    } else {
        AM_LOG_DEBUG(r->instance_id, "%s application logout url feature is not enabled", thisfunc);
    }

    /* access denied url is not enforced */
    if (ISVALID(r->conf->access_denied_url)) {
        int compare_status = r->conf->url_eval_case_ignore ?
                strcasecmp(url, r->conf->access_denied_url) : strcmp(url, r->conf->access_denied_url);
        if (compare_status == 0) {
            r->not_enforced = AM_TRUE;
            if (!r->conf->not_enforced_fetch_attr) {
                r->status = AM_SUCCESS;
                return quit;
            }
            return ok;
        }
    }

    r->not_enforced = AM_FALSE;

    /* see if the client ip is in the not enforced client ip list */
    if (r->conf->not_enforced_ip_map_sz > 0) {
        for (i = 0; i < r->conf->not_enforced_ip_map_sz; i++) {
            am_config_map_t *m = &r->conf->not_enforced_ip_map[i];
            char *p = strstr(m->name, AM_COMMA_CHAR);
            if (p == NULL) {
                const char *l[1] = {m->value};
                if (ip_address_match(r->client_ip, l, 1, r->instance_id) == AM_SUCCESS) {
                    r->not_enforced = AM_TRUE;
                    if (!r->conf->not_enforced_fetch_attr) {
                        r->status = AM_SUCCESS;
                        return quit;
                    }
                    return ok;
                }
                AM_LOG_DEBUG(r->instance_id, "%s client ip address %s does not match %s",
                        thisfunc, r->client_ip, LOGEMPTY(m->value));
            } else {
                char *pv = strndup(m->name, p - m->name);
                if (pv != NULL) {
                    char mtn = am_method_str_to_num(pv);
                    free(pv);
                    if (r->method == mtn) {
                        const char *l[1] = {m->value};
                        if (ip_address_match(r->client_ip, l, 1, r->instance_id) == AM_SUCCESS) {
                            r->not_enforced = AM_TRUE;
                            if (!r->conf->not_enforced_fetch_attr) {
                                r->status = AM_SUCCESS;
                                return quit;
                            }
                            return ok;
                        }
                        AM_LOG_DEBUG(r->instance_id, "%s client ip address %s does not match %s (%s)",
                                thisfunc, r->client_ip, LOGEMPTY(m->value), am_method_num_to_str(mtn));
                    }
                }
            }
        }
    } else {
        AM_LOG_DEBUG(r->instance_id, "%s not enforced client ip validation feature is not enabled", thisfunc);
    }

    AM_LOG_DEBUG(r->instance_id, "%s validating %s", thisfunc, url);

    /* check the request url (normalized) is in not enforced url list */
    if (r->conf->not_enforced_map_sz > 0) {
        int compare_status = 0;
        for (i = 0; i < r->conf->not_enforced_map_sz; i++) {
            am_config_map_t *m = &r->conf->not_enforced_map[i];
            if (ISVALID(m->value)) {
                char *p = strstr(m->name, AM_COMMA_CHAR);
                AM_LOG_DEBUG(r->instance_id, "%s trying not enforced pattern %s", thisfunc, m->value);
                if (p == NULL) {
                    /* regular [0]=not-enforced-url option */
                    compare_status += url_matches_pattern(r, m->value, url, r->conf->not_enforced_regex_enable);
                } else {
                    /* method-extended [GET,0]=not-enforced-url option */
                    char *pv = strndup(m->name, p - m->name);
                    if (pv != NULL) {
                        char mtn = am_method_str_to_num(pv);
                        free(pv);
                        if (r->method != mtn) continue;
                        compare_status += url_matches_pattern(r, m->value, url, r->conf->not_enforced_regex_enable);
                    }
                }
            }
        }

        compare_status = compare_status > 0;

        if (r->conf->not_enforced_invert) {
            AM_LOG_DEBUG(r->instance_id, "%s not enforced list is inverted, "
                    "only not enforced list of urls will be enforced", thisfunc);
            compare_status = !compare_status;
        }
        if (compare_status) {
            AM_LOG_DEBUG(r->instance_id, "%s %s is not enforced", thisfunc, url);
            r->not_enforced = AM_TRUE;
            if (!r->conf->not_enforced_fetch_attr) {
                r->status = AM_SUCCESS;
                return quit;
            }
            return ok;
        }

    } else {
        AM_LOG_DEBUG(r->instance_id, "%s not enforced url validation feature is not enabled", thisfunc);
    }

    /* check the request url (normalized) is in not enforced url list (extended version) */
    if (r->conf->not_enforced_ext_map_sz > 0 && ISVALID(r->client_ip)) {
        for (i = 0; i < r->conf->not_enforced_ext_map_sz; i++) {
            char *p, *v, *t, *is, *us, found = AM_FALSE;
            am_config_map_t *m = &r->conf->not_enforced_ext_map[i];
            if (!ISVALID(m->value)) continue;
            p = strstr(m->value, AM_PIPE_CHAR); /* 10.1.1.0/24 10.1.2.1-10.1.2.7|url1 url2 */
            if (p == NULL) continue;
            is = strndup(m->value, p - m->value);
            us = strdup(p + 1);
            if (is == NULL || us == NULL) {
                AM_FREE(is, us);
                continue;
            }
            for ((v = strtok_r(is, AM_SPACE_CHAR, &t)); v; (v = strtok_r(NULL, AM_SPACE_CHAR, &t))) {
                const char *vlist[1] = {v};
                if (ip_address_match(r->client_ip, vlist, 1, r->instance_id) == AM_SUCCESS) {
                    found = AM_TRUE;
                    break;
                }
            }
            if (found) {
                found = AM_FALSE;
                for ((v = strtok_r(us, AM_SPACE_CHAR, &t)); v; (v = strtok_r(NULL, AM_SPACE_CHAR, &t))) {
                    if (url_matches_pattern(r, v, url, r->conf->not_enforced_ext_regex_enable)) {
                        found = AM_TRUE;
                        break;
                    }
                }
            }
            AM_FREE(is, us);
            if (found) {
                AM_LOG_DEBUG(r->instance_id, "%s %s is not enforced", thisfunc, url);
                r->not_enforced = AM_TRUE;
                if (!r->conf->not_enforced_fetch_attr) {
                    r->status = AM_SUCCESS;
                    return quit;
                }
                return ok;
            }
        }
    } else {
        AM_LOG_DEBUG(r->instance_id, "%s extended not enforced url validation feature is not enabled", thisfunc);
    }

    AM_LOG_DEBUG(r->instance_id, "%s %s is enforced", thisfunc, url);
    return ok;
}

static am_return_t validate_token(am_request_t *r) {
    static const char *thisfunc = "validate_token():";
    am_return_t return_status = ok; /* fail only on non-recoverable error (will quit processing) */
    am_status_t status = AM_ERROR;

    AM_LOG_DEBUG(r->instance_id, "%s", thisfunc);

    if (r->conf->cdsso_enable && r->method == AM_REQUEST_POST) {
        char *token_in_post = NULL;

        /* read post data (blocking) */
        if (r->am_get_post_data_f != NULL) {
            r->am_get_post_data_f(r);
            status = AM_SUCCESS;
        }

        if (status == AM_SUCCESS && ISVALID(r->post_data)) {

            /* if this is a LARES/SAML post, read a token from SAML assertion */
            if (r->post_data_sz > 5 && memcmp(r->post_data, "LARES=", 6) == 0) {
                char *lares = url_decode(r->post_data + 6);
                size_t clear_sz = lares != NULL ? strlen(lares) : 0;
                char *clear = base64_decode(lares, &clear_sz);
                am_free(lares);

                status = AM_NOT_FOUND;
                if (clear != NULL) {
                    struct am_namevalue *e, *t, *session_list;
                    session_list = am_parse_session_saml(r->instance_id, clear, clear_sz);

                    AM_LIST_FOR_EACH(session_list, e, t) {
                        if (strcmp(e->n, "sid") == 0 && ISVALID(e->v)) {
                            token_in_post = strdup(e->v);
                            r->token_in_post = AM_TRUE;

                            if (!r->is_dummypost_url && r->am_set_method_f != NULL) {
                                /* in case its just a LARES post and post was not to dummypost-url,
                                 * change request method to GET
                                 */
                                r->method = AM_REQUEST_GET;
                                r->am_set_method_f(r);
                            }

                            status = AM_SUCCESS;
                            break;
                        }
                    }
                    delete_am_namevalue_list(&session_list);
                    free(clear);
                }
            } else if (r->post_data_sz > 0) {
                /* not a LARES/SAML post, preserve original post data for a replay in the agent(filter) */
                if (r->am_set_post_data_f != NULL) {
                    r->am_set_post_data_f(r);
                }
                status = AM_NOT_FOUND;
            }
        }

        /* token found in LARES/SAML post supersedes one found earlier in a query parameters */
        if (ISVALID(token_in_post)) {
            am_free(r->token);
            r->token = token_in_post;
        }
    }

    if (ISVALID(r->token)) {
        /*token is either found in a query parameters or LARES/SAML post above already*/
        status = AM_SUCCESS;
    }

    if (status != AM_SUCCESS) {
        /* finally, see if a token is in Cookie-s */
        status = get_cookie_value(r, ";", r->conf->cookie_name,
                r->cookies, &r->token);
        if (status != AM_SUCCESS && status != AM_NOT_FOUND) {
            AM_LOG_ERROR(r->instance_id, "%s error while getting sso token "
                    "from a cookie header: %s", thisfunc, am_strerror(status));
            return_status = fail;
        } else if (status == AM_SUCCESS && !ISVALID(r->token)) {
            status = AM_NOT_FOUND;
        }
    }

    AM_LOG_DEBUG(r->instance_id, "%s sso token: %s, status: %s", thisfunc,
            LOGEMPTY(r->token), am_strerror(r->status));

    /* get site/server info */
    if (status == AM_SUCCESS && ISVALID(r->token)) {
        int decode_status = am_session_decode(r);
        if (decode_status == AM_SUCCESS && r->si.error == AM_SUCCESS) {
            AM_LOG_DEBUG(r->instance_id, "%s sso token SI: %s, S1: %s", thisfunc,
                    LOGEMPTY(r->si.si), LOGEMPTY(r->si.s1));
        }
    }

    r->status = status;
    return return_status;
}

static char *create_profile_attribute_request(am_request_t *r) {
    int i;
    char *val = NULL;
    for (i = 0; i < r->conf->profile_attr_map_sz; i++) {
        am_config_map_t *v = &r->conf->profile_attr_map[i];
        am_asprintf(&val, "%s<Attribute name=\"%s\"/>", val == NULL ? "" : val, v->name);
    }
    return val;
}

/**
 * Fetch an attribute value from a cached attribute list (read either from a shared cache
 * or directly from a server 
 */
static const char *get_attr_value(am_request_t *r, const char *name, int mask) {
    static const char *thisfunc = "get_attr_value():";
    struct am_namevalue *e, *t;
    if (r == NULL || !ISVALID(name)) return NULL;
    switch (mask) {
        case AM_SESSION_ATTRIBUTE:
        {

            /* session attribute search */
            AM_LIST_FOR_EACH(r->sattr, e, t) {
                if (strcmp(e->n, name) == 0) {
                    return e->v;
                }
            }
        }
            break;
        case AM_RESPONSE_ATTRIBUTE:
        {

            /* policy response attribute search */
            AM_LIST_FOR_EACH(r->response_attributes, e, t) {
                if (strcmp(e->n, name) == 0) {
                    return e->v;
                }
            }
        }
            break;
        case AM_POLICY_ATTRIBUTE:
        {

            /* policy response decision-attribute search (profile attribute)*/
            AM_LIST_FOR_EACH(r->response_decisions, e, t) {
                if (strcmp(e->n, name) == 0) {
                    return e->v;
                }
            }
        }
            break;
        default:
            AM_LOG_DEBUG(r->instance_id, "%s unknown mask value (%d)", thisfunc, mask);
            break;
    }
    return NULL;
}

#define MAX_VALIDATE_POLICY_RETRY 3

static am_return_t validate_policy(am_request_t *r) {
    static const char *thisfunc = "validate_policy():";
    struct am_policy_result *e, *t, *policy_cache = NULL;
    struct am_namevalue *session_cache = NULL;
    char is_valid = AM_FALSE, remote = AM_FALSE;
    int status = AM_ERROR, policy_status = AM_NO_MATCH, entry_status = r->status;
    time_t cache_ts = 0;

    char *pattrs = NULL;
    const char *url = r->overridden_url;
    int scope = r->conf->policy_scope_subtree;

    AM_LOG_DEBUG(r->instance_id, "%s (entry status: %s)", thisfunc, am_strerror(r->status));

    if (r->not_enforced && (r->conf->not_enforced_fetch_attr || r->is_dummypost_url)) {
        if (!ISVALID(r->token)) {
            /* in case request url is not enforced and attribute fetch is enabled
             * but there is no session token - quit processing w/o policy evaluation.
             * 
             * headers/cookies will be cleared in handle_exit->set_user_attributes
             */
            r->status = AM_SUCCESS;
            return ok;
        }
        scope = AM_SCOPE_RESPONSE_ATTRIBUTE_ONLY;
    }

    if (r->status == AM_NOT_FOUND) {
        r->status = AM_INVALID_SESSION;
        return ok;
    }

    if (r->retry >= MAX_VALIDATE_POLICY_RETRY) {
        AM_LOG_ERROR(r->instance_id,
                "%s validate policy for '%s' failed (max %d retries exhausted)",
                thisfunc, url, MAX_VALIDATE_POLICY_RETRY);
        /*status = AM_RETRY_ERROR;*/
        r->response_attributes = NULL;
        r->response_decisions = NULL;
        r->policy_advice = NULL;
        r->pattr = NULL;
        r->sattr = NULL;
        r->status = AM_ACCESS_DENIED;
        return ok;
    }

    /* look for an entry in a session cache */
    status = am_get_session_policy_cache_entry(r, r->token,
            &policy_cache, &session_cache, &cache_ts);

    if ((status == AM_SUCCESS && cache_ts > 0) || status != AM_SUCCESS) {
        struct am_policy_result *policy_cache_new = NULL;
        struct am_namevalue *session_cache_new = NULL;
        struct am_ssl_options info;
        const char *service_url = get_valid_openam_url(r);
        int max_retry = 3;
        unsigned int retry = 3, retry_wait = 2; //TODO: conf values

        am_net_set_ssl_options(r->conf, &info);

        /* entry is found, but was not valid, or nothing was found,
         * do a policy+session call in either way
         **/
        pattrs = create_profile_attribute_request(r);
        max_retry++;
        do {
            policy_cache_new = NULL;
            session_cache_new = NULL;
            status = am_agent_policy_request(r->instance_id, service_url,
                    r->conf->token, r->token,
                    url,
                    r->conf->notif_url, am_scope_to_str(scope), r->client_ip, pattrs,
                    &info,
                    &session_cache_new,
                    &policy_cache_new);
            if (status == AM_SUCCESS && session_cache_new != NULL && policy_cache_new != NULL) {
                remote = AM_TRUE;
                break;
            }
            delete_am_policy_result_list(&policy_cache_new);
            delete_am_namevalue_list(&session_cache_new);
            AM_LOG_WARNING(r->instance_id, "%s retry %d (remote session/policy call failure: %s)",
                    thisfunc, (retry - max_retry) + 1, am_strerror(status));

            if (status == AM_INVALID_SESSION) {
                am_remove_cache_entry(r->instance_id, r->token);
                break;
            }
            if (status == AM_INVALID_AGENT_SESSION) {
                am_remove_cache_entry(r->instance_id, r->conf->token);
                break;
            }

            sleep(retry_wait);
        } while (--max_retry > 0);

        if (max_retry == 0) {
            AM_LOG_ERROR(r->instance_id,
                    "%s remote session/policy call to validate '%s' failed (max %d retries exhausted)",
                    thisfunc, url, retry);
            status = AM_RETRY_ERROR;
        }

        am_free(pattrs);
        if (status == AM_SUCCESS) {

            /* discard old entries */
            delete_am_policy_result_list(&policy_cache);
            delete_am_namevalue_list(&session_cache);

            status = am_add_session_policy_cache_entry(r, r->token,
                    policy_cache_new, session_cache_new);

            policy_cache = policy_cache_new;
            session_cache = session_cache_new;
            is_valid = AM_TRUE;
        }

        if (status != AM_SUCCESS && cache_ts > 0) {
            /* re-use earlier cached session/policy data */
            //TODO: skew? max?
            //AM_LOG_WARNING(instance_id, "%s retry %d (remote session/policy call failure)",
            //        thisfunc, (retry - max_retry) + 1);
            is_valid = AM_TRUE;
        }

    } else {
        is_valid = AM_TRUE;
    }

    if (status == AM_INVALID_AGENT_SESSION) {
        am_config_t *boot = NULL;
        int rv = AM_ERROR;
        AM_LOG_WARNING(r->instance_id,
                "%s agent session is invalid, trying to fetch new configuration/session",
                thisfunc);
        /*delete all cached data for this agent instance*/
        remove_agent_instance_byname(r->conf->user);
        /*fetch and update with the new configuration*/
        rv = am_get_agent_config(r->instance_id, r->conf->config, &boot);
        if (rv == AM_SUCCESS && boot != NULL) {
            am_config_free(&r->conf);
            AM_LOG_DEBUG(r->instance_id, "%s agent configuration/session updated",
                    thisfunc);
            r->conf = boot; /*set new agent configuration for this request*/
            r->response_attributes = NULL;
            r->response_decisions = NULL;
            r->policy_advice = NULL;
            delete_am_policy_result_list(&policy_cache);
            r->pattr = NULL;
            delete_am_namevalue_list(&session_cache);
            r->sattr = NULL;
            r->status = entry_status;
            r->retry++;
            return retry;
        }
        AM_LOG_ERROR(r->instance_id, "%s failed to fetch new agent configuration/session",
                thisfunc);
    }

    if (status == AM_INVALID_SESSION) {
        r->response_attributes = NULL;
        r->response_decisions = NULL;
        r->policy_advice = NULL;
        r->status = AM_INVALID_SESSION;
        return ok;
    }

    if (session_cache != NULL && is_valid) {
        r->sattr = session_cache;
    }
    if (policy_cache != NULL && is_valid) {
        r->pattr = policy_cache;
    }

    if (r->sattr != NULL && r->pattr != NULL) {

        if (r->conf->client_ip_validate) {
            /*check if client ip read from the environment matches token ip found in the session*/
            const char *remote_ip = get_attr_value(r, "Host", AM_SESSION_ATTRIBUTE);
            if (!ISVALID(r->client_ip) || !ISVALID(remote_ip) || strcmp(remote_ip, r->client_ip) != 0) {
                r->status = AM_ACCESS_DENIED;
                AM_LOG_WARNING(r->instance_id,
                        "%s decision: deny, reason: client ip %s does not match sso token ip %s",
                        thisfunc, LOGEMPTY(r->client_ip), LOGEMPTY(remote_ip));
                return ok;
            }
        }

        AM_LIST_FOR_EACH(r->pattr, e, t) {//TODO: work on loop in 2 threads (split loop in 2; search&match in each thread)
            if (e->scope == scope) {
                const char *pattern = e->resource;
                policy_status = policy_compare_url(r, pattern, url);

                AM_LOG_DEBUG(r->instance_id, "%s pattern: %s, resource: %s, status: %s", thisfunc,
                        pattern, url, am_policy_strerror(policy_status));

                if (remote) {
                    /*in case its a fresh policy response, store it in a cache (resource name only)*/
                    am_add_policy_cache_entry(r, pattern, 300); /*5 minutes*/
                } else {
                    int rv = am_get_policy_cache_entry(r, pattern, e->created);
                    AM_LOG_DEBUG(r->instance_id, "%s pattern: %s, cache status: %s", thisfunc,
                            pattern, am_strerror(rv));
                    if (rv != AM_SUCCESS) {
                        /* policy cache (resource) entry might be removed or updated by a notification
                         * redo validate_policy in either case
                         */
                        r->response_attributes = NULL;
                        r->response_decisions = NULL;
                        r->policy_advice = NULL;

                        delete_am_policy_result_list(&policy_cache);
                        r->pattr = NULL;
                        delete_am_namevalue_list(&session_cache);
                        r->sattr = NULL;

                        r->status = entry_status;
                        r->retry++;
                        return retry;
                    }
                }

                //TODO: sso_only?

                if (policy_status == AM_EXACT_MATCH || policy_status == AM_EXACT_PATTERN_MATCH) {
                    struct am_action_decision *ae, *at;

                    if (r->not_enforced && (r->conf->not_enforced_fetch_attr || r->is_dummypost_url) &&
                            e->scope == AM_SCOPE_RESPONSE_ATTRIBUTE_ONLY) {
                        /* allow, in case this is not-enforced url and attribute fetch is enabled or this is a dummypost_url
                         * (ignoring policy result) */
                        AM_LOG_DEBUG(r->instance_id,
                                "%s method: %s, decision: allow, not enforced url with attribute fetch enabled",
                                thisfunc, am_method_num_to_str(r->method));
                        r->response_attributes = e->response_attributes;
                        r->response_decisions = e->response_decisions;
                        r->status = AM_SUCCESS;
                        return ok;
                    }

                    if (e->action_decisions == NULL) {
                        AM_LOG_WARNING(r->instance_id,
                                "%s decision: deny, reason: no action decisions found",
                                thisfunc);
                    }

                    AM_LIST_FOR_EACH(e->action_decisions, ae, at) {

                        /*time_t ts = ae->ttl;
                        if (difftime(time(NULL), ts) >= 0) {
                            char tsu[32];
                            struct tm until;
                            localtime_r(&ts, &until);
                            strftime(tsu, sizeof (tsu), AM_CACHE_TIMEFORMAT, &until);
                            AM_LOG_WARNING(r->instance_id, "%s cache data is obsolete (valid until: %s)",
                                    thisfunc, tsu);
                            continue;
                        }*/

                        if (ae->method == r->method) {
                            if (ae->action /*allow*/) {
                                r->response_attributes = e->response_attributes; /*will be used by set header/cookie later*/
                                r->response_decisions = e->response_decisions;
                                r->status = AM_SUCCESS;

                                /*fetch user parameter value*/
                                if (ISVALID(r->conf->userid_param) &&
                                        ISVALID(r->conf->userid_param_type)) {
                                    if (strcasecmp(r->conf->userid_param_type, "SESSION") == 0) {
                                        r->user = get_attr_value(r, r->conf->userid_param, AM_SESSION_ATTRIBUTE);
                                    } else {
                                        r->user = get_attr_value(r, r->conf->userid_param, AM_POLICY_ATTRIBUTE);
                                    }
                                    r->user_password = get_attr_value(r, "sunIdentityUserPassword", AM_SESSION_ATTRIBUTE);
                                }

                                AM_LOG_DEBUG(r->instance_id, "%s method: %s, decision: allow",
                                        thisfunc, am_method_num_to_str(ae->method));
                                return ok;
                            }
                            /*deny*/
                            /*set the pointer to the policy advice(s) if any*/
                            r->policy_advice = ae->advices;
                            r->status = AM_ACCESS_DENIED;
                            AM_LOG_DEBUG(r->instance_id,
                                    "%s method: %s, decision: deny, advice: %s",
                                    thisfunc, am_method_num_to_str(ae->method),
                                    ae->advices == NULL ? "n/a" : "available");
                            return ok;
                        }
                    }
                }
            }
        }

        /* in case we haven't found anything in a policy (cached) response - redo validate_policy */
        if (!remote && policy_status != AM_EXACT_MATCH && policy_status != AM_EXACT_PATTERN_MATCH) {
            AM_LOG_WARNING(r->instance_id, "%s validate policy did not find a match for '%s' in the cached entries, "
                    "retrying with the new request to the policy service", thisfunc, url);
            r->response_attributes = NULL;
            r->response_decisions = NULL;
            r->policy_advice = NULL;

            delete_am_policy_result_list(&policy_cache);
            r->pattr = NULL;
            delete_am_namevalue_list(&session_cache);
            r->sattr = NULL;

            am_remove_cache_entry(r->instance_id, r->token);

            r->status = entry_status;
            /*technically, this is still a retry*/
            r->retry++;
            return retry;
        }
    }

    r->response_attributes = NULL;
    r->response_decisions = NULL;
    r->policy_advice = NULL;
    /*nothing is found in a policy response - respond with a default access denied*/
    r->status = AM_ACCESS_DENIED;
    return ok;
}

/**
 * Build and set "Set-Cookie" HTTP header value
 * 
 * @param req pointer to am_request_t
 * @param prefix, cookie name prefix, can be NULL
 * @param name, cookie name, must not be NULL or empty
 * @param value, cookie value, can be NULL
 * @param domain, cookie domain value, can be NULL
 * @param path, cookie path value, can be NULL
 * @param maxage, cookie max-age value in seconds, can be NULL
 */

static void do_cookie_set_generic(am_request_t *r, const char *prefix, const char *name,
        const char *value, const char *domain, const char *path, const char *maxage) {
    static const char *thisfunc = "do_cookie_set_generic():";
    char time_string[32];
    struct tm now;
    time_t raw;
    long sec;
    char *cookie_value, *cookie = NULL;

    if (r == NULL || r->conf == NULL || r->am_add_header_in_response_f == NULL || !ISVALID(name)) return;

    /* set cookie prefix */
    am_asprintf(&cookie, "%s", NOTNULL(prefix));

    /* set cookie name */
    if (cookie != NULL) {
        am_asprintf(&cookie, "%s%s=", cookie, name);
    }

    /* set cookie value */
    if (cookie != NULL) {
        cookie_value = r->conf->cookie_encode_chars ? url_encode((char *) value) : (char *) value;
        am_asprintf(&cookie, "%s%s", cookie, NOTNULL(cookie_value));
        if (r->conf->cookie_encode_chars) {
            am_free(cookie_value);
        }
    }

    if (cookie != NULL) {
        if (!ISVALID(value)) {
            /* no value is provided - we are resetting a cookie */
            am_asprintf(&cookie, "%s;Max-Age=0;Expires=Thu, 01-Jan-1970 00:00:01 GMT", cookie);
        } else {
            /* check if maxage option is provided, if so - use it;
             * if not - try cookie_maxage parameter;
             * if none of the above is provided/valid use a default 300 sec value
             */
            sec = ISVALID(maxage) ? strtol(maxage, NULL, AM_BASE_TEN)
                    : r->conf->cookie_maxage > 0 ? r->conf->cookie_maxage : 300;
            if (sec <= 0 || errno == ERANGE) {
                am_asprintf(&cookie, "%s;Max-Age=0;Expires=Thu, 01-Jan-1970 00:00:01 GMT", cookie);
            } else {
                time(&raw);
                raw += sec;
#ifdef _WIN32
                gmtime_s(&now, &raw);
#endif
                strftime(time_string, sizeof (time_string),
                        "%a, %d-%b-%Y %H:%M:%S GMT",
#ifdef _WIN32
                        &now
#else
                        gmtime_r(&raw, &now)
#endif
                        );
                am_asprintf(&cookie, "%s;Max-Age=%d;Expires=%s", cookie, sec, time_string);
            }
        }
    }

    /* set cookie domain value */
    if (cookie != NULL && ISVALID(domain)) {
        am_asprintf(&cookie, "%s;Domain=%s", cookie, domain);
    }

    /* set cookie path value */
    if (cookie != NULL) {
        am_asprintf(&cookie, "%s;Path=/%s", cookie, NOTNULL(path));
    }

    /* set cookie Secure attribute */
    if (cookie != NULL && r->conf->cookie_secure) {
        am_asprintf(&cookie, "%s;Secure", cookie);
    }

    /* set cookie HttpOnly attribute */
    if (cookie != NULL && r->conf->cookie_http_only) {
        am_asprintf(&cookie, "%s;HttpOnly", cookie);
    }

    if (cookie == NULL) {
        AM_LOG_ERROR(r->instance_id, "%s memory allocation failure", thisfunc);
        return;
    }

    AM_LOG_DEBUG(r->instance_id, "%s %s", thisfunc, LOGEMPTY(cookie));
    r->am_add_header_in_response_f(r, cookie, NULL);
    am_free(cookie);
}

static void do_cookie_set_type(am_request_t *r, am_config_map_t *map, int sz,
        int type, char cookie_reset_enable) {
    int i;
    for (i = 0; i < sz; i++) {
        am_config_map_t *v = &map[i];
        if (cookie_reset_enable) {
            AM_LOG_DEBUG(r->instance_id, "do_cookie_set(): clearing %s", v->value);
            do_cookie_set_generic(r, r->conf->cookie_prefix, v->value, NULL, NULL, NULL, NULL);
        } else {
            const char *val = get_attr_value(r, v->name, type);
            if (ISVALID(val)) {
                AM_LOG_DEBUG(r->instance_id, "do_cookie_set(): setting %s: %s",
                        v->value, val);
                do_cookie_set_generic(r, r->conf->cookie_prefix, v->value, val, NULL, NULL, NULL);
            }
        }
    }
}

static void do_cookie_set(am_request_t *r, char cookie_reset_list_enable, char cookie_reset_enable) {
    int i;
    if (r->am_add_header_in_response_f == NULL) return;
    if (cookie_reset_list_enable && r->conf->cookie_reset_enable
            && r->conf->cookie_reset_map_sz > 0) {
        /* process cookie reset list (agents.config.cookie.reset[0]) */
        for (i = 0; i < r->conf->cookie_reset_map_sz; i++) {
            am_config_map_t *v = &r->conf->cookie_reset_map[i];
            AM_LOG_DEBUG(r->instance_id, "do_cookie_set(): clearing %s", v->value);
            do_cookie_set_generic(r, NULL, v->value, NULL, NULL, NULL, NULL);
        }
    }
    if (r->conf->profile_attr_fetch == AM_SET_ATTRS_AS_COOKIE ||
            r->conf->session_attr_fetch == AM_SET_ATTRS_AS_COOKIE ||
            r->conf->response_attr_fetch == AM_SET_ATTRS_AS_COOKIE) {
        do_cookie_set_type(r, r->conf->profile_attr_map, r->conf->profile_attr_map_sz,
                AM_POLICY_ATTRIBUTE, cookie_reset_enable); //TODO: put each value into "val1,val2,val3.." format
        do_cookie_set_type(r, r->conf->session_attr_map, r->conf->session_attr_map_sz,
                AM_SESSION_ATTRIBUTE, cookie_reset_enable);
        do_cookie_set_type(r, r->conf->response_attr_map, r->conf->response_attr_map_sz,
                AM_RESPONSE_ATTRIBUTE, cookie_reset_enable);
    }
}

static void do_header_set_type(am_request_t *r, am_config_map_t *map, int sz,
        int type, char set_value) {
    int i;
    for (i = 0; i < sz; i++) {
        am_config_map_t *v = &map[i];
        if (set_value) {
            const char *val = get_attr_value(r, v->name, type);
            if (ISVALID(val)) {
                r->am_set_header_in_request_f(r, v->value, val);
                AM_LOG_DEBUG(r->instance_id, "do_header_set(): setting %s: %s",
                        v->value, val);
            }
        } else {
            r->am_set_header_in_request_f(r, v->value, NULL);
            AM_LOG_DEBUG(r->instance_id, "do_header_set(): clearing %s", v->value);
        }
    }
}

static void do_header_set(am_request_t *r, char set_value) {
    if (r->am_set_header_in_request_f == NULL) return;
    if (r->conf->profile_attr_fetch == AM_SET_ATTRS_AS_HEADER ||
            r->conf->session_attr_fetch == AM_SET_ATTRS_AS_HEADER ||
            r->conf->response_attr_fetch == AM_SET_ATTRS_AS_HEADER) {
        do_header_set_type(r, r->conf->profile_attr_map, r->conf->profile_attr_map_sz,
                AM_POLICY_ATTRIBUTE, set_value); //TODO: put each value into "val1,val2,val3.." format
        do_header_set_type(r, r->conf->session_attr_map, r->conf->session_attr_map_sz,
                AM_SESSION_ATTRIBUTE, set_value);
        do_header_set_type(r, r->conf->response_attr_map, r->conf->response_attr_map_sz,
                AM_RESPONSE_ATTRIBUTE, set_value);
    }
}

static void set_user_attributes(am_request_t *r) {
    static const char *thisfunc = "set_user_attributes():";
    int i;
    do {

        if (r->am_set_header_in_request_f == NULL || r->am_add_header_in_response_f == NULL) {
            AM_LOG_ERROR(r->instance_id, "%s no set/add "
                    "request/response header function is provided", thisfunc);
            break;
        }

        /* CDSSO: update request Cookie header (session token) */
        if (r->conf->cdsso_enable) {
            char *new_cookie_hdr = NULL;
            int rv = remove_cookie(r, r->conf->cookie_name, &new_cookie_hdr);
            if (rv != AM_SUCCESS && rv != AM_NOT_FOUND) {
                AM_LOG_ERROR(r->instance_id, "%s error (%s) removing cookie %s from "
                        "cookie header %s", thisfunc, am_strerror(rv),
                        LOGEMPTY(r->conf->cookie_name), LOGEMPTY(r->cookies));
            } else {

                am_asprintf(&new_cookie_hdr, "%s%s%s=%s",
                        new_cookie_hdr == NULL ? "" : new_cookie_hdr,
                        new_cookie_hdr != NULL ? ";" : "",
                        r->conf->cookie_name,
                        r->token);
                if (new_cookie_hdr != NULL) {
                    r->am_set_header_in_request_f(r, "Cookie", new_cookie_hdr);
                    free(new_cookie_hdr);
                }

                /* if no domain is configured, don't set it,
                 * browser will default domain to the host value
                 */
                if (r->conf->cdsso_cookie_domain_map_sz > 0) {
                    for (i = 0; i < r->conf->cdsso_cookie_domain_map_sz; i++) {
                        am_config_map_t *m = &r->conf->cdsso_cookie_domain_map[i];
                        AM_LOG_DEBUG(r->instance_id, "%s setting session cookie in %s domain",
                                thisfunc, LOGEMPTY(m->value));
                        do_cookie_set_generic(r, NULL, r->conf->cookie_name, r->token, m->value, NULL, NULL);
                    }
                } else {
                    do_cookie_set_generic(r, NULL, r->conf->cookie_name, r->token, NULL, NULL, NULL);
                }
            }
        }

        /* if attributes mode is none, we're done */
        if (r->conf->profile_attr_fetch == AM_SET_ATTRS_NONE &&
                r->conf->session_attr_fetch == AM_SET_ATTRS_NONE &&
                r->conf->response_attr_fetch == AM_SET_ATTRS_NONE) {
            AM_LOG_DEBUG(r->instance_id, "%s all set user attribute options are set to none",
                    thisfunc);
            break;
        }

        /* if no attributes in result, we're done */
        if (r->conf->profile_attr_map_sz == 0 &&
                r->conf->session_attr_map_sz == 0 &&
                r->conf->response_attr_map_sz == 0) {
            AM_LOG_DEBUG(r->instance_id, "%s all attribute maps are empty - nothing to set",
                    thisfunc);
            if (!r->not_enforced || r->conf->not_enforced_fetch_attr) {
                /* clear headers/cookies */
                do_header_set(r, AM_FALSE);
                do_cookie_set(r, AM_FALSE, AM_TRUE);
            }
            break;
        }

        /* now go do it */
        if (!r->not_enforced || r->conf->not_enforced_fetch_attr) {
            /* clear headers/cookies */
            AM_LOG_DEBUG(r->instance_id, "%s clearing headers/cookies", thisfunc);
            do_header_set(r, AM_FALSE);
            do_cookie_set(r, AM_FALSE, AM_TRUE);
        }

        /* iterate - set attributes */
        do_header_set(r, AM_TRUE);
        do_cookie_set(r, AM_FALSE, AM_FALSE);

    } while (0);
}

static char *find_active_login_server(am_request_t *r, char add_goto_value) {
    static const char *thisfunc = "find_active_login_server():";
    int i, j, map_sz = 0;
    am_config_map_t *map = NULL;
    char local_alloc = AM_FALSE;
    char *cdsso_elements = NULL;
    char *login_url = NULL;
    const char *url = r->normalized_url;
    int valid_idx = get_valid_url_index(r->instance_id);

    if (r->conf->cdsso_enable) {
        long msec = 0;
        char *realm = NULL, *agent_url = NULL;
        char tsc[32];
#ifdef _WIN32
        SYSTEMTIME time;
        GetSystemTime(&time);
        msec = (time.wSecond * 1000) + time.wMilliseconds;
        snprintf(tsc, sizeof (tsc), "%04d-%02d-%02dT%02d%%3A%02d%%3A%02dZ",
                time.wYear, time.wMonth, time.wDay,
                time.wHour, time.wMinute, time.wSecond);
#else
        struct tm tn;
        time_t now;
        struct timeval time;
        gettimeofday(&time, NULL);
        msec = (time.tv_sec * 1000) + (time.tv_usec / 1000);
        now = (time_t) time.tv_sec;
        gmtime_r(&now, &tn);
        strftime(tsc, sizeof (tsc), "%Y-%m-%dT%H%%3A%M%%3A%SZ", &tn);
#endif
        map_sz = r->conf->cdsso_login_map_sz;
        map = r->conf->cdsso_login_map;

        if (ISVALID(r->conf->realm) && strcmp(r->conf->realm, "/") != 0) {
            realm = url_encode(r->conf->realm);
        }

        agent_url = url_encode(r->conf->agenturi);

        am_asprintf(&cdsso_elements,
                ISVALID(realm) ? "Realm=%s&RequestID=%ld&MajorVersion=1&MinorVersion=0&ProviderID=%s&IssueInstant=%s" :
                "%sRequestID=%ld&MajorVersion=1&MinorVersion=0&ProviderID=%s&IssueInstant=%s",
                ISVALID(realm) ? realm : "",
                msec,
                NOTNULL(agent_url), tsc);

        AM_FREE(realm, agent_url);
    } else {
        map_sz = r->conf->login_url_sz;
        map = r->conf->login_url;
    }

    if (r->conf->cond_login_url_sz > 0 && r->conf->cond_login_url != NULL) {
        for (i = 0; i < r->conf->cond_login_url_sz; i++) {
            am_config_map_t *m = &r->conf->cond_login_url[i];
            char *cl = strdup(m->value);
            if (cl != NULL) {
                char compare_status, *sep = strchr(cl, '|');
                if (sep != NULL && *(sep + 1) != '\0') {
                    *sep = 0;
                } else {
                    free(cl);
                    continue;
                }
                /*try to locate given pattern in a request url*/
                compare_status = r->conf->url_eval_case_ignore ?
                        (stristr((char *) url, cl) != NULL ? AM_TRUE : AM_FALSE) :
                        (strstr(url, cl) != NULL ? AM_TRUE : AM_FALSE);

                AM_LOG_DEBUG(r->instance_id, "%s conditional login pattern: %s, url: %s, match status: %s",
                        thisfunc, cl, url, compare_status ? "match" : "no match");

                if (compare_status) {
                    /*found a match*/
                    char *tk, *tmp = strdup(cl + strlen(cl) + 1), *o = tmp;
                    if (tmp == NULL) break;
                    /*set up url list*/
                    map_sz = char_count(tmp, ',', NULL) + 1;
                    map = (am_config_map_t *) malloc(map_sz * sizeof (am_config_map_t));
                    if (map != NULL) {
                        j = 0;
                        while ((tk = am_strsep(&tmp, AM_COMMA_CHAR)) != NULL) {
                            char *v = strdup(tk);
                            trim(v, ' ');
                            (&map[j])->name = v;
                            (&map[j])->value = v;
                            j++;
                        }
                        local_alloc = AM_TRUE;
                    }
                    free(o);
                    free(cl);
                    break;
                }
                free(cl);
            }
        }
    }

    /*use url-validator confirmed (index) value*/
    if (map_sz > 0 && map != NULL) {
        am_config_map_t *m = (valid_idx >= map_sz) ? &map[0] : &map[valid_idx];
        if (add_goto_value) {
            char *goto_encoded = url_encode(r->overridden_url);
            am_asprintf(&login_url, "%s%s%s=%s",
                    m->value,
                    strchr(m->value, '?') == NULL ? "?" : "&",
                    ISVALID(r->conf->url_redirect_param) ? r->conf->url_redirect_param : "goto",
                    NOTNULL(goto_encoded));

            if (ISVALID(cdsso_elements)) {
                am_asprintf(&login_url, "%s&%s", login_url, cdsso_elements);
            }
            am_free(goto_encoded);
        } else {
            if (ISVALID(cdsso_elements)) {
                am_asprintf(&login_url, "%s%s%s",
                        m->value,
                        strchr(m->value, '?') == NULL ? "?" : "&",
                        cdsso_elements);
            } else {
                login_url = strdup(m->value);
            }
        }
        AM_LOG_DEBUG(r->instance_id, "%s selected login url: %s", thisfunc, LOGEMPTY(login_url));
    }

    if (local_alloc) {
        AM_CONF_MAP_FREE(map_sz, map);
    }

    return login_url;
}

static am_return_t handle_exit(am_request_t *r) {
    static const char *thisfunc = "handle_exit():";
    int valid_idx, i;
    am_status_t status;
    char *url = NULL;

    if (r == NULL || r->ctx == NULL || r->conf == NULL) {
        if (r != NULL) r->status = AM_ERROR;
        return fail;
    }

    status = r->status;
    AM_LOG_DEBUG(r->instance_id, "%s (entry status: %s)", thisfunc, am_strerror(status));

    if (status == AM_NOTIFICATION_DONE) {
        /*fast exit for notification events*/
        r->status = AM_DONE;
        return ok;
    }

    if (status != AM_SUCCESS && r->conf->cache_control_enable &&
            r->am_add_header_in_response_f != NULL) {
        /* do not cache any unauthenticated response */
        r->am_add_header_in_response_f(r, "Cache-Control", "no-store"); /* HTTP 1.1 */
        r->am_add_header_in_response_f(r, "Cache-Control", "no-cache"); /* HTTP 1.1 */
        r->am_add_header_in_response_f(r, "Pragma", "no-cache"); /* HTTP 1.0 */
        r->am_add_header_in_response_f(r, "Expires", "0"); /* prevents caching at a proxy server */
    }

    switch (status) {
        case AM_SUCCESS:
        {
            if (r->is_logout_url) {
                if (r->am_add_header_in_response_f != NULL &&
                        r->conf->logout_cookie_reset_map_sz > 0) {
                    /*process logout cookie reset list (logout.cookie.reset)*/
                    for (i = 0; i < r->conf->logout_cookie_reset_map_sz; i++) {
                        am_config_map_t *m = &r->conf->logout_cookie_reset_map[i];
                        do_cookie_set_generic(r, NULL, m->value, NULL, NULL, NULL, NULL);
                    }
                }

                /*reset headers/cookies*/
                do_header_set(r, AM_FALSE);
                do_cookie_set(r, AM_FALSE, AM_TRUE);

                if (ISVALID(r->token) && !ISVALID(r->conf->logout_redirect_url)) {
                    /*logout.redirect.url is not set - do background logout and cache cleanup*/
                    struct logout_worker_data *wd = malloc(sizeof (struct logout_worker_data));
                    if (wd != NULL) {
                        const char *oam = get_valid_openam_url(r);
                        wd->instance_id = r->instance_id;
                        /*find active OpenAM service URL*/
                        if (oam != NULL) {
                            wd->token = strdup(r->token);
                            wd->openam = strdup(oam);

                            am_net_set_ssl_options(r->conf, &wd->info);

                            if (am_worker_dispatch(session_logout_worker, wd) != 0) {
                                AM_FREE(wd->token, wd->openam);
                                free(wd);
                                r->status = AM_ERROR;
                                AM_LOG_WARNING(r->instance_id, "%s failed to dispatch logout worker", thisfunc);
                                break;
                            }
                        } else {
                            r->status = AM_ERROR;
                            free(wd);
                            AM_LOG_WARNING(r->instance_id, "%s logout failed (could not find a valid OpenAM URL)", thisfunc);
                        }
                    } else {
                        r->status = AM_ENOMEM;
                        break;
                    }

                    r->status = AM_SUCCESS;
                    break; /*early exit - we're done with this resource*/
                }

                /* do OpenAM logout redirect with a goto value if logout_redirect_url is set. 
                 * will land here if no session token is available and logout_redirect_url is not set too.
                 */
                valid_idx = get_valid_url_index(r->instance_id);
                if (r->conf->openam_logout_map_sz > 0) {
                    am_config_map_t *m = (valid_idx >= r->conf->openam_logout_map_sz) ?
                            &r->conf->openam_logout_map[0] : &r->conf->openam_logout_map[valid_idx];

                    char *goto_encoded = url_encode(r->conf->logout_redirect_url);
                    am_asprintf(&url, "%s%s%s=%s",
                            m->value,
                            strchr(m->value, '?') == NULL ? "?" : "&",
                            ISVALID(r->conf->url_redirect_param) ? r->conf->url_redirect_param : "goto",
                            NOTNULL(goto_encoded));
                    am_free(goto_encoded);
                } else {
                    r->status = AM_EINVAL;
                    break;
                }

                if (url == NULL) {
                    r->status = AM_ENOMEM;
                    break;
                }

                r->status = AM_REDIRECT;
                r->am_set_custom_response_f(r, url, NULL);
                free(url);
                break;
            }

            /* set user */
            if (r->am_set_user_f != NULL && ISVALID(r->user)) {
                r->am_set_user_f(r, r->user);
            }

            /* set user attributes */
            set_user_attributes(r);

            if ((r->conf->audit_level & AM_LOG_LEVEL_AUDIT_ALLOW) == AM_LOG_LEVEL_AUDIT_ALLOW) {
                AM_LOG_AUDIT(r->instance_id, AUDIT_ALLOW_USER_MESSAGE,
                        LOGEMPTY(r->user), LOGEMPTY(r->client_ip), LOGEMPTY(r->normalized_url));
            }

            if (r->token_in_post && r->conf->cdsso_enable &&
                    !r->is_dummypost_url && r->am_set_custom_response_f != NULL) {
                /* special GET handling after LARES re-post (do a redirect only on memory failure) */
                am_asprintf(&url, "<html><head></head><body onload=\"document.getform.submit()\">"
                        "<form name=\"getform\" method=\"GET\" action=\"%s\">"
                        "</form></body></html>",
                        r->normalized_url);
                if (url != NULL) {
                    r->status = AM_DONE;
                    r->am_set_custom_response_f(r, url, "text/html");
                    free(url);
                } else {
                    /* r->status = AM_INTERNAL_REDIRECT; */
                    r->status = AM_REDIRECT;
                    r->am_set_custom_response_f(r, r->normalized_url, NULL);
                }
                break;
            }

            if (r->is_dummypost_url) {
                am_status_t pdp_status = AM_ERROR;
                const char *key = r->url.query + 1; /* skip '?' */
                if (ISVALID(key)) {
                    char *data = NULL /* url\0file\0 format */, *content_type = NULL;
                    size_t url_sz = 0;

                    pdp_status = am_get_pdp_cache_entry(r, key, &data, &url_sz, &content_type);
                    if (pdp_status == AM_SUCCESS) {
                        const char *file = data + url_sz + 1;
                        AM_LOG_DEBUG(r->instance_id, "%s found post data preservation cache "
                                "entry: %s, url: %s, file: %s, content type: %s",
                                thisfunc, key, LOGEMPTY(data), LOGEMPTY(file), LOGEMPTY(content_type));

                        /* reset pdp sticky-session load-balancer cookie */
                        if (ISVALID(r->conf->pdp_sess_mode) && ISVALID(r->conf->pdp_sess_value)
                                && strcmp(r->conf->pdp_sess_mode, "COOKIE") == 0
                                && match(r->instance_id, r->conf->pdp_sess_value, "^(\\w+)=([^\\s]+)$") == AM_SUCCESS) {
                            char *sess_cookie = strdup(r->conf->pdp_sess_value);
                            if (sess_cookie != NULL) {
                                char *eq = strchr(sess_cookie, '=');
                                if (eq != NULL) {
                                    *eq++ = 0;
                                    do_cookie_set_generic(r, NULL, sess_cookie, NULL, NULL, NULL, NULL);
                                }
                                free(sess_cookie);
                            } else {
                                AM_LOG_ERROR(r->instance_id, "%s memory allocation failure", thisfunc);
                            }
                        }

                        if (strcmp(file, "0") == 0) {
                            /* empty post */
                            r->method = AM_REQUEST_POST;
                            r->status = AM_PDP_DONE;
                            r->post_data_url = data;
                            r->post_data_sz = 0;
                            am_free(r->post_data);
                            r->post_data = NULL;
                            /* empty pdp does not need post data set */
                            r->am_set_custom_response_f(r, AM_SPACE_CHAR, content_type);
                        } else {
                            size_t post_sz = 0;
                            char *post = load_file(file, &post_sz);
                            if (post != NULL) {
                                if (r->conf->pdp_js_repost) {
                                    /* IE10+ only */
                                    char *repost = NULL;
                                    am_asprintf(&repost, "<html><head><script type=\"text/javascript\">"
                                            "function base64toBlob(b64Data, contentType, sliceSize) {contentType = contentType || '';"
                                            "sliceSize = sliceSize || 512;var byteCharacters = atob(b64Data);var byteArrays = [];"
                                            "for (var offset = 0; offset < byteCharacters.length; offset += sliceSize) {"
                                            "var slice = byteCharacters.slice(offset, offset + sliceSize);"
                                            "var byteNumbers = new Array(slice.length);"
                                            "for (var i = 0; i < slice.length; i++) {byteNumbers[i] = slice.charCodeAt(i);}"
                                            "var byteArray = new Uint8Array(byteNumbers);byteArrays.push(byteArray);}"
                                            "var blob = new Blob(byteArrays, {type: contentType});"
                                            "return blob;}"
                                            "function sendpost() {var r = new XMLHttpRequest();r.open(\"POST\", \"%s\", true);"
                                            "r.onreadystatechange=function(e) {var x = e.target; "
                                            "if (x.readyState==4 && x.status === 200) {"
                                            "document.body.innerHTML = x.responseText;"
                                            "document.title = !x.response.pageTitle ? x.responseURL : x.response.pageTitle;"
                                            "window.history.pushState({\"html\":x.response,\"pageTitle\":x.response.pageTitle},\"\",\"%s\");}};"
                                            "var b = base64toBlob(\"%s\", \"%s\");r.send(b);"
                                            "}</script></head><body onload=\"sendpost();\">"
                                            "</body><p></p></html>",
                                            data, data,
                                            post,
                                            content_type);
                                    r->status = AM_SUCCESS;
                                    r->am_set_custom_response_f(r, repost, "text/html");
                                    am_free(repost);
                                } else {
                                    char *post_clear = base64_decode(post, &post_sz);
                                    r->method = AM_REQUEST_POST;
                                    r->status = AM_PDP_DONE;
                                    r->post_data_url = data;
                                    r->post_data_sz = post_sz;
                                    am_free(r->post_data);
                                    r->post_data = post_clear; /* will be released with am_request_t cleanup */
                                    if (r->am_set_post_data_f != NULL) {
                                        r->am_set_post_data_f(r);
                                    } else {
                                        AM_LOG_DEBUG(r->instance_id, "%s am_set_post_data_f is NULL",
                                                thisfunc);
                                    }
                                    r->am_set_custom_response_f(r, AM_SPACE_CHAR, content_type);
                                }
                            } else {
                                pdp_status = AM_EINVAL;
                            }
                            am_free(post);
                        }

                        /* delete cache file */
                        if (ISVALID(file) && strcmp(file, "0") != 0) {
                            unlink(file);
                        }
                        /* delete cache entry */
                        am_remove_cache_entry(r->instance_id, key);

                    } else {
                        AM_LOG_WARNING(r->instance_id,
                                "%s post data preservation cache entry %s is not available (%s)",
                                thisfunc, key, am_strerror(pdp_status));
                    }

                    AM_FREE(data, content_type);
                } else {
                    AM_LOG_WARNING(r->instance_id,
                            "%s invalid post data preservation key value", thisfunc);
                }

                if (pdp_status != AM_SUCCESS) {
                    r->status = AM_NOT_FOUND;
                }
                break;
            }

            /* allow access to the resource */
            r->status = AM_SUCCESS;
        }
            break;

        case AM_INVALID_SESSION:
        case AM_ACCESS_DENIED:
        case AM_INVALID_FQDN_ACCESS:

            if (status == AM_ACCESS_DENIED &&
                    (r->conf->audit_level & AM_LOG_LEVEL_AUDIT_DENY) == AM_LOG_LEVEL_AUDIT_DENY) {
                AM_LOG_AUDIT(r->instance_id, AUDIT_DENY_USER_MESSAGE,
                        LOGEMPTY(r->user), LOGEMPTY(r->client_ip), LOGEMPTY(r->normalized_url));
            }

            if (r->am_set_custom_response_f != NULL) {

                if (status == AM_INVALID_SESSION) {
                    /* reset LDAP cookies on invalid session */
                    do_cookie_set(r, AM_TRUE, AM_TRUE);
                    if (r->conf->cdsso_enable) {
                        /* reset CDSSO cookie */
                        do_cookie_set_generic(r, NULL, r->conf->cookie_name, NULL, NULL, NULL, NULL);
                    }
                }

                if (status == AM_ACCESS_DENIED && r->conf->cdsso_enable) {
                    /* reset CDSSO and LDAP cookies on access denied */
                    do_cookie_set(r, AM_TRUE, AM_TRUE);
                    do_cookie_set_generic(r, NULL, r->conf->cookie_name, NULL, NULL, NULL, NULL);
                }

                if (r->method == AM_REQUEST_POST && r->conf->pdp_enable &&
                        status != AM_INVALID_FQDN_ACCESS) {
                    am_status_t pdp_status = AM_SUCCESS;
                    char key[37], *file = NULL;
                    ssize_t wrote;

                    /* post data should already be read in validate_token (with cdsso)
                     * if not - read it here */

                    /* read post data (blocking) */
                    if (!r->conf->cdsso_enable) {
                        if (r->am_get_post_data_f != NULL) {
                            r->am_get_post_data_f(r);
                        } else {
                            pdp_status = AM_ERROR;
                        }
                    }

                    /* check if we have an access to the post data file directory */
                    if (!ISVALID(r->conf->pdp_dir) || !file_exists(r->conf->pdp_dir)) {
                        AM_LOG_ERROR(r->instance_id,
                                "%s post data preservation module has no access to %s directory",
                                thisfunc, LOGEMPTY(r->conf->pdp_dir));
                        pdp_status = AM_ERROR;
                    }


                    if (pdp_status == AM_SUCCESS) {
                        char *repost_uri = NULL, *goto_value = NULL, *goto_encoded = NULL,
                                pdp_sess_mode, pdp_sess_mode_url, pdp_sess_mode_cookie;
                        /* generate unique post data identifier */
                        uuid(key, sizeof (key));

                        /* create a file name to store post data */
                        am_asprintf(&file, "%s/%s", r->conf->pdp_dir, key);
                        am_asprintf(&repost_uri, "%s%s", r->url.path, r->url.query);

                        if (r->post_data_sz > 0) {
                            size_t post_enc_sz = r->post_data_sz;
                            char *post_enc = base64_encode(r->post_data, &post_enc_sz);

                            wrote = write_file(file, post_enc, post_enc_sz);
                            if (wrote != (ssize_t) post_enc_sz) {
                                AM_LOG_ERROR(r->instance_id,
                                        "%s could not write %d bytes to %s",
                                        thisfunc, post_enc_sz, LOGEMPTY(file));
                            }
                            am_add_pdp_cache_entry(r, key, repost_uri, file, r->content_type);
                        } else {
                            am_add_pdp_cache_entry(r, key, repost_uri, "0", r->content_type);
                        }

                        /* pdp sticky session value, if set, has to be in a correct format: param=value */
                        pdp_sess_mode = ISVALID(r->conf->pdp_sess_mode) && ISVALID(r->conf->pdp_sess_value)
                                && match(r->instance_id, r->conf->pdp_sess_value, "^(\\w+)=([^\\s]+)$") == AM_SUCCESS;

                        pdp_sess_mode_url = pdp_sess_mode && strcmp(r->conf->pdp_sess_mode, "URL") == 0;
                        pdp_sess_mode_cookie = pdp_sess_mode && strcmp(r->conf->pdp_sess_mode, "COOKIE") == 0;

                        /* create a goto value */
                        am_asprintf(&goto_value, "%s://%s:%d%s%s"POST_PRESERVE_URI"?%s%s%s",
                                r->url.proto, r->url.host, r->url.port,
                                ISVALID(r->conf->pdp_uri_prefix) && r->conf->pdp_uri_prefix[0] != '/' ? "/" : "",
                                NOTNULL(r->conf->pdp_uri_prefix),
                                key,
                                pdp_sess_mode_url ? "&" : "",
                                pdp_sess_mode_url ? r->conf->pdp_sess_value : ""
                                );
                        goto_encoded = url_encode(goto_value);

                        /* create a redirect url value */
                        url = find_active_login_server(r, AM_FALSE);
                        am_asprintf(&url, "%s%s%s=%s",
                                url,
                                strchr(url, '?') != NULL ? "&" : "?",
                                ISVALID(r->conf->url_redirect_param) ? r->conf->url_redirect_param : "goto",
                                NOTNULL(goto_encoded));

                        if (pdp_sess_mode_cookie) {
                            /* create pdp sticky-session load-balancer cookie */
                            char *sess_cookie = strdup(r->conf->pdp_sess_value);
                            if (sess_cookie != NULL) {
                                char *eq = strchr(sess_cookie, '=');
                                if (eq != NULL) {
                                    *eq++ = 0;
                                    do_cookie_set_generic(r, NULL, sess_cookie, eq, NULL, r->conf->pdp_uri_prefix, NULL);
                                }
                                free(sess_cookie);
                            } else {
                                AM_LOG_ERROR(r->instance_id, "%s memory allocation failure", thisfunc);
                            }
                        }

                        AM_FREE(goto_value, goto_encoded, file, repost_uri);
                    }

                } else if (status == AM_INVALID_FQDN_ACCESS) {
                    /* if previous status was invalid fqdn access,
                     * redirect to a valid fqdn url
                     */
                    char *goto_value = NULL, *goto_encoded = NULL;
                    const char *host = ISVALID(r->client_fqdn) ? r->client_fqdn : r->conf->fqdn_default;

                    if (!ISVALID(host)) {
                        /* still nothing - return http403 error
                         * TODO: redirect to access denied page?
                         */
                        r->status = AM_FORBIDDEN;
                        break;
                    }

                    am_asprintf(&goto_value, "%s://%s:%d%s%s",
                            r->url.proto, host,
                            r->url.port, r->url.path, r->url.query);
                    goto_encoded = url_encode(goto_value);

                    url = find_active_login_server(r, AM_FALSE);
                    am_asprintf(&url, "%s%s%s=%s",
                            url,
                            strchr(url, '?') != NULL ? "&" : "?",
                            ISVALID(r->conf->url_redirect_param) ? r->conf->url_redirect_param : "goto",
                            NOTNULL(goto_encoded));
                    AM_FREE(goto_value, goto_encoded);

                } else {
                    /* if previous status was invalid session or if there was a policy
                     * advice, redirect to the OpenAM login page. If not, redirect to the
                     * configured access denied url if any 
                     */
                    if (status == AM_INVALID_SESSION || r->policy_advice != NULL /*|| session advice? */) {

                        url = find_active_login_server(r, AM_TRUE); /*contains goto value*/

                        AM_LOG_DEBUG(r->instance_id, "%s find_active_login_server value: %s", thisfunc,
                                LOGEMPTY(url));

                        if (r->policy_advice != NULL) {
                            //TODO: session advice ?

                            char *composite_advice = NULL, *composite_advice_encoded = NULL;
                            struct am_namevalue *e, *t;

                            AM_LIST_FOR_EACH(r->policy_advice, e, t) {
                                am_asprintf(&composite_advice,
                                        "%s<AttributeValuePair><Attribute name=\"%s\"/><Value>%s</Value></AttributeValuePair>",
                                        composite_advice == NULL ? "" : composite_advice,
                                        e->n, e->v);
                            }
                            if (composite_advice != NULL) {
                                am_asprintf(&composite_advice, "<Advices>%s</Advices>", composite_advice);
                            }

                            composite_advice_encoded = url_encode(composite_advice);
                            am_free(composite_advice);

                            if (!r->conf->use_redirect_for_advice) {
                                am_asprintf(&url, "<html><head></head><body onload=\"document.postform.submit()\">"
                                        "<form name=\"postform\" method=\"POST\" action=\"%s\">"
                                        "<input type=\"hidden\" name=\""COMPOSITE_ADVICE_KEY"\" value=\"%s\"/>"
                                        "</form></body></html>",
                                        url,
                                        NOTNULL(composite_advice_encoded));

                                r->status = AM_DONE;
                                r->am_set_custom_response_f(r, url, "text/html");
                                free(url);
                                am_free(composite_advice_encoded);
                                break;
                            } else {
                                am_asprintf(&url, "%s&"COMPOSITE_ADVICE_KEY"=%s",
                                        url,
                                        NOTNULL(composite_advice_encoded));
                            }
                            am_free(composite_advice_encoded);
                        }

                    } else if (ISVALID(r->conf->access_denied_url)) {
                        char *goto_encoded = url_encode(r->overridden_url);

                        am_asprintf(&url, "%s%s%s=%s", r->conf->access_denied_url,
                                strchr(r->conf->access_denied_url, '?') == NULL ? "?" : "&",
                                ISVALID(r->conf->url_redirect_param) ? r->conf->url_redirect_param : "goto",
                                NOTNULL(goto_encoded));

                        am_free(goto_encoded);
                    } else {
                        r->status = AM_FORBIDDEN;
                        break;
                    }
                }

                if (url == NULL) {
                    r->status = AM_ENOMEM;
                    break;
                }

                /* set Location header and instruct the container to do a redirect */
                r->status = AM_REDIRECT;
                r->am_set_custom_response_f(r, url, NULL);
                free(url);
                break;
            }

        default:
            AM_LOG_ERROR(r->instance_id, "%s status: %s", thisfunc,
                    am_strerror(r->status));
            break;
    }

    return ok;
}

static am_state_func_t const am_request_state[] = {
    setup_request_data,
    validate_url,
    handle_notification,
    validate_token,
    validate_fqdn_access,
    handle_not_enforced,
    validate_policy,
    handle_exit
};

void am_process_request(am_request_t *r) {
    am_state_t cur_state = ENTRY_STATE;
    am_return_t rc = fail;
    am_state_func_t fn;
    for (;;) {
        fn = am_request_state[cur_state];
        rc = fn(r);
        if (EXIT_STATE == cur_state) break;
        cur_state = lookup_transition(cur_state, rc);
    }
}

/**
 * Returns a pointer to the "process state" functions into the callers space and sets the number of pointers.
 * This is used to provide access to the porcess state functions for testing.
 *
 * @param func_array_ptr address of pointer to be set
 * @param array_len_ptr the number of functions returned
 */
extern void am_test_get_state_funcs(am_state_func_t const ** func_array_ptr, int * array_len_ptr) {
    * func_array_ptr = am_request_state;
    * array_len_ptr = (&am_request_state)[1] - am_request_state;
}

