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
 * Copyright 2014 - 2016 ForgeRock AS.
 */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <io.h>
#else
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>
#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <http_main.h>
#include <http_config.h>
#include <ap_mpm.h>
#include <apr_strings.h>
#include <apr_buckets.h>

#include "version.h"
#include "am.h"

static const char amagent_post_filter_name[] = "AmModuleFilterIn";
static const char amagent_preserve_url_hook_name[] = "AmModulePreservedUrl";

module AP_MODULE_DECLARE_DATA amagent_module;

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(amagent);
#endif

typedef struct {
    int done_writing;
    int output_sent;
    int size;
    apr_file_t *tmp_file;
    char *output_ptr;
} amagent_filter_ctx;

typedef struct {
    char enabled;
    char *config;
    char *debug_file;
    char *audit_file;
    int debug_level;
    int audit_level;
    int debug_size;
    int audit_size;
    int error;
    int agent_id;
    unsigned long config_id;
} amagent_config_t; /*per server config*/

static const char *am_set_opt(cmd_parms *c, void *cfg, const char *arg) {
    amagent_config_t *conf = (amagent_config_t *)
            ap_get_module_config(c->server->module_config, &amagent_module);
    const char *name = c->cmd->name;
    if (!conf || !name) {
        return NULL;
    }
    if (strcmp(name, "AmAgentConf") == 0) {
        am_config_t *ac = NULL;
        conf->config = apr_psprintf(c->pool, "%s", arg);
        conf->config_id = am_instance_id(conf->config);
        /* read and parse agent bootstrap configuration */
        ac = am_get_config_file(conf->config_id, conf->config);
        if (ac != NULL) {
            conf->debug_file = ac->debug_file != NULL ? apr_pstrdup(c->pool, ac->debug_file) : NULL;
            conf->audit_file = ac->audit_file != NULL ? apr_pstrdup(c->pool, ac->audit_file) : NULL;
            conf->debug_level = ac->debug_level;
            conf->audit_level = ac->audit_level;
            conf->debug_size = ac->debug;
            conf->audit_size = ac->audit;
            conf->error = AM_SUCCESS;
            am_config_free(&ac);
        } else {
            conf->error = AM_FILE_ERROR;
        }
    } else if (strcmp(name, "AmAgent") == 0) {
        conf->enabled = !strcasecmp(arg, "on");
    } else if (strcmp(name, "AmAgentId") == 0) {
        conf->agent_id = strtol(arg, NULL, 10);
    }
    return NULL;
}

/*Context: either top level or inside VirtualHost*/
static const command_rec amagent_cmds[] = {
    AP_INIT_TAKE1("AmAgent", am_set_opt, NULL, RSRC_CONF, "Module enabled/disabled"),
    AP_INIT_TAKE1("AmAgentConf", am_set_opt, NULL, RSRC_CONF, "Module configuration file"),
    AP_INIT_TAKE1("AmAgentId", am_set_opt, NULL, RSRC_CONF, "Module Id"), {
        NULL
    }
};

static apr_status_t amagent_cleanup(void *arg) {
    /* main process cleanup */
    server_rec *s = (server_rec *) arg;
    amagent_config_t *config = ap_get_module_config(s->module_config, &amagent_module);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s, "amagent_cleanup() %d", getpid());
#ifndef _WIN32
    am_shutdown(config->agent_id);
#endif
    return APR_SUCCESS;
}

static void recovery_callback(void *cb_arg, char * name, int error) {
    server_rec *s = cb_arg;
    if (error) {
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, s, "unable to clear shared resource: %s, error %d", name, error);
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0, s, "agent cleared shared resource: %s", name);
    }
}

static int amagent_init(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp,
        server_rec *s) {
    /* main process init */
    int status;
    apr_status_t rv = APR_SUCCESS;
    void *data = NULL;
    amagent_config_t *config;

#define AMAGENT_INIT_ONCE "AMAGENT_INIT_ONCE"
    apr_pool_userdata_get(&data, AMAGENT_INIT_ONCE, s->process->pool);
    if (data == NULL) {
        /* this is a configuration check phase - do nothing */
        apr_pool_userdata_set((const void *) 1, AMAGENT_INIT_ONCE,
                apr_pool_cleanup_null, s->process->pool);
        return rv;
    }
    apr_pool_cleanup_register(pconf, s, amagent_cleanup, apr_pool_cleanup_null);
    ap_add_version_component(pconf, MODINFO);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s, "amagent_init() %d", getpid());

#ifndef _WIN32
    config = ap_get_module_config(s->module_config, &amagent_module);

    /* find and clear down shared memory resources after abnormal termination */
    if (am_remove_shm_and_locks(config->agent_id, recovery_callback, s) != AM_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, s, "amagent_init() failed to recover after abnormal termination");
        return APR_EINIT;
    }

    status = am_init(config->agent_id);
    if (status != AM_SUCCESS) {
        rv = APR_EINIT;
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, s, "amagent_init() status: %s", am_strerror(status));
    }
#endif
    return rv;
}

static apr_status_t amagent_worker_cleanup(void *arg) {
    /* worker process cleanup */
    server_rec *s = (server_rec *) arg;
#ifdef _WIN32
    amagent_config_t *config = ap_get_module_config(s->module_config, &amagent_module);
#endif
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s, "amagent_worker_cleanup() %d", getpid());
    am_shutdown_worker();
#ifdef _WIN32
    am_shutdown(config->agent_id);
#endif
    return APR_SUCCESS;
}

static void amagent_worker_init(apr_pool_t *p, server_rec *s) {
    /* worker process init */
    amagent_config_t *config = ap_get_module_config(s->module_config, &amagent_module);
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s, "amagent_worker_init() %d", getpid());
    am_init_worker(config->agent_id);
    apr_pool_cleanup_register(p, s, amagent_worker_cleanup, apr_pool_cleanup_null);
}

static void *amagent_srv_config(apr_pool_t *p, server_rec *srv) {
    amagent_config_t *c = apr_pcalloc(p, sizeof (amagent_config_t));
    if (c != NULL) {
        c->config = NULL;
        c->config_id = 0;
        c->enabled = 0;
        c->debug_file = NULL;
        c->audit_file = NULL;
        c->debug_level = 0;
        c->audit_level = 0;
        c->error = 0;
        c->agent_id = 0;
    }
    return (void *) c;
}

static int am_status_value(am_status_t v) {
    switch (v) {
        case AM_SUCCESS:
            return OK;
        case AM_PDP_DONE:
        case AM_DONE:
            return DONE;
        case AM_NOT_HANDLING:
            return DECLINED;
        case AM_NOT_FOUND:
            return HTTP_NOT_FOUND;
        case AM_REDIRECT:
            return HTTP_MOVED_TEMPORARILY;
        case AM_FORBIDDEN:
            return HTTP_FORBIDDEN;
        case AM_BAD_REQUEST:
            return HTTP_BAD_REQUEST;
        case AM_ERROR:
            return HTTP_INTERNAL_SERVER_ERROR;
        case AM_NOT_IMPLEMENTED:
            return HTTP_NOT_IMPLEMENTED;
        default:
            return HTTP_INTERNAL_SERVER_ERROR;
    }
}

static const char *get_request_header(am_request_t *req, const char *name) {
    request_rec *rec;
    if (req == NULL || (rec = (request_rec *) req->ctx) == NULL || ISINVALID(name))
        return NULL;
    return apr_table_get(rec->headers_in, name);
}

static am_status_t get_request_url(am_request_t *req) {
    request_rec *rec;

    if (req == NULL) {
        return AM_EINVAL;
    }

    rec = (request_rec *) req->ctx;
    if (rec == NULL) {
        return AM_EINVAL;
    }

    req->orig_url = apr_table_get(rec->notes, amagent_preserve_url_hook_name);
    if (req->orig_url == NULL) {
        /* ap_hook_translate_name is not invoked for sub-requests, read unparsed url from the current request */
        req->orig_url = ap_construct_url(rec->pool, rec->unparsed_uri, rec);
    }
    if (req->orig_url == NULL) {
        return AM_EINVAL;
    }

    req->path_info = rec->path_info;
    return AM_SUCCESS;
}

static am_status_t set_user(am_request_t *rq, const char *user) {
    static const char *thisfunc = "set_user():";
    request_rec *r = (request_rec *) (rq != NULL ? rq->ctx : NULL);
    if (r == NULL) return AM_EINVAL;
    r->user = apr_pstrdup(r->pool, user == NULL ? "" : user);
    r->ap_auth_type = apr_pstrdup(r->pool, "OpenAM");
    AM_LOG_DEBUG(rq->instance_id, "%s %s", thisfunc, LOGEMPTY(user));
    return AM_SUCCESS;
}

static am_status_t set_header_in_request(am_request_t *rq, const char *key, const char *value) {
    request_rec *r = (request_rec *) (rq != NULL ? rq->ctx : NULL);
    if (r == NULL || !ISVALID(key)) return AM_EINVAL;
    /* remove all instances of the header first */
    apr_table_unset(r->headers_in, key);
    if (ISVALID(value)) {
        apr_table_set(r->headers_in, key, value);
    }
    return AM_SUCCESS;
}

static am_status_t set_cookie(am_request_t *rq, const char *header) {
    request_rec *r = (request_rec *) (rq != NULL ? rq->ctx : NULL);
    const char *current_cookies;
    char *cookie, *equals, *sep;
    if (r == NULL || ISINVALID(header)) return AM_EINVAL;
    /* add cookie in response headers */
    apr_table_add(r->err_headers_out, "Set-Cookie", header);

    /* modify Cookie request header */
    cookie = apr_pstrdup(r->pool, header);
    if (cookie == NULL) return AM_ENOMEM;

    equals = strchr(cookie, '=');
    sep = strchr(cookie, ';');
    current_cookies = apr_table_get(r->headers_in, "Cookie");

    if (sep != NULL && equals != NULL && (sep - equals) > 1) {
        char *new_key = apr_pstrndup(r->pool, cookie, (equals - cookie) + 1); /* keep equals sign */
        char *new_value = apr_pstrndup(r->pool, cookie, sep - cookie);
        if (new_key == NULL || new_value == NULL) return AM_ENOMEM;
        if (ISINVALID(current_cookies)) {
            /* Cookie request header is not available yet - set it now */
            apr_table_add(r->headers_in, "Cookie", new_value);
        } else if (strstr(current_cookies, new_key) == NULL) {
            /* append header value to the existing one */
            apr_table_set(r->headers_in, "Cookie", apr_pstrcat(r->pool, current_cookies, ";", new_value, NULL));
        }
    }
    return AM_SUCCESS;
}

static am_status_t add_header_in_response(am_request_t *rq, const char *key, const char *value) {
    request_rec *r = (request_rec *) (rq != NULL ? rq->ctx : NULL);
    if (r == NULL || !ISVALID(key)) return AM_EINVAL;
    if (!ISVALID(value)) {
        /*value is empty, sdk is setting a cookie in response*/
        return set_cookie(rq, key);
    }
    /* Apache HTTPD keeps two separate server response header tables in the request 
     * record - one for normal response headers and one for error headers. 
     * The difference between them is the error headers are sent to 
     * the client even (not only) on an error response (REDIRECT is one of them)
     */
    apr_table_add(r->err_headers_out, key, value);
    return AM_SUCCESS;
}

static am_status_t set_custom_response(am_request_t *rq, const char *text, const char *cont_type) {
    static const char *thisfunc = "set_custom_response():";
    request_rec *r = (request_rec *) (rq != NULL ? rq->ctx : NULL);
    am_status_t status = AM_ERROR;

    if (r == NULL || !ISVALID(text)) {
        return AM_EINVAL;
    }

    status = rq->is_json_url ? AM_JSON_RESPONSE : rq->status;

    switch (status) {
        case AM_JSON_RESPONSE:
        {
            r->status = (rq->status == AM_REDIRECT || rq->status == AM_SUCCESS ||
                    rq->status == AM_DONE || rq->status == AM_INTERNAL_REDIRECT ||
                    rq->status == AM_PDP_DONE) ? HTTP_OK : am_status_value(rq->status);
            ap_set_content_type(r, "application/json");
            switch (rq->status) {
                case AM_PDP_DONE:
                {
                    apr_file_t *pdp_file;
                    apr_size_t nbytes;
                    apr_status_t rv;
                    char *buf = apr_palloc(r->pool, AP_IOBUFSIZE + 1);
                    char *a = NULL;
                    char *temp = NULL;
                    size_t data_sz = rq->post_data_sz;

                    rv = apr_file_open(&pdp_file, rq->post_data_fn, APR_FOPEN_READ | APR_FOPEN_BINARY,
                            APR_OS_DEFAULT, r->pool);
                    if (rv == APR_SUCCESS) {
                        while (!apr_file_eof(pdp_file)) {
                            do {
                                nbytes = AP_IOBUFSIZE;
                                rv = apr_file_read(pdp_file, buf, &nbytes);
                            } while (APR_STATUS_IS_EINTR(rv));
                            if (nbytes == 0 || rv != APR_SUCCESS) {
                                break;
                            }
                            buf[nbytes] = '\0';
                            if (a == NULL) {
                                a = apr_pstrdup(r->pool, buf);
                            } else {
                                a = apr_pstrcat(r->pool, a, buf, NULL);
                            }
                        }
                        apr_file_close(pdp_file);
                    }

                    if (a != NULL) {
                        temp = base64_encode(a, &data_sz);
                    }

                    ap_rprintf(r, AM_JSON_TEMPLATE_LOCATION_DATA,
                            am_strerror(rq->status), rq->post_data_url, cont_type,
                            NOTNULL(temp),
                            am_status_value(rq->status));
                    am_free(temp);
                    apr_file_remove(rq->post_data_fn, r->pool);
                }
                    break;
                case AM_REDIRECT:
                case AM_INTERNAL_REDIRECT:
                    ap_rprintf(r, AM_JSON_TEMPLATE_LOCATION,
                            am_strerror(rq->status), text, am_status_value(rq->status));
                    if (is_http_status(rq->conf->json_url_response_code)) {
                        r->status = rq->conf->json_url_response_code;
                    } else {
                        if (rq->conf->json_url_response_code != 0) {
                            AM_LOG_WARNING(rq->instance_id, "%s response status code %d is not valid, sending HTTP_FORBIDDEN",
                                    thisfunc, rq->conf->json_url_response_code);
                        }
                        r->status = HTTP_FORBIDDEN;
                    }
                    break;
                default:
                {
                    char *payload = am_json_escape(text, NULL);
                    ap_rprintf(r, AM_JSON_TEMPLATE_DATA,
                            am_strerror(rq->status), ISVALID(payload) ? payload : "\"\"",
                            am_status_value(rq->status));
                    am_free(payload);
                    break;
                }
            }
            ap_rflush(r);
            rq->status = AM_DONE;
            break;
        }
        case AM_INTERNAL_REDIRECT:
        {
            ap_internal_redirect(text, r);
            rq->status = AM_DONE;
            break;
        }
        case AM_REDIRECT:
        {
            apr_table_add(r->headers_out, "Location", text);
            ap_custom_response(r, HTTP_MOVED_TEMPORARILY, text);
            break;
        }
        case AM_PDP_DONE:
        {
            request_rec *sr;

            /* special handler for x-www-form-urlencoded POST data */
            if (apr_strnatcasecmp(cont_type, "application/x-www-form-urlencoded") == 0) {
                char *pair, *a = NULL, *eq, *inputs, *last = NULL;

                inputs = apr_pstrcat(r->pool, "", NULL);

                if (ISVALID(rq->post_data_fn)) {
                    apr_file_t *pdp_file;
                    apr_size_t nbytes;
                    apr_status_t rv;
                    char *buf = apr_palloc(r->pool, AP_IOBUFSIZE + 1);

                    rv = apr_file_open(&pdp_file, rq->post_data_fn, APR_FOPEN_READ | APR_FOPEN_BINARY,
                            APR_OS_DEFAULT, r->pool);
                    if (rv == APR_SUCCESS) {
                        while (!apr_file_eof(pdp_file)) {
                            do {
                                nbytes = AP_IOBUFSIZE;
                                rv = apr_file_read(pdp_file, buf, &nbytes);
                            } while (APR_STATUS_IS_EINTR(rv));
                            if (nbytes == 0 || rv != APR_SUCCESS) {
                                break;
                            }
                            buf[nbytes] = '\0';
                            if (a == NULL) {
                                a = apr_pstrdup(r->pool, buf);
                            } else {
                                a = apr_pstrcat(r->pool, a, buf, NULL);
                            }
                        }
                        apr_file_close(pdp_file);
                        apr_file_remove(rq->post_data_fn, r->pool);

                        /* recreate x-www-form-urlencoded HTML Form data */

                        for (pair = apr_strtok(a, "&", &last); pair;
                                pair = apr_strtok(NULL, "&", &last)) {
                            for (eq = pair; *eq; ++eq) {
                                if (*eq == '+') *eq = ' ';
                            }
                            ap_unescape_url(pair);
                            eq = strchr(pair, '=');
                            if (eq) {
                                *eq++ = 0;
                                inputs = apr_pstrcat(r->pool, inputs,
                                        "<input type=\"hidden\" name=\"", pair, "\" value=\"", eq, "\"/>", NULL);
                            } else {
                                inputs = apr_pstrcat(r->pool, inputs,
                                        "<input type=\"hidden\" name=\"", pair, "\" value=\"\"/>", NULL);
                            }
                        }
                    } else {
                        apr_strerror(rv, buf, AP_IOBUFSIZE);
                        AM_LOG_ERROR(rq->instance_id, "%s unable to open post preservation file: %s, %s",
                                thisfunc, rq->post_data_fn, buf);
                        apr_file_remove(rq->post_data_fn, r->pool);
                    }
                }

                r->clength = 0;
                apr_table_unset(r->headers_in, "Content-Length");
                apr_table_unset(r->notes, amagent_post_filter_name);
                ap_set_content_type(r, "text/html");
                ap_rprintf(r, "<html><head></head><body onload=\"document.postform.submit()\">"
                        "<form name=\"postform\" method=\"%s\" action=\"%s\">"
                        "%s"
                        "</form></body></html>",
                        am_method_num_to_str(rq->method),
                        rq->post_data_url, inputs);
                ap_rflush(r);
                rq->status = AM_DONE;
                break;
            }

            /* all other content types are replied in amagent_post_filter (as sub-request) */
            sr = ap_sub_req_method_uri(am_method_num_to_str(rq->method),
                    rq->post_data_url, r, NULL);

            sr->protocol = r->protocol;
            sr->proto_num = r->proto_num;
            sr->headers_in = r->headers_in;
            sr->notes = r->notes;
            sr->clength = rq->post_data_sz;
            sr->content_type = cont_type;
            sr->path_info = r->path_info;
            sr->args = r->args;

            AM_LOG_DEBUG(rq->instance_id, "%s issuing %s sub-request to %s (%s), status %d",
                    thisfunc, sr->method, rq->post_data_url, LOGEMPTY(cont_type), sr->status);

            ap_run_sub_req(sr);

            r->status_line = apr_pstrdup(r->pool, sr->status_line);
            r->status = sr->status;
            r->uri = sr->uri;

            ap_rflush(sr);

            ap_destroy_sub_req(sr);
            rq->status = AM_SUCCESS;
            break;
        }
        default:
        {
            size_t tl = strlen(text);
            if (ISVALID(cont_type)) {
                ap_set_content_type(r, cont_type);
            }
            ap_set_content_length(r, tl);
            ap_rwrite(text, (int) tl, r);
            ap_custom_response(r,
                    am_status_value(rq->status == AM_SUCCESS ||
                    rq->status == AM_DONE ? AM_SUCCESS : rq->status), text);
            ap_rflush(r);
            break;
        }
    }
    AM_LOG_DEBUG(rq->instance_id, "%s status: %s (exit: %s)",
            thisfunc, am_strerror(status), am_strerror(rq->status));

    return AM_SUCCESS;
}

static char get_method_num(request_rec *r, unsigned long instance_id) {
    static const char *thisfunc = "get_method_num():";
    int method_num = AM_REQUEST_UNKNOWN;
    const char *mthd = ap_method_name_of(r->pool, r->method_number);

    AM_LOG_DEBUG(instance_id, "%s method %s (%s, %d)", thisfunc, LOGEMPTY(r->method),
            LOGEMPTY(mthd), r->method_number);

    if (r->method_number == M_GET && r->header_only > 0) {
        method_num = AM_REQUEST_HEAD;
    } else {
        method_num = am_method_str_to_num(mthd);
    }

    AM_LOG_DEBUG(instance_id, "%s number corresponds to %s method",
            thisfunc, am_method_num_to_str(method_num));

    /* check if method number and method string correspond */
    if (method_num == AM_REQUEST_UNKNOWN) {
        /* if method string is not null, set the correct method number */
        if (r->method != NULL && *(r->method) != '\0') {
            method_num = am_method_str_to_num(r->method);
            r->method_number = ap_method_number_of(r->method);
            AM_LOG_DEBUG(instance_id, "%s set method number to correspond to %s method (%d)",
                    thisfunc, r->method, r->method_number);
        }
    } else if (ISVALID(r->method) && strcasecmp(r->method, am_method_num_to_str(method_num))
            && (method_num != AM_REQUEST_INVALID)) {
        /* in case the method number and the method string do not match,
         * correct the method string. But if the method number is invalid
         * the method string needs to be preserved in case Apache is
         * used as a proxy (in front of Exchange Server for instance)
         */
        r->method = am_method_num_to_str(method_num);
        AM_LOG_DEBUG(instance_id, "%s set method to %s", thisfunc, LOGEMPTY(r->method));
    }
    return method_num;
}

static am_status_t set_method(am_request_t *rq) {
    request_rec *r = (request_rec *) (rq != NULL ? rq->ctx : NULL);
    if (r == NULL) return AM_EINVAL;
    r->method = am_method_num_to_str(rq->method);
    r->method_number = ap_method_number_of(r->method);
    return AM_SUCCESS;
}

static am_status_t set_request_body(am_request_t *rq) {
    request_rec *r = (request_rec *) (rq != NULL ? rq->ctx : NULL);
    am_status_t status = AM_EINVAL;

    if (r == NULL) {
        return status;
    }

    apr_table_unset(r->notes, amagent_post_filter_name);

    if (ISVALID(rq->post_data_fn) && rq->post_data_sz > 0) {
        apr_table_set(r->notes, amagent_post_filter_name,
                apr_psprintf(r->pool, "%s", rq->post_data_fn));
        r->clength = rq->post_data_sz;
        apr_table_set(r->headers_in, "Content-Length",
                apr_psprintf(r->pool, "%ld", rq->post_data_sz));
    }
    return AM_SUCCESS;
}

static am_status_t get_request_body(am_request_t *rq) {
    static const char *thisfunc = "get_request_body():";
    request_rec *r;
    apr_bucket_brigade *bb;
    int eos_found = 0, read_bytes = 0;
    am_bool_t to_file = AM_FALSE, first_run = AM_TRUE;
    apr_status_t read_status = 0, ret;
    am_status_t status = AM_ERROR;
    char *out = NULL, *out_tmp = NULL;
    apr_file_t *fd = NULL;
    char *file_name = NULL;
    char buferr[50];

    if (rq == NULL || rq->ctx == NULL) {
        return AM_EINVAL;
    }

    r = (request_rec *) rq->ctx;
    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    do {
        apr_bucket *ob;
        read_status = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                APR_BLOCK_READ, HUGE_STRING_LEN);
        if (read_status != APR_SUCCESS) {
            am_free(out);
            return AM_ERROR;
        }

        ob = APR_BRIGADE_FIRST(bb);
        while (ob != APR_BRIGADE_SENTINEL(bb)) {
            const char *data;
            apr_size_t data_size;

            if (APR_BUCKET_IS_EOS(ob)) {
                eos_found = 1;
                status = AM_SUCCESS;
                break;
            }

            if (APR_BUCKET_IS_FLUSH(ob)) {
                continue;
            }

            /* read data */
            apr_bucket_read(ob, &data, &data_size, APR_BLOCK_READ);

            if (first_run) {
                to_file = data != NULL && data_size > 5 && memcmp(data, "LARES=", 6) != 0;
                first_run = AM_FALSE;
            }

            if (to_file) {
                apr_size_t nbytes_written;

                if (fd == NULL) {
                    char key[37];

                    if (ISINVALID(rq->conf->pdp_dir)) {
                        AM_LOG_ERROR(rq->instance_id, "%s invalid POST preservation configuration",
                                thisfunc);
                        status = AM_EINVAL;
                        eos_found = 1;
                        break;
                    }

                    uuid(key, sizeof (key));
                    file_name = apr_psprintf(r->pool, "%s/%s", rq->conf->pdp_dir, key);
                    ret = apr_file_open(&fd, file_name,
                            APR_FOPEN_CREATE | APR_FOPEN_APPEND | APR_FOPEN_WRITE | APR_FOPEN_BINARY
                            , APR_OS_DEFAULT, r->pool);
                    if (ret != APR_SUCCESS) {
                        apr_strerror(ret, buferr, sizeof (buferr));
                        AM_LOG_ERROR(rq->instance_id, "%s unable to open POST preservation file: %s, %s",
                                thisfunc, file_name, buferr);
                        status = AM_FILE_ERROR;
                        eos_found = 1;
                        break;
                    }
                }

                ret = apr_file_write_full(fd, data, data_size, &nbytes_written);
                if (ret != APR_SUCCESS) {
                    apr_strerror(ret, buferr, sizeof (buferr));
                    AM_LOG_ERROR(rq->instance_id, "%s unable to write to POST preservation file: %s, %s",
                            thisfunc, file_name, buferr);
                    status = AM_FILE_ERROR;
                    eos_found = 1;
                    break;
                }
                read_bytes += (int) data_size;

            } else {

                /* process in-memory data */
                out_tmp = realloc(out, read_bytes + data_size + 1);
                if (out_tmp == NULL) {
                    am_free(out);
                    status = AM_ENOMEM;
                    eos_found = 1;
                    break;
                } else {
                    out = out_tmp;
                }

                memcpy(out + read_bytes, data, data_size);
                read_bytes += (int) data_size;
                out[read_bytes] = 0;
            }

            ob = APR_BUCKET_NEXT(ob);
            status = AM_SUCCESS;
        }
        apr_brigade_destroy(bb);

    } while (eos_found == 0);

    apr_brigade_destroy(bb);

    rq->post_data = out;
    rq->post_data_fn = ISVALID(file_name) ? strdup(file_name) : NULL;
    rq->post_data_sz = read_bytes;

    if (fd != NULL) {
        apr_file_close(fd);
    }

    if (status == AM_SUCCESS) {
        AM_LOG_DEBUG(rq->instance_id, "%s read %d bytes \n%s", thisfunc,
                read_bytes, ISVALID(out) ? out : LOGEMPTY(file_name));
        /* remove Content-Length since the body has been read */
        r->clength = 0;
        apr_table_unset(r->headers_in, "Content-Length");
    }
    return status;
}

/**
 * The incoming request_req is changed into an am_request_t on which ALL of our remaining processing is then done.
 */
static int amagent_auth_handler(request_rec *req) {
    static const char *thisfunc = "amagent_auth_handler():";
    int result;
    am_request_t am_request;
    am_config_t *boot = NULL;

    amagent_config_t *config = ap_get_module_config(req->server->module_config, &amagent_module);

    if (config == NULL || !config->enabled) {
        /* amagent module is not enabled for this 
         * server/virtualhost - we are not handling this request
         **/
        return DECLINED;
    }

    if (config->error != AM_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, req, "%s is not configured to handle the request "
                "to %s (unable to load bootstrap configuration from %s, error: %s)",
                DESCRIPTION, req->uri, config->config, am_strerror(config->error));
        return HTTP_FORBIDDEN;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, req, "amagent_auth_handler(): [%s] [%ld]", config->config, config->config_id);

    /* register and update instance logger configuration (for already registered
     * instances - update logging level only 
     */
    am_log_register_instance(config->config_id, config->debug_file, config->debug_level, config->debug_size,
            config->audit_file, config->audit_level, config->audit_size, config->config);

    AM_LOG_DEBUG(config->config_id, "%s begin", thisfunc);

    /* fetch agent configuration instance (from cache if available) */
    result = am_get_agent_config(config->config_id, config->config, &boot);
    if (boot == NULL || result != AM_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, req, "%s is not configured to handle the request "
                "to %s (unable to get agent configuration instance, configuration: %s, error: %s)",
                DESCRIPTION, req->uri, config->config, am_strerror(result));

        AM_LOG_ERROR(config->config_id, "amagent_auth_handler(): failed to get agent configuration instance, error: %s",
                am_strerror(result));
        return HTTP_FORBIDDEN;
    }

    /* set up request processor data structure */
    memset(&am_request, 0, sizeof (am_request_t));
    am_request.conf = boot;
    am_request.status = AM_ERROR;
    am_request.instance_id = config->config_id;
    am_request.ctx = req;
    am_request.method = get_method_num(req, config->config_id);
    am_request.content_type = apr_table_get(req->headers_in, "Content-Type");
    am_request.cookies = apr_table_get(req->headers_in, "Cookie");

    if (ISVALID(am_request.conf->client_ip_header)) {
        am_request.client_ip = (char *) apr_table_get(req->headers_in, am_request.conf->client_ip_header);
    }

    if (!ISVALID(am_request.client_ip)) {
#ifdef APACHE24
        am_request.client_ip = (char *) req->connection->client_ip;
#else
        am_request.client_ip = (char *) req->connection->remote_ip;
#endif
    }

    if (ISVALID(am_request.conf->client_hostname_header)) {
        am_request.client_host = (char *) apr_table_get(req->headers_in, am_request.conf->client_hostname_header);
    }

    am_request.am_get_request_url_f = get_request_url;
    am_request.am_get_post_data_f = get_request_body;
    am_request.am_set_post_data_f = set_request_body;
    am_request.am_set_user_f = set_user;
    am_request.am_set_header_in_request_f = set_header_in_request;
    am_request.am_add_header_in_response_f = add_header_in_response;
    am_request.am_set_cookie_f = set_cookie;
    am_request.am_set_custom_response_f = set_custom_response;
    am_request.am_set_method_f = set_method;
    am_request.am_get_request_header_f = get_request_header;

    am_process_request(&am_request);

    result = am_status_value(am_request.status);

    /* json handler for the rest of the unsuccessful exit statuses not processed by set_custom_response */
    if (am_request.is_json_url && !(result == OK || result == DONE || result == DECLINED)) {
        ap_set_content_type(req, "application/json");
        ap_rprintf(req, AM_JSON_TEMPLATE_DATA,
                am_strerror(am_request.status), "\"\"", am_status_value(am_request.status));
        ap_rflush(req);
        result = DONE;
    }

    AM_LOG_DEBUG(config->config_id, "amagent_auth_handler(): exit status: %s (%d)",
            am_strerror(am_request.status), am_request.status);

    am_config_free(&am_request.conf);
    am_request_free(&am_request);

    return result;
}

static void amagent_auth_post_insert_filter(request_rec *req) {
    ap_add_input_filter(amagent_post_filter_name, NULL, req, req->connection);
}

static apr_status_t amagent_post_filter(ap_filter_t *f, apr_bucket_brigade *bucket_out,
        ap_input_mode_t emode, apr_read_type_e eblock, apr_off_t nbytes) {
    static const char *thisfunc = "amagent_post_filter():";
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_status_t ret;
    char buferr[50];
    const char *file_name = apr_table_get(r->notes, amagent_post_filter_name);

    amagent_filter_ctx *state = f->ctx;

    if (ISINVALID(file_name)) {
        return ap_get_brigade(f->next, bucket_out, emode, eblock, nbytes);
    }

    if (state == NULL) {
        apr_finfo_t finfo;

        f->ctx = state = (amagent_filter_ctx *) apr_pcalloc(r->pool, sizeof (amagent_filter_ctx));
        if (state == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, "%s memory allocation error",
                    thisfunc);
            apr_file_remove(file_name, r->pool);
            apr_table_unset(r->notes, amagent_post_filter_name);
            return ap_get_brigade(f->next, bucket_out, emode, eblock, nbytes);
        }

        state->output_ptr = apr_palloc(r->pool, 4000); /* bucket limit of 4K */
        if (state->output_ptr == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, "%s memory allocation error",
                    thisfunc);
            apr_file_remove(file_name, r->pool);
            apr_table_unset(r->notes, amagent_post_filter_name);
            return ap_get_brigade(f->next, bucket_out, emode, eblock, nbytes);
        }

        ret = apr_file_open(&state->tmp_file, file_name, APR_FOPEN_READ | APR_FOPEN_BINARY,
                APR_OS_DEFAULT, r->pool);
        if (ret != APR_SUCCESS) {
            apr_strerror(ret, buferr, sizeof (buferr));
            ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, "%s unable to open POST preservation file: %s, %s",
                    thisfunc, file_name, buferr);
            apr_file_remove(file_name, r->pool);
            apr_table_unset(r->notes, amagent_post_filter_name);
            return ap_get_brigade(f->next, bucket_out, emode, eblock, nbytes);
        }

        ret = apr_file_info_get(&finfo, APR_FINFO_SIZE, state->tmp_file);
        state->size = finfo.size;
        state->output_sent = 0;
        state->done_writing = 0;
    }

    if (state->done_writing == 1) {
        apr_file_remove(file_name, r->pool);
        apr_table_unset(r->notes, amagent_post_filter_name);
        return ap_get_brigade(f->next, bucket_out, emode, eblock, nbytes);
    }

    if (state->output_sent < state->size) {
        apr_bucket *pbktOut;
        apr_size_t len = 4000;

        if (len > (apr_size_t) nbytes) len = (apr_size_t) nbytes;

        if (state->size - state->output_sent < len) len = state->size - state->output_sent;

        ret = apr_file_read(state->tmp_file, state->output_ptr, &len);
        if (ret != APR_SUCCESS) {
            apr_strerror(ret, buferr, sizeof (buferr));
            ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, "%s unable to read POST preservation file: %s, %s",
                    thisfunc, file_name, buferr);
            apr_file_close(state->tmp_file);
            apr_file_remove(file_name, r->pool);
            apr_table_unset(r->notes, amagent_post_filter_name);
            return ap_get_brigade(f->next, bucket_out, emode, eblock, nbytes);
        }

        pbktOut = apr_bucket_heap_create(state->output_ptr, len, NULL, c->bucket_alloc);
        state->output_sent += (int) len;

        APR_BRIGADE_INSERT_TAIL(bucket_out, pbktOut);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "%s sent %ld bytes (%d total)",
                thisfunc, len, state->output_sent);
    }

    /* are we done yet? */
    if (state->output_sent == state->size) {
        /* send an EOS bucket, we're done */
        apr_bucket *pbktOut = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bucket_out, pbktOut);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "%s sent EOS bucket", thisfunc);
        state->done_writing = 1;

        /* nothing left for us to do in this request */
        ap_remove_input_filter(f);

        apr_file_close(state->tmp_file);
        apr_file_remove(file_name, r->pool);
        apr_table_unset(r->notes, amagent_post_filter_name);
    }

    return APR_SUCCESS;
}

static int amagent_preserve_url(request_rec *r) {
    static const char *thisfunc = "amagent_preserve_url():";
    int i;
    request_rec *prev, *main;
#define AM_REQUEST_CHAIN_LIMIT 5

    const char* url = apr_table_get(r->notes, amagent_preserve_url_hook_name);
    if (url != NULL) return DECLINED;


    /* Go down the prev chain to see if this request was a rewrite
     * from another one.  We want to store the uri the user passed in,
     * not the one it was rewritten to */
    prev = r->prev;
    for (i = 0; (url == NULL) && (prev != NULL) && (i < AM_REQUEST_CHAIN_LIMIT);
            ++i, prev = prev->prev) {
        url = apr_table_get(prev->notes, amagent_preserve_url_hook_name);
    }

    /* Do the same for main chain as well (mod_dir internal redirects) */
    main = r->main;
    for (i = 0; (url == NULL) && (main != NULL) && (i < AM_REQUEST_CHAIN_LIMIT);
            ++i, main = main->main) {
        url = apr_table_get(main->notes, amagent_preserve_url_hook_name);
    }

    /* Look into unparsed_uri to check if it is an absolute or relative url/uri.
     * ap_construct_url() works on relative uri values.
     */
    if (url == NULL) {
#ifdef _WIN32
        if (_strnicmp(r->unparsed_uri,
#else
        if (strncasecmp(r->unparsed_uri,
#endif
                "http", 4) == 0) {
            url = apr_pstrdup(r->pool, r->unparsed_uri);
        } else {
            url = ap_construct_url(r->pool, r->unparsed_uri, r);
        }
    }

    if (ISINVALID(url)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
                "%s error parsing request url %s", thisfunc, LOGEMPTY(r->unparsed_uri));
        apr_table_unset(r->notes, amagent_preserve_url_hook_name);
    } else {
        apr_table_set(r->notes, amagent_preserve_url_hook_name, url);
    }
    return DECLINED;
}

static void amagent_register_hooks(apr_pool_t *p) {
#if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER < 3
    ap_hook_access_checker(amagent_auth_handler, NULL, NULL, APR_HOOK_FIRST);
#else
    ap_hook_check_access_ex(amagent_auth_handler, NULL, NULL, APR_HOOK_FIRST, AP_AUTH_INTERNAL_PER_CONF);
#endif
    ap_hook_translate_name(amagent_preserve_url, NULL, NULL, APR_HOOK_FIRST - 2);
    ap_hook_post_config(amagent_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(amagent_worker_init, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_insert_filter(amagent_auth_post_insert_filter, NULL, NULL, APR_HOOK_FIRST);
    ap_register_input_filter(amagent_post_filter_name, amagent_post_filter, NULL, AP_FTYPE_RESOURCE);
}


module AP_MODULE_DECLARE_DATA amagent_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    amagent_srv_config,
    NULL,
    amagent_cmds,
    amagent_register_hooks
};
