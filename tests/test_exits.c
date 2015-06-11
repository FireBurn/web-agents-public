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

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>

#include "platform.h"
#include "am.h"
#include "utility.h"
#include "list.h"
#include "cmocka.h"

#define array_len(a) ( (&a) [1] - a )

typedef am_return_t (* am_state_func_t)(am_request_t *);

void am_test_get_state_funcs(am_state_func_t const ** func_array_p, int * func_array_len_p);

struct cookie_table
{
    int c;
    char * keys [1024];
    char * values [1024];
};

struct cookie_ctx
{
    struct cookie_table in, out, err_out;
};

#define TOKEN_NAME "C-name"
#define TOKEN_VALUE "AQIC5wM2LY4Sfcyro187TdQ7LJIs373_tJP4Lb2VXBv-Qoc.*AAJTSQACMDEAAlNLABM5MjExNjg2Nzk3Mjg3MjI4MDA2*"

static const char * cookie_table_get(struct cookie_table * table, const char * key)
{
    int i;
    for (i = 0; i < table->c; i++)
        if (strcmp(table->keys [i], key) == 0)
            return table->values [i];
    
    return 0;
}

static void cookie_table_add(struct cookie_table * table, const char * key, const char * value)
{
    int i = 0;
    while (i < table->c && table->keys [i])
        i++;
    
    if (i < array_len(table->keys))
    {
        table->keys [i] = strdup(key);
        table->values [i] = strdup(value);
        
        if (i == table->c)
            table->c++;
    }
}

static void cookie_table_clear(struct cookie_table * table)
{
    int i;
    for (i = 0; i < table->c; i++)
        if (table->keys [i])
        {
            free(table->keys [i]);
            table->keys [i] = 0;
            
            free(table->values [i]);
            table->values [i] = 0;
        }
    
    table->c = 0;
}

static void cookie_table_set(struct cookie_table * table, const char * key, const char * value)
{
    int i;
    int c = 0;
    
    for (i = 0; i < table->c; i++)
        if (table->keys [i] && strcmp(table->keys [i], key) == 0)
        {
            free(table->values [i]);
            table->values [i] = strdup(value);
            c++;
        }
    
    if (c == 0)
        cookie_table_add(table, key, value);
}

static void cookie_table_unset(struct cookie_table * table, const char * key)
{
    int i;
    for (i = 0; i < table->c; i++)
        if (strcmp(table->keys [i], key) == 0)
        {
            free(table->keys [i]);
            table->keys [i] = 0;
            
            free(table->values [i]);
            table->values [i] = 0;
        }
}

void cookie_table_dump(char * title, struct cookie_table * table)
{
    int i;
    int c = 0;
    printf("%s:\n", title);
    fflush(stdout);
    if (table == NULL) {
        printf("table is NULL !!!!\n");
        fflush(stdout);
        return;
    }
    printf("table counter is %d\n", table->c);
    fflush(stdout);

    for (i = 0; i < table->c; i++) {
        if (table->keys [i]) {
            printf("%d: %s -> %s\n", c++, table->keys [i], table->values [i]);
        }
    }
    
    cookie_table_clear(table);
}

static am_status_t am_get_url_encoded_token_url(struct am_request * request)
{
    char * path = "/d/e/f;1=2";
    
    char * token = TOKEN_VALUE;
    
    char * url = NULL;
    am_asprintf(&url, "http://a.b.c:80/%s?g=h&%s=%s&i=j", path, TOKEN_NAME, token);
    
    request->orig_url = url;
    
    return AM_SUCCESS;
}

static am_status_t set_cookie(am_request_t *rq, const char *header) {
    struct cookie_ctx * ctx = rq->ctx;
    
    const char * c;

    cookie_table_add(&ctx->err_out, "Set-Cookie", header);
    c = cookie_table_get(&ctx->in, "Cookie");
    if (c == NULL)
    {
        cookie_table_add(&ctx->in, "Cookie", header);
    }
    else
    {
        char * cookie = NULL;
        am_asprintf(&cookie, "%s;%s", header, c);
        cookie_table_set(&ctx->in, "Cookie", cookie);
        free(cookie);
    }
    return AM_SUCCESS;
}

static am_status_t add_header_in_response(am_request_t *rq, const char *key, const char *value) {
    struct cookie_ctx * ctx = rq->ctx;
    
    if (!ISVALID(value))
    {
        /*value is empty, sdk is setting a cookie in response*/
        return set_cookie(rq, key);
    }
    /* Apache HTTPD keeps two separate server response header tables in the request
     * record — one for normal response headers and one for error headers.
     * The difference between them is the error headers are sent to
     * the client even (not only) on an error response (REDIRECT is one of them)
     */
    cookie_table_add(&ctx->err_out, key, value);
    return AM_SUCCESS;
}

static am_status_t set_header_in_request(struct am_request * rq, const char * key, const char * value)
{
    struct cookie_ctx * ctx = rq->ctx;

    /* remove all instances of the header first */
    cookie_table_unset(&ctx->in, key);
    if (ISVALID(value))
    {
        cookie_table_set(&ctx->in, key, value);
    }
    return AM_SUCCESS;
}

static am_status_t set_custom_response(am_request_t * rq, const char * text, const char * cont_type)
{
    struct cookie_ctx * ctx = rq->ctx;

    am_status_t status = AM_ERROR;
    
    if (!ISVALID(text))
    {
        return AM_EINVAL;
    }
    
    status = rq->status;
    switch (status)
    {
        case AM_JSON_RESPONSE:
        {
            rq->status = AM_DONE;
        }
        break;
        
        case AM_INTERNAL_REDIRECT:
        {
            rq->status = AM_DONE;
        }
        break;
            
        case AM_REDIRECT:
        {
            cookie_table_add(&ctx->out, "Location", text);
        }
        break;
            
        case AM_PDP_DONE:
        {
            printf("set_custom_response(): issuing sub-request %s to %s (%s)",
                         am_method_num_to_str(rq->method), rq->post_data_url, LOGEMPTY(cont_type));
            
            rq->status = AM_SUCCESS;
        }
        break;
            
        default:
        {
            printf("set_custom_response(): setting content %s to %s (%s): %s\n",
                   am_method_num_to_str(rq->method), rq->post_data_url, LOGEMPTY(cont_type), text);
        }
        break;
    }
    
    return AM_SUCCESS;
}

static struct am_namevalue * new_namevalue(char * name, char * value)
{
    struct am_namevalue * el = NULL;
    create_am_namevalue_node(name, strlen(name), value, strlen(value), &el);
    return el;
}


void test_handle_exits_with_success(void **state) {

    am_state_func_t const * func_array = NULL;
    int array_len = 0;
    struct am_namevalue *el;
    struct am_namevalue *sattr = NULL;
    struct am_namevalue *response_decisions = NULL;
    struct am_namevalue *response_attributes = NULL;
    am_state_func_t exit_f;
    
    am_config_map_t session_attr_map [] =
    {
        { "ldap-session-0", "Session-header-0" },
        { "ldap-session-1", "Session-header-1" },
    };
    
    am_config_map_t profile_attr_map [] =
    {
        { "ldap-profile-0", "Profile-header-0" },
        { "ldap-profile-1", "Profile-header-1" },
    };
    
    am_config_map_t response_attr_map [] =
    {
        { "ldap-response-0", "Response-header-0" },
        { "ldap-response-1", "Response-header-1" },
    };
    
    struct cookie_ctx ctx =
    {
        .in = { .c = 0 }, .out = { .c = 0 }
    };
    
    am_config_t config =
    {
        .instance_id                    = 0,
        .agenturi                       = "https://www.override.com:90/am",
        
        .override_protocol              = AM_TRUE,
        .override_host                  = AM_TRUE,
        .override_port                  = AM_FALSE,
        
        .resolve_client_host            = 0,
        
        .cdsso_enable                   = AM_TRUE,
        .cookie_name                    = TOKEN_NAME,
        .cookie_encode_chars            = AM_TRUE,
        
        .profile_attr_fetch             = AM_SET_ATTRS_AS_COOKIE,
        .profile_attr_map_sz            = array_len(profile_attr_map),
        .profile_attr_map               = profile_attr_map,
        
        .session_attr_fetch             = AM_SET_ATTRS_AS_COOKIE,
        .session_attr_map_sz            = array_len(session_attr_map),
        .session_attr_map               = session_attr_map,
        
        .response_attr_fetch            = AM_SET_ATTRS_AS_COOKIE,
        .response_attr_map_sz           = array_len(response_attr_map),
        .response_attr_map              = response_attr_map,
    };
    
    am_request_t request =
    {
        .instance_id                    = 0,
        .conf                           = &config,
        .ctx                            = &ctx,
        
        .am_get_request_url_f           = am_get_url_encoded_token_url,
        
        .client_ip                      = "209.173.53.167",
        .client_host                    = "d.e.f",
        
        .method                         = AM_REQUEST_GET,
        
        .status                         = AM_SUCCESS,
        .am_add_header_in_response_f    = add_header_in_response,
        .am_set_header_in_request_f     = set_header_in_request,
        
        .token                          = TOKEN_VALUE,
        .cookies                        = "GoogleAccountsLocale_session=en;"TOKEN_NAME"="TOKEN_VALUE";a=b;c=d",
        
        .response_attributes            = response_attributes,
        .sattr                          = sattr,
        .response_decisions             = response_decisions,
    };
    
    el = new_namevalue("ldap-session-0", "session-value-0");
    AM_LIST_INSERT(sattr, el);
    el = new_namevalue("ldap-session-1", "session-value-1");
    AM_LIST_INSERT(sattr, el);
    
    el = new_namevalue("ldap-profile-0", "profile-value-0");
    AM_LIST_INSERT(response_decisions, el);
    el = new_namevalue("ldap-profile-1", "profile-value-1");
    AM_LIST_INSERT(response_decisions, el);
    
    el = new_namevalue("ldap-response-0", "response-value-0");
    AM_LIST_INSERT(response_attributes, el);
    el = new_namevalue("ldap-response-1", "response-value-1");
    AM_LIST_INSERT(response_attributes, el);
    
    am_test_get_state_funcs(&func_array, &array_len);
    exit_f = func_array [7];
    
    /* test the function */
    
    assert_int_equal(exit_f(&request), AM_OK);
    
    delete_am_namevalue_list(&response_attributes);
    delete_am_namevalue_list(&sattr);
    delete_am_namevalue_list(&response_decisions);

    cookie_table_dump("headers in", &ctx.in);
    cookie_table_dump("headers out", &ctx.out);
    cookie_table_dump("error headers out", &ctx.err_out);
}


void test_handle_exits_with_access_denied(void **state) {

    am_state_func_t const * func_array = NULL;
    int array_len = 0;
    struct am_namevalue *el;
    struct am_namevalue *sattr = NULL;
    struct am_namevalue *response_decisions = NULL;
    struct am_namevalue *response_attributes = NULL;
    am_state_func_t exit_f;
    
    am_config_map_t session_attr_map [] =
    {
        { "ldap-session-0", "Session-header-0" },
        { "ldap-session-1", "Session-header-1" },
    };
    
    am_config_map_t profile_attr_map [] =
    {
        { "ldap-profile-0", "Profile-header-0" },
        { "ldap-profile-1", "Profile-header-1" },
    };
    
    am_config_map_t response_attr_map [] =
    {
        { "ldap-response-0", "Response-header-0" },
        { "ldap-response-1", "Response-header-1" },
    };
    
    struct cookie_ctx ctx =
    {
        .in = { .c = 0 }, .out = { .c = 0 }
    };
    
    am_config_t config =
    {
        .instance_id                    = 0,
        .agenturi                       = "https://www.override.com:90/am",
        
        .override_protocol              = AM_TRUE,
        .override_host                  = AM_TRUE,
        .override_port                  = AM_FALSE,
        
        .resolve_client_host            = 0,
        
        .pdp_enable                     = AM_TRUE,
        .cdsso_enable                   = AM_TRUE,
        
        .cookie_name                    = TOKEN_NAME,
        .cookie_encode_chars            = AM_TRUE,
        
        .profile_attr_fetch             = AM_SET_ATTRS_AS_COOKIE,
        .profile_attr_map_sz            = array_len(profile_attr_map),
        .profile_attr_map               = profile_attr_map,
        
        .session_attr_fetch             = AM_SET_ATTRS_AS_COOKIE,
        .session_attr_map_sz            = array_len(session_attr_map),
        .session_attr_map               = session_attr_map,
        
        .response_attr_fetch            = AM_SET_ATTRS_AS_COOKIE,
        .response_attr_map_sz           = array_len(response_attr_map),
        .response_attr_map              = response_attr_map,
    };
    
    am_request_t request =
    {
        .instance_id                    = 0,
        .conf                           = &config,
        .ctx                            = &ctx,
        
        .am_get_request_url_f           = am_get_url_encoded_token_url,
        
        .client_ip                      = "209.173.53.167",
        .client_host                    = "d.e.f",
        
        .method                         = AM_REQUEST_POST,
        
        .status                         = AM_ACCESS_DENIED,
        .am_add_header_in_response_f    = add_header_in_response,
        .am_set_header_in_request_f     = set_header_in_request,
        .am_set_custom_response_f       = set_custom_response,
        
        .token                          = TOKEN_VALUE,
        .cookies                        = "GoogleAccountsLocale_session=en;"TOKEN_NAME"="TOKEN_VALUE";a=b;c=d",
        
        .response_attributes            = response_attributes,
        .sattr                          = sattr,
        .response_decisions             = response_decisions,
    };
    
    el = new_namevalue("ldap-session-0", "session-value-0");
    AM_LIST_INSERT(sattr, el);
    el = new_namevalue("ldap-session-1", "session-value-1");
    AM_LIST_INSERT(sattr, el);
    
    el = new_namevalue("ldap-profile-0", "profile-value-0");
    AM_LIST_INSERT(response_decisions, el);
    el = new_namevalue("ldap-profile-1", "profile-value-1");
    AM_LIST_INSERT(response_decisions, el);
    
    el = new_namevalue("ldap-response-0", "response-value-0");
    AM_LIST_INSERT(response_attributes, el);
    el = new_namevalue("ldap-response-1", "response-value-1");
    AM_LIST_INSERT(response_attributes, el);
    
    am_test_get_state_funcs(&func_array, &array_len);
    exit_f = func_array [7];
    
    assert_int_equal(exit_f(&request), AM_OK);
    
    delete_am_namevalue_list(&response_attributes);
    delete_am_namevalue_list(&sattr);
    delete_am_namevalue_list(&response_decisions);
  
    cookie_table_dump("headers in", &ctx.in);
    cookie_table_dump("headers out", &ctx.out);
    cookie_table_dump("error headers out", &ctx.err_out);
}
