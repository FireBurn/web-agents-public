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
#include <setjmp.h>

#include "platform.h"
#include "am.h"
#include "utility.h"
#include "cmocka.h"

typedef am_return_t (* am_state_func_t)(am_request_t *);

void am_test_get_state_funcs(am_state_func_t const ** func_array_p, int * func_array_len_p);
void am_net_init();
void am_net_shutdown();
void am_worker_pool_init_reset();
void am_net_init_ssl_reset();

#define TOKEN_NAME "C-name"
#define TEST_TOKEN_VALUE "AQIC5wM2LY4Sfcyro187TdQ7LJIs373_tJP4Lb2VXBv-Qoc.*AAJTSQACMDEAAlNLABM5MjExNjg2Nzk3Mjg3MjI4MDA2*"

/**
 * Compare only the prefix against the string.
 * Return the result of strncmp, so 0 means no differences, etc.
 */
int compare_prefix(char* prefix, char* string) {
    return strncmp(prefix, string, strlen(prefix));
}

static am_status_t am_get_url_encoded_token_url(struct am_request* request)
{
    char* path = "/d/e/f;1=2";

    char* token = TEST_TOKEN_VALUE;

    char* url = NULL;
    am_asprintf(&url, "http://a.b.c:80/%s?g=h&%s=%s&i=j", path, TOKEN_NAME, token);
    
    request->orig_url = url;
    
    return AM_SUCCESS;
}

static am_status_t get_valid_path_url(struct am_request* request)
{
    char* path = "/x/y/../../d/e/f";

    char* encoded_token = url_encode(TEST_TOKEN_VALUE);

    char* url = NULL;
    am_asprintf(&url, "http://a.b.c:80/%s?g=h&%s=%s&i=j", path, TOKEN_NAME, encoded_token);
    request->orig_url = url;
    
    return AM_SUCCESS;
}

static am_status_t get_invalid_path_url(struct am_request* request)
{
    char* path = "/x/../../../d/e/f";
    
    char* encoded_token = url_encode(TEST_TOKEN_VALUE);
    
    char* url = NULL;
    am_asprintf(&url, "http://a.b.c:80/%s?g=h&%s=%s&i=j", path, TOKEN_NAME, encoded_token);
    request->orig_url = url;
    
    return AM_SUCCESS;
}


static am_status_t am_get_SAML_post_url(struct am_request* request)
{
    /* note that the parser does not accept namespaces and it does not normalize character content.*/
    
    char* saml =
    "<x xmlns:saml=\"http:/w3c.org/nonsense#id\">"
    "<saml:NameIdentifier>"TEST_TOKEN_VALUE"</saml:NameIdentifier>"
    "</x>";
    
    char* url = NULL;
    size_t len = strlen(saml);
    char* base64XML = base64_encode(saml, &len);
    
    am_asprintf(&url, "http://a.b.c:80/d/e/f?g=h&LARES=%s&i=j", base64XML);
    
    request->orig_url = url;
    
    return AM_SUCCESS;
}

/*****************************************************************************************************/

void test_setup_with_simple_token(void **state) {

    am_state_func_t const* func_array = NULL;
    int array_len = 0;    
    am_state_func_t setup;
    
    struct ctx {
        void *dummy;
    } ctx;
    
    am_config_t config = {
        .instance_id            = 0,
        .agenturi               = "https://www.override.com:90/am",
        
        .override_protocol      = AM_TRUE,
        .override_host          = AM_TRUE,
        .override_port          = AM_FALSE,
        
        .cookie_name            = TOKEN_NAME,
        
        .resolve_client_host    = 0,
    };
    
    am_request_t request = {
        .instance_id            = 0,
        .conf                   = &config,
        .ctx                    = &ctx,
        .am_get_request_url_f   = am_get_url_encoded_token_url,
        
        .client_ip              = "209.173.53.167",
        .client_host            = "d.e.f",
        
        .method                 = AM_REQUEST_GET,
        .token                  = NULL,
    };
    
    am_test_get_state_funcs(&func_array, &array_len);
    setup = func_array [0];
    
    am_net_init();
    
    assert_int_equal(setup(&request), AM_OK);
    assert_int_equal(compare_prefix("https://www.override.com:80/d/e/f", request.overridden_url), 0);
    assert_string_equal(TEST_TOKEN_VALUE, request.token);
    
    am_net_shutdown();
    am_net_init_ssl_reset();
}



void test_setup_with_valid_path(void **state) {

    am_state_func_t const* func_array = NULL;
    int array_len = 0;
    am_state_func_t setup;
    
    struct ctx {
        void *dummy;
    } ctx;
        
    am_config_t config = {
        .instance_id            = 0,
        .agenturi               = "https://www.override.com:90/am",
        
        .override_protocol      = AM_TRUE,
        .override_host          = AM_TRUE,
        .override_port          = AM_FALSE,
        
        .cookie_name            = TOKEN_NAME,
        
        .resolve_client_host    = 0,
    };
    
    am_request_t request = {
        .instance_id            = 0,
        .conf                   = &config,
        .ctx                    = &ctx,
        .am_get_request_url_f   = get_valid_path_url,
        
        .client_ip              = "2001:5c0:9168:0:0:0:0:1",
        .client_host            = "d.e.f:8090",
        
        .method                 = AM_REQUEST_GET,
        .token                  = NULL,
    };
    
    am_test_get_state_funcs(&func_array, &array_len);
    setup = func_array [0];
    
    am_net_init();
    
    assert_int_equal(setup(&request), AM_OK);
    assert_int_equal(compare_prefix("https://www.override.com:80/d/e/f", request.overridden_url), 0);
    assert_string_equal("/d/e/f", request.url.path);
    assert_string_equal("?g=h&i=j", request.url.query);
    assert_string_equal(url_encode(TEST_TOKEN_VALUE), request.token);
    
    am_net_shutdown();
    am_net_init_ssl_reset();
}



void test_setup_with_invalid_path(void **state) {

    am_state_func_t const* func_array = NULL;
    int array_len = 0;
    am_state_func_t setup;
    
    struct ctx {
        void *dummy;
    } ctx;
    
    am_config_t config = {
        .instance_id            = 0,
        .agenturi               = "https://www.override.com:90/am",
        
        .override_protocol      = AM_TRUE,
        .override_host          = AM_TRUE,
        .override_port          = AM_FALSE,
        
        .cookie_name            = TOKEN_NAME,
        
        .resolve_client_host    = 0,
    };
    
    am_request_t request = {
        .instance_id            = 0,
        .conf                   = &config,
        .ctx                    = &ctx,
        .am_get_request_url_f   = get_invalid_path_url,
        
        .client_ip              = "2001:5c0:9168:0:0:0:0:1",
        .client_host            = "d.e.f:8080",
        
        .method                 = AM_REQUEST_GET,
        .token                  = NULL,
    };
    
    am_test_get_state_funcs(&func_array, &array_len);
    setup = func_array [0];
    
    am_net_init();
    
    /* this should fail because the invalid path tried to refer outside of the root */
    assert_int_equal(setup(&request), AM_FAIL);
    
    am_net_shutdown();
    am_net_init_ssl_reset();
}


void test_setup_with_SAML_token(void **state) {

    am_state_func_t const* func_array = NULL;
    int array_len = 0;
    am_state_func_t setup;
    
    struct ctx {
        void *dummy;
    } ctx;
    
    am_config_t config = {
        .instance_id            = 0,
        .agenturi               = "https://www.override.com:90/am",
        
        .override_protocol      = AM_TRUE,
        .override_host          = AM_FALSE,
        .override_port          = AM_TRUE,
        
        .cookie_name            = TOKEN_NAME,
        
        .cdsso_enable           = 1,
        
        .resolve_client_host    = 0,
    };
    
    am_request_t request = {
        .instance_id            = 0,
        .conf                   = &config,
        
        .ctx                    = &ctx,
        .am_get_request_url_f   = am_get_SAML_post_url,
        
        .client_ip              = "209.173.53.167,09.173.53.168",
        .client_host            = "d.e.f:37289423,g.h.i",
        
        .method                 = AM_REQUEST_POST,
        .content_type           = "application/xml",
        .token                  = NULL,
    };
    
    am_test_get_state_funcs(&func_array, &array_len);
    setup = func_array [0];
    
    am_net_init();
    
    assert_int_equal(setup(&request), AM_OK);
    assert_int_equal(compare_prefix("https://a.b.c:90/d/e/f", request.overridden_url), 0);
    assert_string_equal(TEST_TOKEN_VALUE, request.token);
    assert_string_equal("209.173.53.167", request.client_ip);
    assert_string_equal("d.e.f", request.client_host);
    
    am_net_shutdown();
    am_net_init_ssl_reset();
}



/*
 * note: this test requires an Internet connection since it contacts a DNS server to verify the client host
 */
void test_setup_with_resolve_host(void **state) {

    am_state_func_t const* func_array = NULL;
    int array_len = 0;
    am_state_func_t setup;
    
    struct ctx {
        void *dummy;
    } ctx;
    
    am_config_t config = {
        .instance_id            = 0,
        .agenturi               = "https://www.override.com:90/am",
        
        .override_protocol      = AM_TRUE,
        .override_host          = AM_TRUE,
        .override_port          = AM_FALSE,
        
        .cookie_name            = TOKEN_NAME,
        
        .resolve_client_host    = 1,
    };
    
    am_request_t request = {
        .instance_id            = 0,
        .conf                   = &config,
        .ctx                    = &ctx,
        .am_get_request_url_f   = get_valid_path_url,
        
        .client_ip              = "2001:4860:4860::8888,2001:5c0:9168:0:0:0:0:1",
        .client_host            = "www.google.com",
        
        .method                 = AM_REQUEST_GET,
        .token                  = NULL,
    };
    
    am_test_get_state_funcs(&func_array, &array_len);
    setup = func_array [0];
    
    am_net_init();
    
    assert_int_equal(setup(&request), AM_OK);
    assert_int_equal(compare_prefix("https://a.b.c:90/d/e/f", request.overridden_url), 0);
    assert_string_equal("/d/e/f", request.url.path);
    assert_string_equal("?g=h&i=j", request.url.query);
    assert_string_equal("google-public-dns-a.google.com", request.client_host);
    assert_string_equal(url_encode(TEST_TOKEN_VALUE), request.token);
    
    am_net_shutdown();
    am_net_init_ssl_reset();
}
