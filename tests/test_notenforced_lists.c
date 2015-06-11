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
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include "platform.h"
#include "am.h"
#include "utility.h"
#include "cmocka.h"


typedef am_return_t (* am_state_func_t)(am_request_t *);
void am_test_get_state_funcs(am_state_func_t const ** func_array_p, int * func_array_len_p);
am_status_t ip_address_match(const char *ip, const char **list, unsigned int listsize, unsigned long instance_id);

#define array_of(a) ((const char *[]){ a })
#define array_len(a) ( (&a) [1] - a )

#define test_cidr(expect, addr, range) do \
{ \
assert_int_equal(ip_address_match(addr, array_of(range), 1, 0l), expect ? AM_SUCCESS : AM_NOT_FOUND); \
} while (0)

#define test_hyphenated(expect, addr, range) do \
{ \
assert_int_equal(ip_address_match(addr, array_of(range), 1, 0l), expect ? AM_SUCCESS : AM_NOT_FOUND); \
} while (0)


void test_ip_ranges(void **state) {

    (void)state;

    /* V4 */
    
    test_cidr(          1,  "192.168.0.25",                     "192.168.0.0/24");
    test_hyphenated(    0,  "192.168.0.25",                     "192.168.0.0-192.168.0.23");

    test_cidr(          0,  "192.153.0.0",                      "192.168.0.0/24");
    test_hyphenated(    0,  "192.153.0.0",                      "192.168.0.0-192.168.0.23");
    test_hyphenated(    0,  "192.153.0.23",                     "192.168.0.0-192.168.0.23");
    
    test_hyphenated(    1,  "192.153.0.23",                     "192.153.0.0-192.168.0.23");

    /* V6 */
    
    test_cidr(          0,  "2001:8c0:9168:0:0:0:0:2",          "2001:5c0:9168:/48");
    test_hyphenated(    0,  "2001:8c0:9168:0:0:0:0:2",          "2001:5c0:9168:0:0:0:0:1-2001:5c0:9168:0:0:0:0:2");

    test_cidr(          1,  "2001:5c0:9168:0:0:0:0:3",          "2001:5c0:9168:/48");
    test_hyphenated(    0,  "2001:5c0:9168:0:0:0:0:3",          "2001:5c0:9168:0:0:0:0:1-2001:5c0:9168:0:0:0:0:2");
    test_hyphenated(    1,  "2001:5c0:9168:0:0:0:0:1",          "2001:5c0:9168:0:0:0:0:1-2001:5c0:9168:0:0:0:0:2");
    
    test_cidr(          1,  "ffff:ffff:0:0:0:0:0:0",            "ffff:ffff:/32");
    test_cidr(          0,  "ffff:ffff:0:0:0:0:0:0",            "ffff:ffff:ffff:/33");
    test_cidr(          1,  "ffff:ffff:8000:0:0:0:0:0",         "ffff:ffff:ffff:/33");
}



static void test_range_ip4_notenforced(void **state) {

    am_state_func_t const * func_array = NULL;
    int array_len = 0;
    am_state_func_t notenforced_handler;
    
    struct am_config_map not_enforced_ips [] = {
        { "", "192.153.0.0-192.168.0.23" },
    };
    
    struct ctx {
        void *dummy;
    } ctx;
    
    am_config_t config = {
        .instance_id                = 0,
        .notif_enable               = AM_TRUE,
        .notif_url                  = "https://www.notify.com:1234/am",
        .override_notif_url         = AM_TRUE,
        
        .url_eval_case_ignore       = AM_FALSE,
        
        .not_enforced_ip_map_sz     = array_len(not_enforced_ips),
        .not_enforced_ip_map        = not_enforced_ips,
        
        .not_enforced_fetch_attr    = 0,
        
        .not_enforced_map_sz        = 0,
        .not_enforced_ext_map_sz    = 0,
        .logout_map_sz              = 0,
    };
    
    am_request_t request = {
        .instance_id                = 0,
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = NULL,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.notify.com:90/am",
        
        .client_ip                  = "192.153.0.23", /* in the ip v4 range */
    };
    
    am_test_get_state_funcs(&func_array, &array_len);
    notenforced_handler = func_array [5];
    
    parse_url("http://www.url.com/path", &request.url);
    
    assert_int_equal(notenforced_handler(&request), AM_QUIT);
    assert_int_equal(request.not_enforced, AM_TRUE);
}



void test_cidr_ip6_notenforced_fetch_attr(void **state) {

    am_state_func_t const * func_array = NULL;
    int array_len = 0;
    am_state_func_t notenforced_handler;
    
    struct am_config_map not_enforced_ips [] = {
        { "", "2001:5c0:9168:0:0:0:0:1-2001:5c0:9168:0:0:0:0:2" },
        { "", "2001:5c0:9168:/48" },
    };
    
    struct ctx {
        void *dummy;
    } ctx;
    
    am_config_t config = {
        .instance_id                = 0,
        .notif_enable               = AM_TRUE,
        .notif_url                  = "https://www.notify.com:1234/am",
        .override_notif_url         = AM_TRUE,
        
        .url_eval_case_ignore       = AM_FALSE,
        
        .not_enforced_ip_map_sz     = array_len(not_enforced_ips),
        .not_enforced_ip_map        = not_enforced_ips,
        
        .not_enforced_fetch_attr    = 1,
        
        .not_enforced_map_sz        = 0,
        .not_enforced_ext_map_sz    = 0,
        .logout_map_sz              = 0,
    };
    
    am_request_t request = {
        .instance_id                = 0,
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = NULL,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.notify.com:90/am",
        
        .client_ip                  = "2001:5c0:9168:0:0:0:0:3", /* only in the masked range */
    };
    
    am_test_get_state_funcs(&func_array, &array_len);
    notenforced_handler = func_array [5];
    
    parse_url("http://www.url.com/path", &request.url);
    
    assert_int_equal(notenforced_handler(&request), AM_OK);
    assert_int_equal(request.not_enforced, AM_TRUE);
}



void test_cidr_ip6_notenforced_get(void **state) {

    am_state_func_t const * func_array = NULL;
    int array_len = 0;
    am_state_func_t notenforced_handler;
    
    struct am_config_map not_enforced_ips[] = {
        { "GET,",   "2001:5c0:9168:0:0:0:0:1-2001:5c0:9168:0:0:0:0:2" },
        { "POST,",  "2001:6c0:9168:/48" },
    };
    
    struct ctx {
        void *dummy;
    } ctx;
    
    am_config_t config = {
        .instance_id                = 0,
        .notif_enable               = AM_TRUE,
        .notif_url                  = "https://www.notify.com:1234/am",
        .override_notif_url         = AM_TRUE,
        
        .url_eval_case_ignore       = AM_FALSE,
        
        .not_enforced_ip_map_sz     = array_len(not_enforced_ips),
        .not_enforced_ip_map        = not_enforced_ips,

        .not_enforced_fetch_attr    = 1,

        .not_enforced_map_sz        = 0,
        .not_enforced_ext_map_sz    = 0,
        .logout_map_sz              = 0,
    };
    
    am_request_t request = {
        .instance_id                = 0,
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = NULL,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.notify.com:90/am",
        
        .client_ip                  = "2001:5c0:9168:0:0:0:0:2", /* not in the range for posts */
    };
    
    am_test_get_state_funcs(&func_array, &array_len);
    notenforced_handler = func_array [5];
    
    parse_url("http://www.url.com/path", &request.url);
    
    assert_int_equal(notenforced_handler(&request), AM_FAIL);
    assert_int_equal(request.not_enforced, AM_FALSE);
}



void test_url_notenforced_get(void **state) {

    am_state_func_t const * func_array = NULL;
    int array_len = 0;
    am_state_func_t notenforced_handler;
    
    struct ctx {
        void *dummy;
    } ctx;
    
    struct am_config_map not_enforced_ips[] = {
        { "GET,0",   "2001:5c0:9168:0:0:0:0:1-2001:5c0:9168:0:0:0:0:2" },
        { "POST,0",  "2001:5c0:9168:/48" },
    };
    
    struct am_config_map not_enforced_map[] = {
        { "GET,0",   ".+://\\.+" },
        { "POST,0",  "https://www\\..+/path.*" },
    };
    
    am_config_t config = {
        .instance_id                = 0,
        .notif_enable               = AM_TRUE,
        .notif_url                  = "https://www.notify.com:1234/am",
        .override_notif_url         = AM_TRUE,
        
        .url_eval_case_ignore       = AM_FALSE,
        .access_denied_url          = "https://www.access.com/deny",
        
        .not_enforced_ip_map_sz     = array_len(not_enforced_ips),
        .not_enforced_ip_map        = not_enforced_ips,
        
        .not_enforced_fetch_attr    = 1,
        
        .not_enforced_map_sz        = array_len(not_enforced_map),
        .not_enforced_map           = not_enforced_map,
        
        .not_enforced_invert        = 0,
        
        .not_enforced_ext_map_sz    = 0,
        .logout_map_sz              = 0,
    };
    
    am_request_t request = {
        .instance_id                = 0,
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = NULL,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.url.com/path",
        
        .client_ip                  = "2001:6c0:9168:0:0:0:0:2", /* not in any ip range */
    };
    
    am_test_get_state_funcs(&func_array, &array_len);
    notenforced_handler = func_array [5];
    
    parse_url("http://www.url.com/path", &request.url);
    
    assert_int_equal(notenforced_handler(&request), AM_OK);
    assert_int_equal(request.not_enforced, AM_TRUE);
}


void test_deny_url_notenforced_get(void **state) {

    am_state_func_t const * func_array = NULL;
    int array_len = 0;
    am_state_func_t notenforced_handler;
    
    struct am_config_map not_enforced_ips[] = {
        { "GET,0",   "2001:5c0:9168:0:0:0:0:1-2001:5c0:9168:0:0:0:0:2" },
        { "POST,0",  "2001:5c0:9168:/48" },
    };
    
    struct am_config_map not_enforced_map[] = {
        { "GET,0",   "https://www.url.com:90/path" },
        { "POST,0",  "https://www.url.com/path" },
    };
    
    struct ctx {
        void *dummy;
    } ctx;
    
    am_config_t config = {
        .instance_id                = 0,
        .notif_enable               = AM_TRUE,
        .notif_url                  = "https://www.notify.com:1234/am",
        .override_notif_url         = AM_TRUE,
        
        .url_eval_case_ignore       = AM_FALSE,
        .access_denied_url          = "https://www.access.com/deny",
        
        .not_enforced_ip_map_sz     = array_len(not_enforced_ips),
        .not_enforced_ip_map        = not_enforced_ips,
        
        .not_enforced_fetch_attr    = 1,
        
        .not_enforced_map_sz        = array_len(not_enforced_map),
        .not_enforced_map           = not_enforced_map,
        
        .not_enforced_invert        = 0,

        .not_enforced_ext_map_sz    = 0,
        .logout_map_sz              = 0,
    };
    
    am_request_t request = {
        .instance_id                = 0,
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = NULL,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.access.com/deny",
        
        .client_ip                  = "2001:6c0:9168:0:0:0:0:2", /* not in any ip range */
    };
    
    am_test_get_state_funcs(&func_array, &array_len);
    notenforced_handler = func_array [5];
    
    parse_url("https://www.access.com/deny", &request.url); /* this is the access-denied url */
    
    assert_int_equal(notenforced_handler(&request), AM_OK);
    assert_int_equal(request.not_enforced, AM_TRUE);
}
