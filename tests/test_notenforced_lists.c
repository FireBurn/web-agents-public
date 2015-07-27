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



// this is in ip.c, as an alternative to inet_net_pton, which is not protable and seems faulty.
int ipv6_pton(const char * p, struct in6_addr * n);

#ifdef _WIN32
int inet_net_pton(int af, const char * src, void * dst, size_t size)
{
    return -1;
}
#endif

/*
 * (i) the output of ipv6_pton is as expected.
 *
 * (ii) also tests that the masked binary can be round-tripped - i.e. converted to a presentation
 * address and then to exactly the same binary with no bits masked. This checks that the masking is correct.
 */
static void ipv6_compare(int expected, const char * p)
{
    char buffer [INET6_ADDRSTRLEN];
    char ctl_buffer [INET6_ADDRSTRLEN];
    
    struct in6_addr addr;
    int bits = ipv6_pton(p, &addr);
    
    struct in6_addr ctl_addr;
    memset(&ctl_addr, 0, sizeof(ctl_addr));
    int ctl_bits = inet_net_pton(AF_INET6, p, &ctl_addr, sizeof(ctl_addr));
    
    if (bits != ctl_bits)
    {
        printf("different results: inet_net_pton returns %d\n", ctl_bits);
        ipv6_pton(p, &addr);
    }
    
    if (bits != -1)
    {
        struct in6_addr addr2;
        inet_ntop(AF_INET6, &addr, buffer, INET6_ADDRSTRLEN);
        
        // roundtrip
        ipv6_pton(buffer, &addr2);
        assert_int_equal(memcmp(&addr, &addr2, sizeof(addr)), 0);
        
        //inet_net_ntop(AF_INET6, &addr, bits, buffer, sizeof(buffer));
        printf("%s -> %s\n", p, buffer);
    }
    
    if (ctl_bits != -1)
    {
        inet_ntop(AF_INET6, &ctl_addr, ctl_buffer, INET6_ADDRSTRLEN);
        //inet_net_ntop(AF_INET6, &ctl_addr, ctl_bits, ctl_buffer, sizeof(ctl_buffer));
        printf("%s -> %s (control)\n", p, ctl_buffer);
    }
    
    if (bits != -1 && ctl_bits != -1)
    {
        if (strcmp(buffer, ctl_buffer) != 0)
        {
            printf("different presentations %s\n", ctl_buffer);
            ipv6_pton(p, &addr);
        }
        
        if (memcmp(&addr, &ctl_addr, sizeof(addr)) != 0)
        {
            printf("different binaries\n");
            ipv6_pton(p, &addr);
        }
    }
    printf("--------\n");
    assert_int_equal(expected, bits);
}

static void test_ip6()
{
    ipv6_compare(32,  "::/32");
    ipv6_compare(128, "2001:db8:0:0:0:0:2:1");
    ipv6_compare(128, "2001:db8::2:1");
    ipv6_compare(96,  "::ffff:0:0:0/96");            // inet_net_ntop is wrong about this
    ipv6_compare(28,  "2001:20::/28");               // ORCHIDv2 (Overlay Routable Cryptographic Hash Identifiers). inet_net_pton says they are invalid
    ipv6_compare(10,  "fe80::/10");
    
    ipv6_compare(-1,  "ffff:ffff:ffff:");            // neither allow this
    ipv6_compare(-1,  "ffff:ffff:ffff/33");          // inet_net_pton allows this
    ipv6_compare(-1,  "ffff:ffff:ffff:/33");         // inet_net_pton allows this
    
    ipv6_compare(33,  "ffff:ffff:ffff::/33");        // inet_net_pton does not allow this, with contraction
    ipv6_compare(34,  "ffff:ffff:ffff::/34");        // inet_net_pton does not allow this, with contraction
    ipv6_compare(35,  "ffff:ffff:ffff::/35");        // inet_net_pton does not allow this, with contraction
    
    ipv6_compare(35,  "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/35"); // inet_net_pton fails this
    ipv6_compare(35,  "fe:fe:fe:fe:fe:fe:fe:fe/35"); // inet_net_pton fails this
    
    ipv6_compare(128,  "::");
    ipv6_compare(-1,   "::/256");
    
    ipv6_compare(128,  "::13.1.68.3");
    ipv6_compare(128,  "::FFFF:129.144.52.38");
}

void test_ip6_addresses(void ** state) {
    (void)state;
    
    test_ip6();
}

void test_ip_ranges(void ** state) {
    (void)state;
    
    // V4
    
    test_cidr(          1,  "192.168.0.25",                     "192.168.0.0/24");
    test_hyphenated(    0,  "192.168.0.25",                     "192.168.0.0-192.168.0.23");
    
    test_cidr(          0,  "192.153.0.0",                      "192.168.0.0/24");
    test_hyphenated(    0,  "192.153.0.0",                      "192.168.0.0-192.168.0.23");
    test_hyphenated(    0,  "192.153.0.23",                     "192.168.0.0-192.168.0.23");
    
    test_hyphenated(    1,  "192.153.0.23",                     "192.153.0.0-192.168.0.23");
    
    test_cidr(          1,  "127.0.1.25",                       "127.0.1.0/16");
    test_hyphenated(    1,  "127.0.1.25",                       "127.0.1.0-127.0.1.26");
    
    // bad ranges
    test_cidr(          1,  "127.0.1.25",                       "127.0.1.25/0");
    test_hyphenated(    0,  "172.18.1.10",                      "172.18.1.10-172.17.1.1");
    
    test_cidr(          1,  "172.18.55.21",                     "172.18.0.0/16");
    test_cidr(          1,  "172.18.55.48",                     "172.18.1.0/16");
    
    // V6
    
    test_cidr(          0,  "2001:8c0:9168:0:0:0:0:2",          "2001:5c0:9168::/48");
    test_hyphenated(    0,  "2001:8c0:9168::2",                 "2001:5c0:9168::1-2001:5c0:9168::2");
    
    test_cidr(          1,  "2001:5c0:9168:0:0:0:0:3",          "2001:5c0:9168::/48");
    test_hyphenated(    0,  "2001:5c0:9168:0:0:0:0:3",          "2001:5c0:9168::1-2001:5c0:9168::0:0:0:2");
    test_hyphenated(    1,  "2001:5c0:9168:0:0:0:0:1",          "2001:5c0:9168::1-2001:5c0:9168::2");
    
    test_cidr(          1,  "ffff:ffff:0:0:0:0:0:0",            "ffff:ffff::/32");
    test_cidr(          0,  "ffff:ffff:0:0:0:0:0:0",            "ffff:ffff:ffff::/33");
    test_cidr(          1,  "ffff:ffff:8000::",                 "ffff:ffff:ffff::/33");
    test_cidr(          1,  "ffff:ffff:e000::",                 "ffff:ffff:ffff::/35");
    
    test_cidr(          1,  "ffff:ffff:f000:0:0:0:0:0",        "ffff:ffff:ffff::/35");
    test_cidr(          0,  "fffff:ffff:f000:0:0:0:0:0",        "ffff:ffff:ffff::/35");
    
    test_cidr(          0,  "ffff:ffff:8000:0:0:0:0:0",         "ffff:ffff:ffff::/126");
    test_cidr(          0,  "ffff:ffff:8000:0:0:0:0:0",         "ffff:ffff:ffff::/128");
    
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
        { "", "2001:5c0:9168::/48" },
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
        { "GET,",   "2001:5c0:9168::1-2001:5c0:9168::2" },
        { "POST,",  "2001:6c0:9168::/48" },
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
        { "POST,0",  "2001:5c0:9168::/48" },
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
        
        .client_ip                  = "2001:6c0:9168::2", /* not in any ip range */
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
        { "POST,0",  "2001:5c0:9168::/48" },
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
