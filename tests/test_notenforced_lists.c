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
#include <cmocka.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "am.h"
#include "utility.h"


typedef am_return_t (* am_state_func_t)(am_request_t *);

void am_test_get_state_funcs(am_state_func_t const ** func_array_p, int * func_array_len_p);


int ip_address_match(const char *ip, const char **list, unsigned int listsize, unsigned long instance_id);



/*
 * This is reference code that correctly matches ip v4 and v6 addresses, as well as unit tests for matching
 * ip addresses in notenforced lists.
 *
 * A reference implementation for ip matching from the linux kernel is: http://fxr.watson.org/fxr/ident?v=linux-2.6;i=addr4_match ( see: addr_match(), addr4_match() )
 *
 *
 */

// NOTE: this only works for an array, not a pointer derived from an array
#define array_len(a) ( (&a) [1] - a )

// NOTE: only to simplify the macro below - a typed null pointer
#define np(type) ( (type *)0 )

// the number of 32 bit words (quads) in the network format of an ip v6 address (which will just be 4)
#define IP6_QUADS array_len( np(struct in6_addr)->__u6_addr.__u6_addr32 )

// the number of 32 bit words (quads) in the network format of an ip v4 address
#define IP4_QUADS 1


/*
 * test equivalence masked bits in two ipv4 addresses in network form
 */
static int cidr_match(const struct in_addr * addr, const struct in_addr * net, int bits)
{
    if (bits == 0) {
        // the range is all inclusive - uint32_t << 32 is undefined
        return 1;
    }
    
    // here and in the function below, we are comparing quads (uint32_t) represented in the network byte
    // order. Xor (^) is used to identify differences between the quads, and then << is used to remove the
    // differences outside of the network masks' number of bits.
    
    if ((addr->s_addr ^ net->s_addr) & htonl(0xFFFFFFFFu << (32 - bits))) {
        return 0;
    }
    return 1;
}

/**
 * test masked bits in two ipv6 addresses in network form.
 *
 * see above for an explanation of the bit twiddling code here.
 */
static int cidr6_match(const struct in6_addr * addr, const struct in6_addr * net, int bits)
{
    const uint32_t * a = addr->__u6_addr.__u6_addr32;
    const uint32_t * n = net->__u6_addr.__u6_addr32;

    int quads = bits >> 5; // number of whole quads masked = bits/32
    int remainder = bits & 0x1F;  // number of bits masked in the subsequent quad = bits%32
    
    if (quads)
    {
        if (memcmp(a, n, quads * sizeof(uint32_t)))
            return 0;
    }
    
    if (remainder)
    {
        if ((a [quads] ^ n [quads]) & htonl(0xFFFFFFFFu << (32 - remainder)))
            return 0;
    }
    return 1;
}

/**
 * tests wether the first argument is in the (inclusive) range of V6 addresses from adr_lo to addr_hi
 * return 0 if the address is in the range.
 */
static int cmp_ip_range(const struct in_addr * addr, const struct in_addr * addr_lo, const struct in_addr * addr_hi)
{
    const uint32_t a = addr->s_addr;
    
    const uint32_t lo = addr_lo->s_addr;
    const uint32_t hi = addr_hi->s_addr;
    
    return ntohl(a) < ntohl(lo) ? -1 : ntohl(hi) < ntohl(a) ? 1 : 0;
}

#define cmp(a, b) ((a) < (b) ? -1 : (a) == (b) ? 0 : 1)

/**
 * compares two uint32 arrays in network format (requiring ntohl translation)
 * returns negative if a < b, positive if a > b, 0 if they are equal
 */
static inline int cmp_net(const uint32_t * a, const uint32_t * b)
{
    int i;
    int c = 0;
    for (i = IP6_QUADS; 0 < i--;)
    {
        uint32_t ha = ntohl(a [i]), hb = ntohl(b [i]);
        c = cmp(ha, hb);
        if (c)
            break;
    }
    return c;
}

/**
 * tests wether the first argument is in the (inclusive) range of V6 addresses from adr_lo to addr_hi
 * return 0 if the address is in the range, negative if below the range, positive if its above
 */
static int cmp_ip6_range(const struct in6_addr * addr, const struct in6_addr * addr_lo, const struct in6_addr * addr_hi)
{
    int c;
    
    c = cmp_net(addr_lo->__u6_addr.__u6_addr32, addr->__u6_addr.__u6_addr32);
    if (0 < c)
        return -1;
    
    c = cmp_net(addr->__u6_addr.__u6_addr32, addr_hi->__u6_addr.__u6_addr32);
    if (0 < c)
        return 1;
    
    return 0;
}

/*
 * initialise and read an ip v4 presentation, returning in bpits the number of bits on
 * returns 0 if the presentation cannot be read as an ip v4 address in CIDR notation
 */
static int read_ip(const char * p, struct in_addr * n, int * pbits)
{
    memset(n, 0, sizeof(struct in_addr));
    * pbits = inet_net_pton(AF_INET, p, n, sizeof(struct in_addr));
    
    if (* pbits == -1)
    {
        return 0;
    }
    return 1;
}

/*
 * read an ip v4 presentation p, expecting all bits to be masked, i.e. not a range
 * returns 0 if the presentation is not ip v4, or if it is a CIDR range
 */
static int read_full_ip(const char * p, struct in_addr * n)
{
    int mask;
    if (read_ip(p, n, &mask))
    {
        if (mask == sizeof(n->s_addr) * 8)
            return 1;
        
        printf("range not expected for ip %s\n", p);
    }
    return 0;
}

/*
 * initialise and read the ip v6 presentation, returning in pbits the number of masked (on) bits
 * returns 0 if the presentation form cannot be parsed as an ip v6 address in CIDR notation
 */
static int read_ip6(const char * p, struct in6_addr * n, int * pbits)
{
    memset(n, 0, sizeof(struct in6_addr));
    * pbits = inet_net_pton(AF_INET6, p, n, sizeof(struct in6_addr));
    
    if (* pbits == -1)
    {
        return 0;
    }
    return 1;
}

/*
 * read the presentation form of an ip v6 address, expecting all bits to be masked (on)
 * returns true if all bits are masked (on).
 */
static int read_full_ip6(const char * ip, struct in6_addr * p)
{
    int mask;
    if (read_ip6(ip, p, &mask)) {
        if (mask == sizeof(p->__u6_addr.__u6_addr32) * 8) {
            return 1;
        }
        printf("range not expected for %s\n", ip);
    }
    return 0;
}

/*
 * test whether an ip address falls within two inclusive boundaries, ensuring that
 * all addresses are of the same family, v4 or v6, and are not ranges.
 *
 * returns 0 on success, and -1 on address parse error
 */
static int test_within_bounds(const char * addr_p, const char * lo_p, const char * hi_p)
{
    struct in_addr addr;
    struct in6_addr addr6;
    
    if (read_full_ip(addr_p, &addr)) {
        struct in_addr lo, hi;
        
        if (read_full_ip(lo_p, &lo) && read_full_ip(hi_p, &hi)) {
            return cmp_ip_range(&addr, &lo, &hi) == 0;
        }
    }
    else if (read_full_ip6(addr_p, &addr6)) {
        struct in6_addr lo6, hi6;
        
        if (read_full_ip6(lo_p, &lo6) && read_full_ip6(hi_p, &hi6)) {
            return cmp_ip6_range(&addr6, &lo6, &hi6) == 0;
        }
    }
    return -1;
}

/**
 * parse a <LO>-<HI> ip address range, and test that an ip address is in that range
 */
static int _test_hyphenated_range(const char * addr, const char * range)
{
    char * p = strchr(range, '-');
    if (p == 0) {
        printf("address range not identified: %s\n", range);
        return -1;
    }
    
    char * lo_p = strndup(range, p - range);
    char * hi_p = strdup(p + 1);
    
    int c;
    if (lo_p && hi_p) {
        c = test_within_bounds(addr, lo_p, hi_p);
    } else {
        // memory failure
        c = -1;
    }
    
    // free or ignore allocated strings
    free(lo_p);
    free(hi_p);
    
    return c;
}

/**
 * test that an ip address is within a range specified by a CIDR in the same address family (v4 or v6).
 *
 * returns 0 on match, -1 on address parse error.
 */
static int _test_cidr_range(const char * addr, const char * range)
{
    struct in_addr addr4;
    struct in6_addr addr6;
    
    if (read_full_ip(addr, &addr4)) {
        int bits;
        struct in_addr cidr;
        if (read_ip(range, &cidr, &bits)) {
            return cidr_match(&addr4, &cidr, bits);
        }
    }
    else if (read_full_ip6(addr, &addr6)) {
        int bits;
        struct in6_addr cidr;
        if (read_ip6(range, &cidr, &bits)) {
            return cidr6_match(&addr6, &cidr, bits);
        }
    }
    return -1;
}

#define array_of(a) ((const char *[]){ a })

#define test_cidr(expect, addr, range) do \
{ \
assert_int_equal(ip_address_match(addr, array_of(range), 1, 0l), expect ? AM_SUCCESS : AM_NOT_FOUND); \
assert_int_equal(_test_cidr_range(addr, range), expect); \
} while (0)

#define test_hyphenated(expect, addr, range) do \
{ \
assert_int_equal(ip_address_match(addr, array_of(range), 1, 0l), expect ? AM_SUCCESS : AM_NOT_FOUND); \
assert_int_equal(_test_hyphenated_range(addr, range), expect); \
} while (0)


void test_ip_ranges(void **state) {

    (void)state;

    // V4
    
    test_cidr(          1,  "192.168.0.25",                     "192.168.0.0/24");
    test_hyphenated(    0,  "192.168.0.25",                     "192.168.0.0-192.168.0.23");

    test_cidr(          0,  "192.153.0.0",                      "192.168.0.0/24");
    test_hyphenated(    0,  "192.153.0.0",                      "192.168.0.0-192.168.0.23");
    test_hyphenated(    0,  "192.153.0.23",                     "192.168.0.0-192.168.0.23");
    
    test_hyphenated(    1,  "192.153.0.23",                     "192.153.0.0-192.168.0.23");

    // V6
    
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

    (void)state;

    am_state_func_t const * func_array = 0;
    int array_len = 0;
    
    am_test_get_state_funcs(&func_array, &array_len);
    am_state_func_t notenforced_handler = func_array [5];
    
    struct am_config_map not_enforced_ips [] = {
        { "", "192.153.0.0-192.168.0.23" },
    };
    
    struct {
    } ctx;
    
    am_config_t config = {
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
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = 0,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.notify.com:90/am",
        
        .client_ip                  = "192.153.0.23", // in the ip v4 range
    };
    
    parse_url("http://www.url.com/path", &request.url);
    
    assert_int_equal(notenforced_handler(&request), AM_QUIT);
    assert_int_equal(request.not_enforced, AM_TRUE);
}



void test_cidr_ip6_notenforced_fetch_attr(void **state) {

    (void)state;

    am_state_func_t const * func_array = 0;
    int array_len = 0;
    
    am_test_get_state_funcs(&func_array, &array_len);
    am_state_func_t notenforced_handler = func_array [5];
    
    struct am_config_map not_enforced_ips [] = {
        { "", "2001:5c0:9168:0:0:0:0:1-2001:5c0:9168:0:0:0:0:2" },
        { "", "2001:5c0:9168:/48" },
    };
    
    struct {
    } ctx;
    
    am_config_t config = {
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
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = 0,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.notify.com:90/am",
        
        .client_ip                  = "2001:5c0:9168:0:0:0:0:3", // only in the masked range
    };
    
    parse_url("http://www.url.com/path", &request.url);
    
    assert_int_equal(notenforced_handler(&request), AM_OK);
    assert_int_equal(request.not_enforced, AM_TRUE);
}



void test_cidr_ip6_notenforced_get(void **state) {

    (void)state;

    am_state_func_t const * func_array = 0;
    int array_len = 0;
    
    am_test_get_state_funcs(&func_array, &array_len);
    am_state_func_t notenforced_handler = func_array [5];
    
    struct am_config_map not_enforced_ips[] = {
        { "GET,",   "2001:5c0:9168:0:0:0:0:1-2001:5c0:9168:0:0:0:0:2" },
        { "POST,",  "2001:6c0:9168:/48" },
    };
    
    struct {
    } ctx;
    
    am_config_t config = {
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
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = 0,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.notify.com:90/am",
        
        .client_ip                  = "2001:5c0:9168:0:0:0:0:2", // not in the range for posts
    };
    
    parse_url("http://www.url.com/path", &request.url);
    
    assert_int_equal(notenforced_handler(&request), AM_FAIL);
    assert_int_equal(request.not_enforced, AM_FALSE);
}



void test_url_notenforced_get(void **state) {

    (void)state;

    am_state_func_t const * func_array = 0;
    int array_len = 0;
    
    am_test_get_state_funcs(&func_array, &array_len);
    am_state_func_t notenforced_handler = func_array [5];
    
    struct am_config_map not_enforced_ips[] = {
        { "GET,0",   "2001:5c0:9168:0:0:0:0:1-2001:5c0:9168:0:0:0:0:2" },
        { "POST,0",  "2001:5c0:9168:/48" },
    };
    
    struct am_config_map not_enforced_map[] = {
        { "GET,0",   ".+://\\.+" },
        { "POST,0",  "https://www\\..+/path.*" },
    };
    
    struct {
    } ctx;
    
    am_config_t config = {
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
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = 0,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.url.com/path",
        
        .client_ip                  = "2001:6c0:9168:0:0:0:0:2", // not in any ip range
    };
    
    parse_url("http://www.url.com/path", &request.url);
    
    assert_int_equal(notenforced_handler(&request), AM_OK);
    assert_int_equal(request.not_enforced, AM_TRUE);
}


void test_deny_url_notenforced_get(void **state) {

    (void)state;

    am_state_func_t const * func_array = 0;
    int array_len = 0;
    
    am_test_get_state_funcs(&func_array, &array_len);
    am_state_func_t notenforced_handler = func_array [5];
    
    struct am_config_map not_enforced_ips[] = {
        { "GET,0",   "2001:5c0:9168:0:0:0:0:1-2001:5c0:9168:0:0:0:0:2" },
        { "POST,0",  "2001:5c0:9168:/48" },
    };
    
    struct am_config_map not_enforced_map[] = {
        { "GET,0",   "https://www.url.com:90/path" },
        { "POST,0",  "https://www.url.com/path" },
    };
    
    struct {
    } ctx;
    
    am_config_t config = {
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
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = 0,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.access.com/deny",
        
        .client_ip                  = "2001:6c0:9168:0:0:0:0:2", // not in any ip range
    };
    
    parse_url("https://www.access.com/deny", &request.url); // this is the access-denied url
    
    assert_int_equal(notenforced_handler(&request), AM_OK);
    assert_int_equal(request.not_enforced, AM_TRUE);
}
