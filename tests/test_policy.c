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
 * Copyright 2015-2016 ForgeRock AS.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <setjmp.h>

#include "am.h"
#include "platform.h"
#include "utility.h"
#include "log.h"
#include "cmocka.h"

static void check_normalisation(char *pattern, char *expect) {
    char *norm = am_normalize_pattern(pattern);

    if (expect) {
        assert_string_equal(norm, expect);

    } else {
        assert_null(norm);

    }
    am_free(norm);
}

void test_pattern_normalisation(void **state) {

    /* simple cases */
    check_normalisation("http://a.c.b/first/second?a=b", "http://a.c.b:80/first/second?a=b");
    check_normalisation("https://a.c.b/first/second", "https://a.c.b:443/first/second");
    check_normalisation("https://*.com/path", "https://*.com:443/path");
    check_normalisation("https://*.com/?a=b", "https://*.com:443/?a=b");

    /* without path */
    check_normalisation("https://a.b.com", "https://a.b.com:443");
    check_normalisation("https://*.com", "https://*.com:443");

    /* without path except params */
    check_normalisation("https://a.b.c?a=b", "https://a.b.c:443?a=b");
    check_normalisation("http://a.b.c?/*", "http://a.b.c:80?/*");
    check_normalisation("https://a.b.c?*", "https://a.b.c:443?*");
    check_normalisation("http://a.*.c?*", "http://a.*.c:80?*");

    /* no path, but wildcard */
    check_normalisation("https://*", NULL);
    check_normalisation("https://*?a=b", NULL);
    check_normalisation("https://a.b.*?a=b", NULL);

    /* wildcard disables normalisation */
    check_normalisation("http://a.c.b*/first/second", NULL);
    check_normalisation("https://*/first/second", NULL);
    check_normalisation("http://a.c.b*", NULL);

    /* protocol not present or unrecognisable */
    check_normalisation("htt://substr.protocol.com/first/second", NULL);
    check_normalisation("httpn://superstr.protocol.com/first/second", NULL);
    check_normalisation("httpsn://superstr.protocol.com/first/second", NULL);
    check_normalisation("no.protocol.com", NULL);
    check_normalisation("://empty.protocol.com", NULL);
}

static int compare_url(am_request_t *r, const char *pattern, const char *resource) {
    int status = policy_compare_url(r, pattern, resource);
    fprintf(stdout, "%s\t\t%s\t\t[%s]\n", pattern, resource, am_policy_strerror(status));
    return status;
}

void test_policy_compare_url(void **state) {
    am_config_t config = { .instance_id = 101, .url_eval_case_ignore = 1 };
    am_request_t r = { .conf = &config, };

    /* pattern, resource */

    /* wildcard in a resource */
    assert_int_equal(compare_url(&r, "http://h/a*", "http://h/a*b"), AM_EXACT_PATTERN_MATCH);
    assert_int_equal(compare_url(&r, "http://h/a*", "http://h/a*"), AM_EXACT_PATTERN_MATCH);
    assert_int_equal(compare_url(&r, "http://h/axb", "http://h/a*b"), AM_NO_MATCH);
    assert_int_equal(compare_url(&r, "http://h/ax", "http://h/a*"), AM_NO_MATCH);
    assert_int_equal(compare_url(&r, "http://h/a", "http://h/a*"), AM_NO_MATCH);
    assert_int_equal(compare_url(&r, "http://a.b.c/-*-/b", "http://a.b.c/a*/*/b"), AM_NO_MATCH);
    assert_int_equal(compare_url(&r, "http://a.b.c/-*-/b", "http://a.b.c/a*/b"), AM_EXACT_PATTERN_MATCH);

    /* other types */
    assert_int_equal(compare_url(&r, "http://h/a*", "http://h/ab"), AM_EXACT_PATTERN_MATCH);

    assert_int_equal(compare_url(&r, "http://h/a*", "http://h/b"), AM_NO_MATCH);
    assert_int_equal(compare_url(&r, "http://h/ab", "http://h/ab"), AM_EXACT_MATCH);

    assert_int_equal(compare_url(&r, "http://*.c*/-*-/z", "http://a.b.c:90/x/z"), AM_EXACT_PATTERN_MATCH);
    assert_int_equal(compare_url(&r, "http://vb2.*/test*", "http://vb3.local.com:80/test/path"), AM_NO_MATCH);
    assert_int_equal(compare_url(&r, "http://a.b.c:*/x/y/z", "http://a.b.c:90/x"), AM_NO_MATCH);
    assert_int_equal(compare_url(&r, "http://a.b.*/*/z", "http://a.b.c:90/x/y/z"), AM_EXACT_PATTERN_MATCH);

    assert_int_equal(compare_url(&r, "http://a.b.*/-*-/z", "http://a.b.c:90/x/y/z"), AM_NO_MATCH);
    assert_int_equal(compare_url(&r, "http://a.b.*/-*-/z", "http://a.b.c:90/x/z"), AM_EXACT_PATTERN_MATCH);

    assert_int_equal(compare_url(&r, "http://a.b.*:123456/*x", "http://a.b.c:123456/x"), AM_EXACT_PATTERN_MATCH);
    assert_int_equal(compare_url(&r, "http://a.b.*:123456/*x", "http://a.ffff.c/x"), AM_NO_MATCH);

    assert_int_equal(compare_url(&r, "http://-*-.c*/-*-/z", "http://a.b.c:90/x/z"), AM_EXACT_PATTERN_MATCH);
    assert_int_equal(compare_url(&r, "http://*.c*/x/-*-/z", "http://a.b.c:90/x//z"), AM_EXACT_PATTERN_MATCH);

    assert_int_equal(compare_url(&r, "http:/a.b.c*/*/-*-/z", "http://a.b.c:90/x/z"), AM_NO_MATCH);

    assert_int_equal(compare_url(&r, "http://-*-.c*/-*-/z", "http://a.b.c/:90/x/z"), AM_NO_MATCH);

    assert_int_equal(compare_url(&r, "*.c*/-*-/z", "http://a.b.c:90/y/z"), AM_EXACT_PATTERN_MATCH);
    assert_int_equal(compare_url(&r, "*.c:90/-*-/z", "http://a.b.c:90/x/y/z"), AM_NO_MATCH);

    assert_int_equal(compare_url(&r, "*.c*/-*-/z", "http://a.b.c:90/x/y/z"), AM_EXACT_PATTERN_MATCH);
    assert_int_equal(compare_url(&r, "http*.c*/-*-/z", "http://a.b.c:90/x/y/z"), AM_EXACT_PATTERN_MATCH);

    assert_int_equal(compare_url(&r, "http://a.b.c/*.gif", "http://a.b.c/illegal?hack.gif"), AM_NO_MATCH);
    assert_int_equal(compare_url(&r, "http://a.b.c/*.gif", "http://a.b.c/illegal#hack.gif"), AM_EXACT_PATTERN_MATCH);

    /* check that this isn't a partial match */
    assert_int_equal(compare_url(&r, "http://a.b.c/*x", "http://a.b.c/illegalxand-the-rest"), AM_NO_MATCH);
    assert_int_equal(compare_url(&r, "http://a.b.c/*x", "xxxxxhttp://a.b.c/illegalx"), AM_NO_MATCH);
    assert_int_equal(compare_url(&r, "http://a.b.c/*", "http://a.b.c/illegalxand-the-rest"), AM_EXACT_PATTERN_MATCH);

    /* check escape characters */
    assert_int_equal(compare_url(&r, "http://?$a.b.c/\t([]x", "http://?$a.b.c/\t([]x"), AM_EXACT_MATCH);

    /* test backtrack */
    assert_int_equal(compare_url(&r, "http://a*bcd:80/n", "http://abxxxbcxxxxbcd:80/n"), AM_EXACT_PATTERN_MATCH);
    assert_int_equal(compare_url(&r, "http://a*b*cM:80/n", "http://axbxcNbxcM:80/n"), AM_EXACT_PATTERN_MATCH);

    /* test without path */
    assert_int_equal(compare_url(&r, "http://a*b*cM:80?a=b", "http://axbxcNbxcM:80?a=b"), AM_EXACT_PATTERN_MATCH);
    assert_int_equal(compare_url(&r, "http://a*b*cM*", "http://axbxcNbxcM:80"), AM_EXACT_PATTERN_MATCH);
    assert_int_equal(compare_url(&r, "http://a*b*cM*", "http://axbxcNbxcM:80/q"), AM_NO_MATCH);
    assert_int_equal(compare_url(&r, "http://a*b*cM*", "http://axbxcNbxcM:80?q"), AM_NO_MATCH);
}


#define BACKTRACK_CASES
#define MATCH(r, p, u) compare_pattern_resource(r, p, u)

am_bool_t compare_pattern_resource(am_request_t *r, const char * pattern, const char * url);

typedef struct {

    char * pattern, * resource;
    am_bool_t expect;
    
} pattern_exp_t;

#define array_len(a) ((&a) [1] - a)

#define expect(p, r, e) { .pattern = p, .resource = r, .expect = e }

static pattern_exp_t exps[] = {

    expect("*.c:90/-*-/z",               "http://a.b.c:90/x/y/z",               AM_FALSE),

    expect("*://*/-*-*.html",            "http://a.b.c/path?hack.html",         AM_FALSE),

    expect("http://x/cM*",               "http://x/cM-80?q",                    AM_FALSE),
    expect("*://*:*/xapp/*",             "://:///xapp/?x",                      AM_FALSE),

    expect("http://*/a*b",               "http://foo.bar/axbxxxxxxxxx",         AM_FALSE),
    expect("http://*/a*b",               "http://foo/bar/axbxbx",               AM_FALSE),

    expect("*://*/root/*?*",             "https://foo.bar:443/root/next/path?params", AM_TRUE),
    expect("*://*/root/*?*P=Q",          "http://foo.bar:4738923249/root/next/path?P=Q", AM_TRUE),
    expect("*://*/root/*?*P=Q",          "http://foo.bar:4/root/next/path?S=T&P=Q", AM_TRUE),
    
    expect("http://vb2.*/test*",         "http://vb3.local.com:80/test/path",   AM_FALSE),
    
    expect("http://a.b.c:*/x/y/z",       "http://a.b.c:90/x",                   AM_FALSE),
    expect("http://a.b.*/*/z",           "http://a.b.c:90/x/y/z",               AM_TRUE),
    
    /* wildcard goes over port and path */

#ifdef BACKTRACK_CASES
    expect("http://a.b.*/-*-/z",         "http://a.b.c:90/x/y/z",               AM_TRUE),
    expect("*.c*/-*-/z",                 "http://a.b.c:90/x/y/z",               AM_TRUE),
    expect("http*.c*/-*-/z",             "http://a.b.c:90/x/y/z",               AM_TRUE),
    expect("http*.c*/-*-/z*",            "http://a.b.c:90/x/y/z/a",             AM_TRUE),
    expect("http*.c*/-*-z*",             "http://a.b.c:90/x/yz/a",              AM_TRUE),
    expect("http*.c*/-*-z*",             "http://a.b.c:90/x/y?z/a",             AM_FALSE),
#endif

    expect("http:/a.b.c*/*/-*-/z",       "http://a.b.c:90/x/z",                 AM_FALSE),
    expect("*.c:90/-*-/z",               "http://a.b.c:90/x/y/z",               AM_FALSE),

    expect("http://a.b.*/-*-/z",         "http://a.b.c:90/x/z",                 AM_TRUE),
    
    expect("http://a.b.*:123456/*x",     "http://a.b.c:123456/x",               AM_TRUE),
    expect("http://a.b.*:123456/*x",     "http://a.ffff.c/x",                   AM_FALSE),
    
    expect("http://-*-.c:*/*/-*-/z",     "http://a.b.c:90/x/y/z",               AM_TRUE),
    expect("http://-*-.c*/-*-/z",        "http://a.b.c:90/x/z",                 AM_TRUE),
    expect("http://*.c*/x/-*-/z",        "http://a.b.c:90/x//z",                AM_TRUE),

    /* should not pass the sanity check: bad url, not 3 /s */

#ifdef MALFORMED_URL
    expect("http://-*-.c*/-*-/z",        "http://a.b.c/:90/x/z",                AM_FALSE),
    expect("*://*:*/*",                  "http:///a.b.c:90/x/z",                AM_FALSE),
#endif

    expect("*.c*/-*-/z",                 "http://a.b.c:90/y/z",                 AM_TRUE),

    expect("http://a.b.c/*.gif",         "http://a.b.c/illegal?hack.gif",       AM_FALSE),

    expect("http://a.b.c/*x",            "http://a.b.c/illegalxand-the-rest",   AM_FALSE),
    expect("http://a.b.c/*x",            "xxxxxhttp://a.b.c/illegalx",          AM_FALSE),
    expect("http://a.b.c/*x*",           "http://a.b.c/illegalxand-the-rest",   AM_TRUE),
    
    expect("http://?$a.b.c/\t([]x",      "http://?$a.b.c/\t([]x",               AM_TRUE),
    
    /* backtrack 1 level */

    expect("http://a*bcd:80/n",          "http://abxxxbcxxxxbcd:80/n",          AM_TRUE),
    expect("http://a*b*cM:80/n",         "http://axbxcMNbxcM:80/n",             AM_TRUE),
    
    /* test without paths */

    expect("http://a*b*cM:80?a=b",       "http://axbxcNbxcM:80?a=b",            AM_TRUE),
    expect("http://a*b*cM*",             "http://axbxcNbxcM:80",                AM_TRUE),

    expect("http://a*b*cM:*/*",          "http://axbxcMbxcM:80/q",              AM_TRUE),
    expect("http://a*b*cM*/q",           "http://axbxcNbxcM:80/q",              AM_TRUE),
    expect("http://a*b*cM*/*r",          "http://axbxcNbxcM:80/q?r",            AM_FALSE),
    expect("http://a*b*cM*/*?r",         "http://axbxcNbxcM:80/q?r",            AM_TRUE),

    expect("http://a*b*cM*/-*-r",        "http://axbxcNbxcM:80/q?r",            AM_FALSE),
    expect("http://a*b*cM*/-*-?r",       "http://axbxcNbxcM:80/q?r",            AM_TRUE),

    expect("http://a*b*cM*",             "http://axbxcNbxcM:80/q",              AM_TRUE),
    expect("http://a*b*cM*",             "http://axbxcNbxcM:80?q",              AM_FALSE),

    expect("*://*/*.html",               "http://a.b.c/secret.xml?hack.html",   AM_FALSE),
    expect("*://*/*.html",               "http://a.b.c/path/no-hack.html",      AM_TRUE),

    expect("*://*/-*-.html",             "http://a.b.c/secret.xml?hack.html",   AM_FALSE),
    expect("*://*/*/-*-.html",           "http://a.b.c/foo/bar/secret.xml?hack.html",AM_FALSE),
    expect("*://*/-*-*.html",            "http://a.b.c/path?hack.html",         AM_FALSE),

    /* degenerate cases: concatenated wildcards - don't have more of them than characters */

    expect("***",                        "01",                                  AM_TRUE),
    expect("****",                       "01",                                  AM_FALSE), 

    expect("http://a.b.c:90/x/y/z?a/b",  "http://a.b.c:90/x/y/z?a/b",           AM_TRUE),
    expect("**-*-****?***",              "http://a.b.c:90/x/y/z?a/b",           AM_TRUE),
    expect("**-*-******",                "http://a.b.c:90/x/y/z?a/b",           AM_FALSE),
};

void test_compare_pattern_resource(void **state) {
    size_t len = array_len(exps);
    
    am_config_t config = { .instance_id = 101, .url_eval_case_ignore = 0 };
    am_request_t request = { .conf = &config, };

    int i, errs = 0;

    for (i = 0; i < len; i++) {
        if (MATCH(&request, exps[i].pattern, exps[i].resource) !=  exps[i].expect) {
            printf("policy test error with pattern %s and URL %s: expected %d\n", exps[i].pattern, exps[i].resource, exps[i].expect);
            errs++;

        }

    }
    assert_int_equal(errs, 0);

}

static void match_wildcard(const char* url, const char *ptn) {
    am_config_t config = { .instance_id = 101, .url_eval_case_ignore = 1 };
    am_request_t request = { .conf = &config, };

    if (! MATCH(&request, ptn, url)) {
        printf("expected url %s to match pattern %s\n", url, ptn);
    }

}

void test_am_policy_results(void **state) {
    match_wildcard("http://example.com:80/fred/index.html", "http*://*example.com:*/fred/*");
    match_wildcard("http://www.example.com:80/fred/index.html", "http*://*example.com:*/fred/*");
    match_wildcard("http://www.google.com:80/asdf/hello/blah/wibble/asdf/blah", "http://www.google.com:80/*/blah/wibble/*/blah");
    match_wildcard("http://www.google.com.net", "http://www.google.com*");
    match_wildcard("http://www.google.com:80/", "http://www.google.com:*");
    match_wildcard("http://www.google.com.co.uk", "http://www.google.com*");
    match_wildcard("http://www.google.com.co.uk:80", "http://www.google.com*");
    match_wildcard("http://www.google.com.co.uk:80/", "http://www.google.com*");
    match_wildcard("http://www.google.com.co.uk:80/blah", "http://www.google.com*");
    match_wildcard("http://example.com/index.html", "http*://example.com/index.html");
    match_wildcard("http://www.google.com:80/123/index.html", "http://*.com:80/123/index.html");
    match_wildcard("http://example.com:80/index.html?a=b", "http://example.com:80/index.*?a=b");
    match_wildcard("http://example.com:80/index.html?a=b", "http://example.com:80/index.*?*");

}

