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

void test_pattern_normalisation(void **state) {

    /* simple cases */
    assert_string_equal(am_normalize_pattern("http://a.c.b/first/second?a=b"), "http://a.c.b:80/first/second?a=b");
    assert_string_equal(am_normalize_pattern("https://a.c.b/first/second"), "https://a.c.b:443/first/second");
    assert_string_equal(am_normalize_pattern("https://*.com/path"), "https://*.com:443/path");
    assert_string_equal(am_normalize_pattern("https://*.com/?a=b"), "https://*.com:443/?a=b");

    /* without path */
    assert_string_equal(am_normalize_pattern("https://a.b.com"), "https://a.b.com:443");
    assert_string_equal(am_normalize_pattern("https://*.com"), "https://*.com:443");

    /* without path except params */
    assert_string_equal(am_normalize_pattern("https://a.b.c?a=b"), "https://a.b.c:443?a=b");
    assert_string_equal(am_normalize_pattern("http://a.b.c?/*"), "http://a.b.c:80?/*");
    assert_string_equal(am_normalize_pattern("https://a.b.c?*"), "https://a.b.c:443?*");
    assert_string_equal(am_normalize_pattern("http://a.*.c?*"), "http://a.*.c:80?*");

    /* no path, but wildcard */
    assert_null(am_normalize_pattern("https://*"));
    assert_null(am_normalize_pattern("https://*?a=b"));
    assert_null(am_normalize_pattern("https://a.b.*?a=b"));

    /* wildcard disables normalisation */
    assert_null(am_normalize_pattern("http://a.c.b*/first/second"));
    assert_null(am_normalize_pattern("https://*/first/second"));
    assert_null(am_normalize_pattern("http://a.c.b*"));

    /* protocol not present or unrecognisable */
    assert_null(am_normalize_pattern("htt://substr.protocol.com/first/second"));
    assert_null(am_normalize_pattern("httpn://superstr.protocol.com/first/second"));
    assert_null(am_normalize_pattern("httpsn://superstr.protocol.com/first/second"));
    assert_null(am_normalize_pattern("no.protocol.com"));
    assert_null(am_normalize_pattern("://empty.protocol.com"));
}

static int compare_url(am_request_t *r, const char *pattern, const char *resource) {
    int status = policy_compare_url(r, pattern, resource);
    fprintf(stdout, "%s\t\t%s\t\t[%s]\n", pattern, resource, am_policy_strerror(status));
    return status;
}

void test_pattern_match(void **state) {
    am_request_t r;
    memset(&r, 0, sizeof (am_request_t));
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

    assert_int_equal(compare_url(&r, "*.c*/-*-/z", "http://a.b.c:90/x/y/z"), AM_NO_MATCH);
    assert_int_equal(compare_url(&r, "http*.c*/-*-/z", "http://a.b.c:90/x/y/z"), AM_NO_MATCH);

    assert_int_equal(compare_url(&r, "http://a.b.c/*.gif", "http://a.b.c/illegal?hack.gif"), AM_EXACT_PATTERN_MATCH);
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
