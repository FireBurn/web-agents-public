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
 * Copyright 2015 ForgeRock AS.
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
    
    // simple cases
    assert_string_equal(  am_normalize_pattern("http://a.c.b/first/second?a=b"),  "http://a.c.b:80/first/second?a=b");
    assert_string_equal(  am_normalize_pattern("https://a.c.b/first/second"),     "https://a.c.b:443/first/second");
    assert_string_equal(  am_normalize_pattern("https://*.com/path"),             "https://*.com:443/path");
    assert_string_equal(  am_normalize_pattern("https://*.com/?a=b"),             "https://*.com:443/?a=b");
    
    // without path
    assert_string_equal(  am_normalize_pattern("https://a.b.com"),                "https://a.b.com:443");
    assert_string_equal(  am_normalize_pattern("https://*.com"),                  "https://*.com:443");
    
    // without path except params
    assert_string_equal(  am_normalize_pattern("https://a.b.c?a=b"),              "https://a.b.c:443?a=b");
    assert_string_equal(  am_normalize_pattern("http://a.b.c?/*"),                "http://a.b.c:80?/*");
    assert_string_equal(  am_normalize_pattern("https://a.b.c?*"),                "https://a.b.c:443?*");
    assert_string_equal(  am_normalize_pattern("http://a.*.c?*"),                 "http://a.*.c:80?*");
    
    // no path, but wildcard
    assert_null(    am_normalize_pattern("https://*"));
    assert_null(    am_normalize_pattern("https://*?a=b"));
    assert_null(    am_normalize_pattern("https://a.b.*?a=b"));
    
    // wildcard disables normalisation
    assert_null(    am_normalize_pattern("http://a.c.b*/first/second"));
    assert_null(    am_normalize_pattern("https://*/first/second"));
    assert_null(    am_normalize_pattern("http://a.c.b*"));
    
    // protocol not present or unrecognisable
    assert_null(    am_normalize_pattern("htt://substr.protocol.com/first/second"));
    assert_null(    am_normalize_pattern("httpn://superstr.protocol.com/first/second"));
    assert_null(    am_normalize_pattern("httpsn://superstr.protocol.com/first/second"));
    assert_null(    am_normalize_pattern("no.protocol.com"));
    assert_null(    am_normalize_pattern("://empty.protocol.com"));
}

