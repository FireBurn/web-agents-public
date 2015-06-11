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
#include <setjmp.h>

#include "platform.h"
#include "am.h"
#include "utility.h"
#include "cmocka.h"

/**
 * This is the marker we spatter throughout our destination buffer for testing purposes.  It must not be null
 * because as far as this code is concerned, null is valid data.  We need this to be invalid and noticable.
 * Thus I chose control A.
 */
#define MARKER   0x1


/**
 * Encode the string stored in p and make non printing characters (including nulls) visible by representing
 * them as \HH where HH is the hex value in the shortest width possible (so null comes out as \0).  We return
 * a pointer to a dynamically allocated piece of memory which should be freed.  This routine isn't particularly
 * efficient.
 */
const char* encode(const char* p, size_t len) {
    static char buf[1024];
    
    buf[0] = '\0';
    while(len--) {
        char buf2[50];
        if (*p < ' ' || *p == 127) {
            sprintf(buf2, "\\%x", *p);
            strcat(buf, buf2);
        } else {
            buf2[0] = *p;
            buf2[1] = '\0';
            strcat(buf, buf2);
        }
        p++;
    }
    return strdup(buf);
}

/**
 * Find the first marker character in "dest" and return the number of characters before it.
 */
size_t find_marker(const char* dest) {
    
    const char* p = dest;
    while (*p != MARKER) {
        p++;
    }
    return p - dest;
}

/**
 * Compare the actual and expected values.  If they do not match, dump out a representation of both the expected
 * and actual values so we can see what has gone wrong.  If they do match, print "SUCCESS" and return 0.  In
 * this way we draw maximum attention to ourselves only if the test fails.
 */
int compare(const char* actual, const char* expected, size_t expected_len) {
    
    size_t actual_len = find_marker(actual);
    
    if (actual_len != expected_len) {
        printf("actual length and expected lengths are different (%lu vs %lu)\n",
               actual_len, expected_len);

        printf("expected: %s\nactual: %s\n", encode(expected, expected_len), encode(actual, actual_len));
        return 1;
    }

    if (memcmp(actual, expected, expected_len) != 0) {
        printf("actual and expected strings are different (although the same length)\n");
        printf("expected: %s\nactual: %s\n", encode(expected, expected_len), encode(actual, actual_len));
        return 1;
    }
    
    return 0;
}

/************************************************************************************************************/

/**
 * test mem2cpy, returning 1 if the test fails, 0 if it succeeds.
 */
void test_mem2cpy(void** state) {

    char a[] = "ABCDEF";
    char b[] = "GHI";

    char expected[] = "ABCDEF\0GHI"; // C gives us a free null after the "I"

    char dest[1000];
    
    memset(dest, MARKER, ARRAY_SIZE(dest));
    mem2cpy(dest, a, 6, b, 3);

    assert_int_equal(compare(dest, expected, ARRAY_SIZE(expected)), 0);
}

/**
 * test mem3cpy, returning 1 if the test fails, 0 if it succeeds.
 */
void test_mem3cpy(void** state) {

    char a[] = "ABCDEF";
    char b[] = "GHI";
    char c[] = "JKLMN";

    char expected[] = "ABCDEF\0GHI\0JKLMN"; // C gives us a free null after the "N"

    char dest[1000];

    memset(dest, MARKER, ARRAY_SIZE(dest));
    mem3cpy(dest, a, 6, b, 3, c, 5);

    assert_int_equal(compare(dest, expected, ARRAY_SIZE(expected)), 0);
}

/**
 * Test the match function.
 */
void test_match(void** state) {
    
    static const char* text = "Now is the winter of our discontent, "
                                "Made glorious summer by this son of York";
        
    // for some reason, passing in null results in an "ok" match
    assert_int_equal(match(1, NULL, NULL), AM_OK);
    assert_int_equal(match(1, NULL, text), AM_OK);
    assert_int_equal(match(1, text, NULL), AM_OK);
    
    assert_int_equal(match(1, text, "content,"), AM_OK);
    assert_int_equal(match(1, text, "ter.of..ur"), AM_OK);
    assert_int_equal(match(1, text, "[Gg]lorio.s"), AM_OK);
    
    assert_int_equal(match(1, text, "Aardvark,"), AM_FAIL);
    assert_int_equal(match(1, text, "[Gg]lourio.s"), AM_FAIL);
}

/**
 * Note that the match_groups function isn't tested here because it is only invoked once in the entire codebase.
 * Also I can't quite figure what the length parameters should be set to.
 */


