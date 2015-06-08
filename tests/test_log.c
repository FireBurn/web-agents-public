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

#include "am.h"
#include "log.h"

#include <setjmp.h>
#include <cmocka.h>

/**
 * This is the simplest of tests to check we can log things without crashing.
 *
 * In fact, because of the way logging works (differently) in test mode than it does in "agent mode"
 * all we're really doing here is to test that logging in test mode isn't broken.  This may or may not
 * bear any relation to whether logging works for the rest of the time.
 */
void test_logging(void** state) {
    
    static const char* text1 = "Now is the winter of our discontent,";
    static const char* text2 = "Made glorious summer by this son of York";
    
    (void)state;
    
    AM_LOG_INFO(0, "instance id is zero and no args");
    AM_LOG_INFO(0, "instance id is zero and incorrect args", text1);
    AM_LOG_INFO(0, "instance id is zero and more incorrect args", text1, text2);

    /* we're testing this will not crash */
    AM_LOG_INFO(0, NULL, text1, text2);

    /* this will not appear, since the instance is greater than zero, but it should not crash either */
    AM_LOG_ERROR(10, "%s %s", text1, text2);

    AM_LOG_INFO(0, "%s %s", text1, text2);
    AM_LOG_WARNING(0, "%s %s", text1, text2);
    AM_LOG_ERROR(0, "%s %s", text1, text2);
    AM_LOG_DEBUG(0, "%s %s", text1, text2);
    AM_LOG_AUDIT(0, "%s %s", text1, text2);

    AM_LOG_ALWAYS(0, "%s %s", text1, text2);
    AM_LOG_ALWAYS(0, "Now %s the %s of our %s, %s summ%s of York",
                  "is",
                  "winter",
                  "discontent",
                  "Made glorious",
                  "er by this son");

    /* attempt to overflow the buffer */
    AM_LOG_ALWAYS(0, "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
}

void test_am_strncat(void** state) {
    
    char   buf[10] = "a";

    am_strncat(buf, "bcdefghijklmnopq", sizeof(buf));
    assert_int_equal(strlen(buf), sizeof(buf) - 1);
    assert_string_equal(buf, "abcdefghi");

    am_strncat(buf, "1234567890", sizeof(buf));
    assert_int_equal(strlen(buf), sizeof(buf) - 1);
    assert_string_equal(buf, "abcdefghi");

}
