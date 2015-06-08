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

/** THIS FILE AUTOMATICALLY GENERATED FROM mm.sh.  DO NOT EDIT !! */

#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>

#include "am.h"

#include "test_log.h"

/**
 * The main framework for calling the cmocka tests.  The exit status reflects the success or failure of
 * the tests.
 */
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_logging),
        cmocka_unit_test(test_am_strncat),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
