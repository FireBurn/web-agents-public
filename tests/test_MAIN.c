// SPDX-License-Identifier: CDDL-1.0
//
// Copyright 2015 ForgeRock AS.
// Copyright 2018-2026 Open Identity Platform Community.

/**
 * THIS FILE INCLUDES AUTOMATICALLY GENERATED CONTENT FROM "tests.h".
 * DO NOT EDIT "test_MAIN.c" AND "tests.h" FILES.
 */

#include <stdio.h>
#include <stdarg.h>
#include <setjmp.h>

#include "cmocka.h"
#include "tests.h"

/**
 * The main framework for calling the cmocka tests.  The exit status reflects the success or failure of
 * the tests.
 */
int main(int argc, char **argv) {
    return cmocka_run_group_tests(tests, NULL, NULL);
}
