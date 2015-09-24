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
#include <setjmp.h>

#include "platform.h"
#include "am.h"
#include "utility.h"
#include "net_client.h"
#include "thread.h"
#include "cmocka.h"

static void test_log_callback(void *arg, char *name, int error) {
    int *pcount = arg;
    (*pcount)++;
    printf("%s -> error %d (%s)\n", name, error, strerror(error));
}

void test_init_cleanup(void **state) {
    int instance = 1;
    int clearup_count;

    clearup_count = 0;
    assert_int_equal(am_remove_shm_and_locks(instance, test_log_callback, &clearup_count), AM_SUCCESS);
    assert_int_equal(clearup_count, 0);

    am_init(instance);
    clearup_count = 0;
    assert_int_equal(am_remove_shm_and_locks(instance, test_log_callback, &clearup_count), AM_SUCCESS);
#ifdef _WIN32
    assert_int_equal(clearup_count, 0);
#else
#ifdef __APPLE__
    /* OS X mach semaphore is not cleared */
    assert_int_equal(clearup_count, 4);
#else
    assert_int_equal(clearup_count, 5);
#endif
#endif

    clearup_count = 0;
    assert_int_equal(am_remove_shm_and_locks(instance, test_log_callback, &clearup_count), AM_SUCCESS);
    assert_int_equal(clearup_count, 0);
}

