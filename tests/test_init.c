// SPDX-License-Identifier: CDDL-1.0
//
// Copyright 2015 ForgeRock AS.
// Copyright 2018-2026 Open Identity Platform Community.

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
    assert_int_equal(clearup_count, 5);
#endif

    clearup_count = 0;
    assert_int_equal(am_remove_shm_and_locks(instance, test_log_callback, &clearup_count), AM_SUCCESS);
    assert_int_equal(clearup_count, 0);
}
