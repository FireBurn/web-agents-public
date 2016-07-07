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
 * Copyright 2015 - 2016 ForgeRock AS.
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

struct log_range {
    int inst;
    long start, end;
};

/*
 * cleardown callback for information
 */
static void test_log_callback(void *arg, char *name, int error) {
    int *pcount = arg;
    (*pcount)++;
    printf("%s -> error %d (%s)\n", name, error, strerror(error));
}

/*
 * log unique messages within a range
 */
static void *log_procedure(void * params) {
    struct log_range * range = params;
    int i;

    for (i = range->start; i < range->end; i++) {
        AM_LOG_DEBUG(range->inst, "message %d", i);

        if (i % 10000 == 0)
            fprintf(stdout, "%d\n", i);
    }
    return NULL;
}

#define NTHREADS 256
#define NLOGS    1234

/*
 * create threads which willl log messages in separate ranges
 */
static void test_threaded_logging(int instance, int nthreads, int nlogs) {
    am_thread_t *threads = calloc(nthreads, sizeof (am_thread_t));
    struct log_range *ranges = calloc(nthreads, sizeof (struct log_range));

    long t0 = clock();
    double dt;

    int i;

    for (i = 0; i < nthreads; i++) {
        ranges [i].inst = instance;
        ranges [i].start = i * nlogs;
        ranges [i].end = ranges [i].start + nlogs;
        AM_THREAD_CREATE(threads[i], log_procedure, ranges + i);
    }

    for (i = 0; i < nthreads; i++) {
        AM_THREAD_JOIN(threads[i]);
    }

    dt = ((double) (clock() - t0)) / CLOCKS_PER_SEC;
    fprintf(stdout, "%d log entries takes %lf secs\n", nthreads * nlogs, dt);

    free(threads);
    free(ranges);
}

#define word_offset(id) ((id) >> 6)
#define word_bit(id) (0x1ull << ((id) & 0x3full))

/*
 * read back log file and use a bit map to ensure each message
 * was logged once
 */
static void verify_file(char * path, int count) {
    size_t size = 0;
    char * s, *t;
    char * p = load_file(path, &size);

    const int offset = strlen("message ");

    int i;
    uint64_t c = word_offset(count);
    uint64_t * bits = calloc(1 + c, sizeof (uint64_t));

    t = p;
    while ((s = am_strsep(&t, "\n")) != NULL) {
        char * str = strstr(s, "message ");
        if (str) {
            char * end = NULL;
            uint64_t msgid = strtoul(str + offset, &end, 10);
            if (end == str + offset)
                printf("corrupt log entry: %s\n", str);
            else if (count <= msgid)
                printf("out of rangelog entry: %s\n", str);
            else if (bits [word_offset(msgid)] & word_bit(msgid))
                printf("error: duplicated log: %s\n", str);
            else
                bits [word_offset(msgid)] |= word_bit(msgid);
        }
    }
    free(p);

    /* test all bits are set (redundant) */

    for (i = 0; i < count; i++)
        if ((bits [word_offset(i)] & word_bit(i)) == 0)
            printf("error at position %d, got %llu\n", i, bits [word_offset(i)]);

    /* test all bits are set */

    for (i = 0; i < c; i++)
        if (~bits [i])
            printf("error at word %d, got %llu\n", i, bits [i]);

    if (bits [c] != word_bit(count) - 1)
        printf("error in final word %llu, got %llu (expected %llu)\n", c, bits [c], word_bit(count) - 1);

    free(bits);
}

/*
 * log to a file with multiple threads and ensure that each message is present
 */
void test_logging(void **state) {
    int instance = 1;
    int clearup_count = 0;
    struct log_range range = {.inst = instance, .start = 0, .end = NLOGS};

    assert_int_equal(am_remove_shm_and_locks(instance, test_log_callback, &clearup_count), AM_SUCCESS);
#ifdef _WIN32
    am_init_worker(instance);
#else
    am_init(instance);
#endif

    am_delete_file("temp-debug.log");
    am_delete_file("temp-audit.log");

    printf("type return\n");
    getc(stdin);

    am_log_register_instance(instance, "temp-debug.log", AM_LOG_LEVEL_DEBUG, 0,
            "temp-audit.log", 0, 0x100000, "temp-agent.conf");

    // log_procedure(&range);
    test_threaded_logging(instance, NTHREADS, NLOGS);

    am_shutdown_worker();
    am_shutdown(instance);

    verify_file("temp-debug.log", NTHREADS * NLOGS);

    am_delete_file("temp-debug.log");
    am_delete_file("temp-audit.log");
}
