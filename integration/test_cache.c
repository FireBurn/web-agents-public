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
 * Copyright 2014 - 2016 ForgeRock AS.
 */

#include "platform.h"
#include "thread.h"

#include "alloc.h"
#include "agent_cache.h"

#define THREADS                             5

#define DATA_BUFFER_SZ                      0x1000
#define DATA_OFFSET_MASK                    0xfff

#define RANDOM_BUFFER_SZ                    0x2000
#define RANDOM_OFFSET_MASK                  0x1fff


#define rotate64(v, n)                      (((v) << (n)) | ((v) >> (64 - (n))))

#ifndef offsetof
#define offsetof(type, field)               ( (char *)(&((type *)0)->field) - (char *)0 )
#endif

struct bucket
{
    uint32_t                                key;

    uint64_t                                checksum;
    size_t                                  ln;
    uint8_t                                 data[DATA_BUFFER_SZ];

};


uint8_t                                     random_buffer[RANDOM_BUFFER_SZ];          /* reduce time generating random data */


static void initialise_random_buffer()
{
    int                                     i;

    //srandomdev();

    for (i = 0; i < RANDOM_BUFFER_SZ; i++)
    {
        random_buffer[i] = rand() & 0xff;
    }

}


void write_bucket(uint32_t key, struct bucket *bucket)
{
    uint64_t                                checksum = 0x43f42a71e03;
    uint32_t                                seed = rand();
    int                                     i;

    bucket->key = key;
    bucket->ln = 1 + (seed & DATA_OFFSET_MASK);

    for (i = 0; i < bucket->ln; i++)
    {
        bucket->data[i] = random_buffer[(seed + i) & RANDOM_OFFSET_MASK];

        checksum = rotate64(checksum, 3) ^ bucket->data[i];
    }
   
    bucket->checksum = checksum;

}

int verify_bucket(struct bucket *bucket)
{
    uint64_t                                checksum = 0x43f42a71e03;
    int                                     i;

    for (i = 0; i < bucket->ln; i++)
    {
        checksum = rotate64(checksum, 3) ^ bucket->data[i];
    }
   
    return bucket->checksum == checksum;

}

static int bucket_identity(void *a, void *b)
{
    return ((struct bucket *)a)->key == ((struct bucket *)b)->key;

}

void *cache_robustness_thread(void *data)
{
    struct bucket                           bucket;
    void                                   *ptr;
    uint32_t                                ln;

    int                                     i;

    int                                     n_iters = 10000, iter;
    int                                     n_ops = 4096;

    uint32_t                                n_keys = 0x7fff;

    for (iter = 0; iter < n_iters; iter++)
    {
        for (i = 1; i < n_ops; i++)
        {
            uint32_t                        key = ((uint32_t)rand()) & n_keys;

            write_bucket(key, &bucket);

            if (cache_add(key, &bucket, offsetof(struct bucket, data) + bucket.ln, time(0) + 2, bucket_identity))
            {
                printf("error adding cache item\n");                                  /* acceptable during high load and recovery */
            }
        }

        for (i = 1; i < n_ops; i++)
        {
            uint32_t                        key = ((uint32_t)rand()) & n_keys;

            bucket.key = key;

            if (cache_get_readlocked_ptr(key, &ptr, &ln, &bucket, time(0), bucket_identity))
            {
                /* deleted */
            }
            else
            {
                if (verify_bucket(ptr) == 0)
                {
                    printf("*** bucket verification error\n");
                }
                cache_release_readlocked_ptr(key);
            }
        }

        for (i = 1; i < n_ops; i++)
        {
            uint32_t                        key = ((uint32_t)rand()) & n_keys;

            bucket.key = key;

            cache_delete(key, &bucket, bucket_identity);
        }
    }

    return data;

}

void *cache_update_thread(void *data)
{
    struct bucket                           bucket;
    void                                   *ptr;
    uint32_t                                ln;

    int                                     i;

    int                                     n_iters = 10000, iter;
    int                                     n_ops = 4096;

    uint32_t                                n_keys = 0x1fffff;

    for (iter = 0; iter < n_iters; iter++)
    {
        for (i = 1; i < n_ops; i++)
        {
            uint32_t                        key = ((uint32_t)rand()) & n_keys;

            bucket.key = key;

            if (i & 0x1)
            {
                write_bucket(key, &bucket);

                cache_add(key, &bucket, offsetof(struct bucket, data) + bucket.ln, time(0) + 60, bucket_identity);
            }
            else if (cache_get_readlocked_ptr(key, &ptr, &ln, &bucket, time(0), bucket_identity))
            {
                write_bucket(key, &bucket);

                cache_add(key, &bucket, offsetof(struct bucket, data) + bucket.ln, time(0) + 60, bucket_identity);
            }
            else
            {
                if (verify_bucket(ptr) == 0)
                {
                    printf("*** bucket verification error\n");
                }
                cache_release_readlocked_ptr(key);
            }
        }
    }

    return data;

}

int main(int argc, char *argv[])
{
    am_thread_t                             threads[THREADS];
    long                                    args[THREADS];

    int                                     i;
    long                                    t0;
    double                                  dt;

    if (cache_initialise(0))
    {
        printf("unable to initialise cache\n");
        exit(0);
    }


    if (argc == 2 && strcmp(argv[1], "--destroy") == 0)
    {
        cache_shutdown(1);                                                            /* one-off delete shared resources */

        exit(0);
    }

    if (argc == 2 && strcmp(argv[1], "--gc") == 0)
    {
        pid_t                               pid = getpid();                           /* run as garbage collection thread */

        do
        {
            agent_memory_validate(pid);

            t0 = clock();
            cache_garbage_collect();
            dt = ((double) (clock() - t0)) / CLOCKS_PER_SEC;

            cache_stats();

            printf("gc takes %lf secs\n", dt);

            sleep(2);

        } while (1);

        exit(0);
    }

    if (argc == 2 && strcmp(argv[1], "--expire") == 0)
    {
        pid_t                               pid = getpid();                           /* run as an expiry thread */

        do
        {
            agent_memory_validate(pid);

            t0 = clock();
            cache_readlock_total_barrier(pid);
            dt = ((double) (clock() - t0)) / CLOCKS_PER_SEC;

            printf("barrier takes %lf secs\n", dt);

            t0 = clock();
            cache_purge_expired_entries(pid);
            dt = ((double) (clock() - t0)) / CLOCKS_PER_SEC;

            printf("expiry scan takes %lf secs\n", dt);

            sleep(2);

        } while (1);

        exit(0);
    }

    if (argc == 2 && strcmp(argv[1], "--error") == 0)
    {
        agent_memory_error();                                                         /* one-off trigger global cache reset */

        exit(0);
    }

    initialise_random_buffer();

    t0 = clock();

    for (i = 0; i < THREADS; i++)
    {
        args [i] = 0;

        AM_THREAD_CREATE(threads[i], cache_robustness_thread, args + i);
    }

    for (i = 0; i < THREADS; i++)
    {
        AM_THREAD_JOIN(threads[i]);
    }

    dt = ((double) (clock() - t0)) / CLOCKS_PER_SEC;
    printf("finished after %lf secs\n", dt);

    agent_memory_check(getpid(), 0, 0);

    cache_shutdown(0);

    exit(0);

}

