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

/**
 ** test utility for read-write lock using sysv semaphores
 **
 **
 **/

#include "platform.h"
#include "thread.h"

#include "rwlock.h"

#define THREADS                             21

#define N_SEMS                              128

#define MAX_DATA_LN                         4096

#define rotate64(v, n)                      (((v) << (n)) | ((v) >> (64 - (n))))

struct bucket
{
    uint64_t                                checksum;
    size_t                                  ln;
    uint8_t                                 data[MAX_DATA_LN];

};

struct readlock                            *locks;

struct bucket                               bucket;


static void initialise_locks()
{
    int                                     i;

    locks = malloc(N_SEMS * sizeof(struct readlock));

    for (i = 0; i < N_SEMS; i++)
    {
        locks[i] = readlock_init;
    }

}

void update_bucket(struct bucket *bucket)
{
    uint64_t                                checksum = 0x43f42a71e03;
    int                                     i;

    bucket->ln = rand() % MAX_DATA_LN;

    for (i = 0; i < bucket->ln; i++)
    {
        bucket->data[i] = rand();

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

void *multi_lock_thread(void *data)
{
    int                                     self = *(int *)data;
    pid_t                                   pid = getpid();

    int                                     i;
    int                                     updates = 0, busy = 0;

    for (i = 0; i < 10000000; i++)
    {
        int                                 l = 0;//rand() % N_SEMS;

        if (i&1)
        {
            if (read_lock(locks + l, pid))
            {
                if (verify_bucket(&bucket) == 0)
                {
                    printf("******** bucket not stable, lock counter -> %d\n", locks[l].readers);
                    return 0;
                }
                read_release(locks + l, pid);
            }
            else
            {
                printf("%d:%d failed lock %d readlock\n", pid, self, (int)l);
            }
        }
        else
        {
            if (read_lock(locks + l, pid))
            {
                if (read_try_unique(locks + l, 10))
                {
                    update_bucket(&bucket);
                    read_release_unique(locks + l);

                    updates++;
                }
                else
                {
                    busy++;
                }
                read_release(locks + l, pid);
            }
            else
            {
                printf("%d:%d failed lock %d writelock\n", pid, self, (int)l);
            }
        }

        if (i % 1000000 == 0)
        {
            printf("%d:%d iteration %d, updates %d out of %d\n", pid, self, i, updates, busy);
        }
    }

    return data;

}

void *single_lock_thread(void *data)
{
    int                                     self = *(int *)data;
    pid_t                                   pid = getpid();

    int                                     i;
    int                                     updates = 0, busy = 0, blocks = 0;

    for (i = 0; i < 10000000; i++)
    {
        int                                 l = 0;
        int                                 r = rand() & 3;

        if (r == 0)
        {
            if (read_lock(locks + l, pid))
            {
                if (verify_bucket(&bucket) == 0)
                {
                    printf("******** bucket not stable\n");
                }
                read_release(locks + l, pid);
            }
            else
            {
                printf("%d:%d failed lock %d readlock\n", pid, self, (int)l);
            }
        }
        else if (r == 1)
        {
            if (read_block(locks + l, pid))
            {
                update_bucket(&bucket);

                //usleep(1000);

                if (read_unblock(locks + l, pid) == 0)
                    printf("********* read unblock failed\n");

                blocks++;
            }
        }
        else if (r == 2)
        {
            if (read_lock_try(locks + l, pid, 1))
            {
                if (read_try_unique(locks + l, 1))
                {
                    update_bucket(&bucket);
                    read_release_unique(locks + l);

                    updates++;
                } 
                else
                {
                    busy++;
                }

                read_release(locks + l, pid);
            }
            else
            {
                //printf("%d:%d failed lock %d writelock\n", pid, self, (int)l);
            }
        }

        if (i % 100000 == 0)
        {
            printf("%d:%d iteration %d, wr %d (busy %d), blocks %d\n", pid, self, i, updates, busy, blocks);
        }
    }

    return data;

}


int main(int argc, char *argv[])
{
    am_thread_t                             threads[THREADS];
    int                                     args[THREADS];
    
    int                                     i;
    long                                    t0;
    double                                  dt;

    initialise_locks();

    update_bucket(&bucket);

    t0 = clock();
    
    for (i = 0; i < THREADS; i++)
    {
        args [i] = i;

        AM_THREAD_CREATE(threads[i], single_lock_thread, args + i);
    }

    for (i = 0; i < THREADS; i++)
    {
        AM_THREAD_JOIN(threads[i]);
    }
    
    dt = ((double) (clock() - t0)) / CLOCKS_PER_SEC;
    printf("finished after %lf secs\n", dt);
    
    exit(0);

}

