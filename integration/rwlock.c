
/*
 * this is a prototype for a robust, in-memory readlock, which is intended to ensure that readers cannot have
 * still be reading data that is inaccessible after it is unlinked
 *
 */

#include <stdio.h>

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <sched.h>
#include <signal.h>
#include <errno.h>

#include "rwlock.h"

#define cas(p, old, new)                    __sync_bool_compare_and_swap(p, old, new)
#define casv(p, old, new)                   __sync_val_compare_and_swap(p, old, new)
#define sync()                              __sync_synchronize()
#define inc(p)                              __sync_fetch_and_add((p), 1)
#define yield()                             sched_yield()

const struct readlock                       readlock_init = { .readers = 0, .barrier = 0, .pids = { 0 } };


static int try_read_barrier(struct readlock *lock, int tries)
{
    do
    {
        sync();

        if (lock->readers == 0)
        {
            return 1;
        }

        yield();

    } while (--tries);

    return 0;

}

/*
 * robust wait for readers to finish, by using the pid table to wait for it to empty
 * and discarding pids that are not running
 *
 * this will block all readers, but it should be quick because readers are very transient
 *
 */
static int try_robust_barrier(struct readlock *lock, pid_t pid) 
{
    int                                     i, j;

    int32_t                                 readers;

    pid_t                                   checker = 0;

    while (( checker = casv(&lock->barrier, 0, pid) ))
    {
        if (kill(checker, 0) && errno == ESRCH)
        {
            printf("checker is dead\n");
        }
        else
        {
            return 0;                                                                 // after some time, we can suspect this process
        }
    }

    do
    {
        int                                 n = 0;

        for (i = 0; i < THREAD_LIMIT; i++)
        {
            pid_t                           writer = lock->pids[i];

            if (writer)
            {
                if (kill(writer, 0) && errno == ESRCH)
                {
                    printf("recovery after termination of %d\n", pid);

                    for (j = i; j < THREAD_LIMIT; j++)
                    {
                        cas(lock->pids + i, writer, 0);
                    }
                    n++;
                }
            }
            else
            {
               n++;
            }
        }

        if (n == THREAD_LIMIT)
        {
            break;
        }

        usleep(10);                                                                   // wait for existing readers to complete

printf("waiting for %d threads\n", THREAD_LIMIT - n);
    } while (1);

    do
    {
        readers = lock->readers;

    } while (readers && cas(&lock->readers, readers, 0) == 0);

    cas(&lock->barrier, pid, 0);

printf("recovery complete\n");

    return 1;

}

static void check_barrier(struct readlock *lock, pid_t pid)
{
    pid_t                                   barrier = lock->barrier;

    if (barrier)
    {
        printf("lock barrier entry\n");

        do
        {
            if (try_robust_barrier(lock, pid))
            {
                break;
            }

            usleep(100);

            sync();

            barrier = lock->barrier;

        } while (barrier);

        printf("lock barrier exit\n");
    }

}

/*
 * wait forever for extant readers to complete
 *
 */
int wait_for_barrier(struct readlock *lock, pid_t pid)
{
    int                                     i = 0;

    do
    {
        if (try_read_barrier(lock, 100))
        {
            return 1;
        }

        usleep(100);

        i++;

    } while (i < 100);

    do
    {
        printf("%d try wait for robust barrier\n", pid);

        if (try_robust_barrier(lock, pid))
        {
            return 1;
        }

        usleep(1000);

        i++;

    } while (1);

    return 1;

}

static int cas_array32(volatile int32_t *array, size_t array_ln, int32_t old, int32_t new)
{
    int                                     i;

    for (i = 0; i < array_ln; i++)
    {
        if (cas(array + i, old, new))
        {
            return 1;
        }
    }
    return 0;

}

int read_lock(struct readlock *lock, pid_t pid)
{
    do
    {
        int                                 tries = 1000;

        check_barrier(lock, pid);
                                                                                      // needed for robust barrier, also ensures size limit
        while (cas_array32(lock->pids, THREAD_LIMIT, 0, pid) == 0)
        {
            yield();

            wait_for_barrier(lock, pid);                                              // attempt to allow write locks
        }

        do
        {
            uint32_t                        readers = lock->readers;
    
            if (readers == THREAD_LIMIT)
            {
                if (try_read_barrier(lock, 10) && cas(&lock->readers, 0, 1))
                {
                    return 1;
                }

                break;                                                                // wait for barrier, robustly if necessary
            }
            else if (cas(&lock->readers, readers, readers + 1))
            {
                return 1;
            }

            usleep(100);

            sync();

        } while (--tries);

        while (cas_array32(lock->pids, THREAD_LIMIT, pid, 0) == 0)                    // should never fail
        {
            yield();
        }

        wait_for_barrier(lock, pid);

    } while (1);

}

int read_lock_try(struct readlock *lock, pid_t pid, int tries)
{
    check_barrier(lock, pid);

    if (cas_array32(lock->pids, THREAD_LIMIT, 0, pid) == 0)
    {
        return 0;
    }

    do
    {
        uint32_t                            readers = lock->readers;

        if (readers < THREAD_LIMIT && cas(&lock->readers, readers, readers + 1))
        {
            return 1;
        }

        yield();            

        sync();

    } while (--tries);

    while (cas_array32(lock->pids, THREAD_LIMIT, pid, 0) == 0)                        // should never fail
    {
        yield();            
    }

    return 0;

}


int read_try_unique(struct readlock *lock, int tries)
{
    do
    {
if (lock->readers == 0) printf("*********** i don't have a readlock\n");

        if (cas(&lock->readers, 1, THREAD_LIMIT))
        {
            return 1;
        }

        yield();            

    } while (--tries);

    return 0;

}

int read_release_unique(struct readlock *lock)
{
    do
    {
        if (cas(&lock->readers, THREAD_LIMIT, 1))
        {
            return 1;
        }
printf("lock_release_unique: readers -> %d\n", lock->readers);

        yield();            

    } while (1);

}

int read_release_all(struct readlock *lock, pid_t pid)
{
    do
    {
        if (cas(&lock->readers, THREAD_LIMIT, 0))
        {
            break;
        }
printf("lock_release_unique: readers -> %d\n", lock->readers);

        yield();            

    } while (1);

    while (cas_array32(lock->pids, THREAD_LIMIT, pid, 0) == 0)                        // should never fail
    {
        yield();            
    }

    return 1;

}

int read_release(struct readlock *lock, pid_t pid)
{
    uint32_t                                readers;

    do
    {
        readers = lock->readers;

        if (cas(&lock->readers, readers, readers - 1))
        {
            break;
        }
        yield();            

    } while (1);

if (lock->readers < 0) printf("***** read_release: readers -> %d \n", readers);

    while (cas_array32(lock->pids, THREAD_LIMIT, pid, 0) == 0)                        // should never fail
    {
        yield();            
    }

    return 1;

}

