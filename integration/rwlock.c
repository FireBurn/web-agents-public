
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


/*
 * quick test whether all readers are finished with the lock; it is used to ensure that writers are not starved
 *
 */
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

    } while (--tries);                                                                // NOTE: tries must be a positive number

    return 0;

}

/*
 * robust wait for readers to finish, by using the pid table to wait for it to empty
 * and discarding pids that are not running
 *
 * this will block all readers, but it should be quick because readers are very transient
 *
 */
static int try_robust_barrier(struct readlock *lock, pid_t pid, int unblock) 
{
    int                                     i, j;

    int32_t                                 readers;

    pid_t                                   checker = 0;

    while (( checker = casv(&lock->barrier, 0, pid) ))
    {
        if (checker == pid)
        {
            return 0;
        }
        else if (kill(checker, 0) && errno == ESRCH)
        {
            if (cas(&lock->barrier, checker, pid))
            {
                printf("rwlock: %d takes over as checker\n", pid);

                break;                                                                // this thread becomes the checker
            }
            else
            {
                printf("rwlock: %d gives up being checker\n", pid);

                return 0;
            }
        }
        else
        {
            return 0;                                                                 // after some time, we should suspect this process
        }
        yield();
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
                    printf("rwlock: recovery after termination of %d\n", writer);

                    for (j = i; j < THREAD_LIMIT; j++)
                    {
                        cas(lock->pids + j, writer, 0);                               // FIXME: this *was* completely wrong..
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

    } while (1);

    do
    {
        readers = lock->readers;

    } while (readers && cas(&lock->readers, readers, 0) == 0);

    if (unblock)
    {
        cas(&lock->barrier, pid, 0);
    }

    return 1;

}

int read_block(struct readlock *lock, pid_t pid)
{
    return try_robust_barrier(lock, pid, 0);

}

int read_unblock(struct readlock *lock, pid_t pid)
{
    return cas(&lock->barrier, pid, 0);

}

static void check_barrier(struct readlock *lock, pid_t pid)
{
    pid_t                                   barrier = lock->barrier;

    if (barrier)
    {
        do
        {
            if (try_robust_barrier(lock, pid, 1))
            {
                break;
            }

            usleep(100);

            sync();

            barrier = lock->barrier;

        } while (barrier);
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
#if 0
        printf("rwlock: %d try wait for robust barrier\n", pid);                      // FIXME: leave this for now, to ensure we don't have too much unless checking 
#endif

        if (try_robust_barrier(lock, pid, 1))
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

/*
 * get a read lock, trying to ensure that writers are not starved by enforing a "barrier" where readers -> zero, and
 * remove pid and retry with robust barrier if it is taking too long
 *
 */
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
    if (lock->barrier)                                                               // this must not wait during recovery
    {
        return 0;
    }

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

