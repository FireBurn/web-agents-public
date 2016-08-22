
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
static int wait_for_counted_readers(struct readlock *lock, int tries)
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
 * determine whether a process is live
 *
 */
static int process_dead(pid_t pid)
{
    if (kill(pid, 0))
    {
        if (errno == ESRCH)
        {
            return 1;
        }
printf("************** after kill, errno was %d\n", errno);
    }
    return 0;

}

/*
 * robust wait for readers to finish, by using the pid table to wait for it to empty
 * and discarding pids that are not running
 *
 * this will block all readers, but it should be quick because readers are very transient
 *
 */
static int wait_for_live_readers(struct readlock *lock, pid_t pid, int unblock) 
{
    int                                     i, j;

    pid_t                                   checker = 0;

    if (( checker = casv(&lock->barrier, 0, pid) ))
    {
        if (checker == pid)
        {
            return 0;                                                                 // this process is already the checker, wait 
        }
        else if (process_dead(checker))
        {
            if (cas(&lock->barrier, checker, pid))
            {
                printf("rwlock: %d takes over as checker\n", pid);                    // this process takes over as checker
            }
            else
            {
                return 0;                                                             // another process has become the checker
            }
        }
        else
        {
            return 0;                                                                 // a live process is the checker, wait for it to finish
        }
    }

    do
    {
        int                                 n = 0;

        for (i = 0; i < THREAD_LIMIT; i++)
        {
            pid_t                           writer;

            if (( writer = casv(lock->pids + i, 0, -1) ))
            {
                if (writer == -1)
                {
                    n++;
                }
                else if (process_dead(writer))
                {
printf("rwlock: %d sees termination of %d\n", pid, writer);
                    for (j = i; j < THREAD_LIMIT; j++)
                    {
                        cas(lock->pids + j, writer, -1);                              // remove pids for threads of a dead process
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

    int32_t                                 readers = lock->readers;

    while (cas(&lock->readers, readers, 0) == 0)
    {
        yield();

        readers = lock->readers;
    }

    if (unblock)
    {
        for (i = 0; i < THREAD_LIMIT; i++)
        {
            cas(lock->pids + i, -1, 0);
        }
        cas(&lock->barrier, pid, 0);
    }

    return 1;

}

/*
 * robust wait for extant readers to complete, leaving the lock blocked
 *
 */
int read_block(struct readlock *lock, pid_t pid)
{
    return wait_for_live_readers(lock, pid, 0);

}

/*
 * unblock the lock after read_block() has succeeded
 *
 */
int read_unblock(struct readlock *lock, pid_t pid)
{
    int                                     i;

    for (i = 0; i < THREAD_LIMIT; i++)
    {
        cas(lock->pids + i, -1, 0);
    }

    return cas(&lock->barrier, pid, 0);

}

/*
 * wait for any lock check to complete, and take over if checker is not live
 *
 */
static void ensure_liveness(struct readlock *lock, pid_t pid)
{
    pid_t                                   checker = lock->barrier;

    if (checker)
    {
        do
        {
            if (wait_for_live_readers(lock, pid, 1))
            {
                break;
            }

            usleep(100);

            sync();

            checker = lock->barrier;

        } while (checker);
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
        if (wait_for_counted_readers(lock, 100))
        {
            return 1;
        }

        usleep(100);

        i++;

    } while (i < 100);

    do
    {
        if (wait_for_live_readers(lock, pid, 1))
        {
            return 1;
        }

        usleep(100);

        i++;

    } while (1);

    return 1;

}

/*
 * atomically add a pid (which represents a thread in a process) to a fixed size array
 *
 */
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
 * get read lock, trying to ensure that writers are not starved by enforing a "barrier" where readers -> zero, and
 * remove pid and retry with robust barrier if it is taking too long
 *
 */
int read_lock(struct readlock *lock, pid_t pid)
{
    do
    {
        int                                 tries = 1000;

        ensure_liveness(lock, pid);
                                                                                      // ensure that any checker can complete
        while (cas_array32(lock->pids, THREAD_LIMIT, 0, pid) == 0)
        {
            yield();

            wait_for_barrier(lock, pid);                                              // allow write locks by waiting for lockers to complete
        }

        do
        {
            int32_t                         readers = lock->readers;
    
            if (readers < THREAD_LIMIT)
            {
                if (cas(&lock->readers, readers, readers + 1))
                {
                    return 1;
                }
            }
            else if (wait_for_counted_readers(lock, 100) == 0)
            {
                break;                                                                // too much contention or blockage
            }
            yield();

        } while (--tries);

        while (cas_array32(lock->pids, THREAD_LIMIT, pid, 0) == 0)                    // should never fail
        {
            yield();
        }

        wait_for_live_readers(lock, pid, 1);                                          // ensure robustly that writers momentarily go to zero

    } while (1);

}

/*
 * non-waiting read lock
 *
 */
int read_lock_try(struct readlock *lock, pid_t pid, int tries)
{
    if (cas_array32(lock->pids, THREAD_LIMIT, 0, pid) == 0)
    {
        return 0;
    }

    do
    {
        int32_t                             readers = lock->readers;

        if (readers < THREAD_LIMIT && cas(&lock->readers, readers, readers + 1))
        {
            return 1;
        }

        yield();            

    } while (--tries);

    while (cas_array32(lock->pids, THREAD_LIMIT, pid, 0) == 0)                        // should never fail
    {
        yield();            
    }

    return 0;

}

/*
 * non-blocking attempt to get write lock
 *
 */
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

/*
 * conversion of write lock to read lock
 *
 */
int read_release_unique(struct readlock *lock)
{
    do
    {
        if (cas(&lock->readers, THREAD_LIMIT, 1))
        {
            return 1;
        }
printf("lock_release_unique: *************** readers -> %d\n", lock->readers);

        yield();            

    } while (1);

}

/*
 * release of write lock
 *
 */
int read_release_all(struct readlock *lock, pid_t pid)
{
    do
    {
        if (cas(&lock->readers, THREAD_LIMIT, 0))
        {
            break;
        }
printf("lock_release_unique: **************** readers -> %d\n", lock->readers);

        yield();            

    } while (1);

    while (cas_array32(lock->pids, THREAD_LIMIT, pid, 0) == 0)                        // should never fail
    {
        yield();            
    }

    return 1;

}

/*
 * release of read lock
 *
 */
int read_release(struct readlock *lock, pid_t pid)
{
    int32_t                                 readers = lock->readers;

    do
    {
        if (readers)
        {
            if (cas(&lock->readers, readers, readers - 1))
            {
                break;
            }
        }
        else
        {
printf("lock_release: *************** count error has occurredn");
            break;
        }
        
        yield();            

        readers = lock->readers;

    } while (1);

    while (cas_array32(lock->pids, THREAD_LIMIT, pid, 0) == 0)                        // should never fail
    {
        yield();            
    }

    return 1;

}

