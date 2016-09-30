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


/*
 * this is a robust, in-memory read/write lock
 *
 */

#include "platform.h"
#include "am.h"
#include "log.h"

#include "rwlock.h"

#if defined _WIN32

#define casv(p, old, new)                   InterlockedCompareExchange(p, new, old)
#define cas(p, old, new)                    (casv(p, old, new) == (old))
#define yield()                             SwitchToThread()

#else

#define casv(p, old, new)                   __sync_val_compare_and_swap(p, old, new)
#define cas(p, old, new)                    __sync_bool_compare_and_swap(p, old, new)
#define yield()                             sched_yield()

#endif


const struct readlock                       readlock_init = { .readers = 0, .barrier = 0, .pids = { 0 } };


/*
 * check whether a process is dead
 *
 */
static int process_dead(pid_t pid) {
    static const char                      *thisfunc = "process_dead():";
#if defined _WIN32
    HANDLE                                  h;
    if (( h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) )) {         /* expected error is ERROR_INVALID_PARAMETER */
        int                                 exitcode, done = 0;
        if (GetExitCodeProcess(h, &exitcode)) {
            if (exitcode != STILL_ACTIVE)
                done = 1;
        } else {
            AM_LOG_DEBUG(0, "%s unable to verify liveness of locking process %"PR_L64" (error %d)",
                             thisfunc, (int64_t)pid, GetLastError());                 /* permissions error */
        }
        CloseHandle(h);
        return done;
    } else if (GetLastError() == ERROR_ACCESS_DENIED) {
        AM_LOG_DEBUG(0, "%s unable to verify liveness of locking process %"PR_L64" (error %d)",
                         thisfunc, (int64_t)pid, GetLastError());                     /* permissions error */
    }
    return 1;
#else
    if (kill(pid, 0)) {
        if (errno == ESRCH) {
            return 1;
        } else {
            AM_LOG_DEBUG(0, "%s unable to verify liveness of locking process %"PR_L64" (error %d)",
                             thisfunc, (int64_t)pid, errno);                         /* permissions error */
        }
    }
    return 0;
#endif
}

/*
 * quick test whether all readers are finished with the lock; it is used to ensure that writers are not starved
 *
 */
static int wait_for_counted_readers(struct readlock *lock, int tries) {

    do {
        if (lock->readers == 0) {
            return 1;
        }

        yield();

    } while (--tries);                                                                /* NOTE: tries must be a positive number */

    return 0;

}

/*
 * robust wait for readers to finish, by using the pid table to wait for it to empty
 * and discarding pids that are not running
 *
 * this will block all readers, but it should be quick because readers are very transient
 *
 */
static int wait_for_live_readers(struct readlock *lock, pid_t pid, int unblock) {
    static const char                      *thisfunc = "wait_for_live_readers():";

    pid_t                                   checker = 0;

    if (( checker = casv(&lock->barrier, 0, pid) )) {
        if (checker == pid) {
            return 0;                                                                 /* this process is already the checker, wait  */
        } else if (process_dead(checker)) {
            if (cas(&lock->barrier, checker, pid)) {
                AM_LOG_DEBUG(0, "%s rwlock recovery: %"PR_L64" takes over from %"PR_L64"",
                                 thisfunc, (int64_t)pid, (int64_t)checker);           /* this process takes over as checker */
            } else {
                return 0;                                                             /* another process has become the checker */
            }
        } else {
            return 0;                                                                 /* a live process is the checker, wait for it to finish */
        }
    }

    do {
        int                                 n = 0;

        for (int i = 0; i < THREAD_LIMIT; i++) {
            pid_t                           writer;

            if (( writer = casv(lock->pids + i, 0, -1) )) {
                if (writer == -1) {
                    n++;
                } else if (process_dead(writer)) {
                    for (int j = i; j < THREAD_LIMIT; j++) {
                        cas(lock->pids + j, writer, -1);                              /* remove pids for threads of a dead process */
                    }
                    n++;
                }
            } else {
               n++;
            }
        }

        if (n == THREAD_LIMIT) {
            break;
        }

        yield();                                                                      /* wait for existing readers to complete */

    } while (1);

    int32_t                                 readers = lock->readers;

    while (cas(&lock->readers, readers, 0) == 0) {
        yield();

        readers = lock->readers;
    }

    if (unblock) {
        for (int i = 0; i < THREAD_LIMIT; i++) {
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
int read_block(struct readlock *lock, pid_t pid) {

    return wait_for_live_readers(lock, pid, 0);

}

/*
 * unblock the lock after read_block() has succeeded
 *
 */
int read_unblock(struct readlock *lock, pid_t pid) {

    for (int i = 0; i < THREAD_LIMIT; i++) {
        cas(lock->pids + i, -1, 0);
    }

    return cas(&lock->barrier, pid, 0);

}

/*
 * wait for any lock check to complete, and take over if checker is not live
 *
 */
static void ensure_liveness(struct readlock *lock, pid_t pid) {

    pid_t                                   checker = lock->barrier;

    if (checker) {
        do {
            if (wait_for_live_readers(lock, pid, 1)) {
                break;
            }

            yield();     

            checker = lock->barrier;

        } while (checker);
    }

}

/*
 * wait forever for extant readers to complete
 *
 */
int wait_for_barrier(struct readlock *lock, pid_t pid) {

    int                                     i = 0;

    do {
        if (wait_for_counted_readers(lock, 100)) {
            return 1;
        }

        yield();     

        i++;

    } while (i < 100);

    do {
        if (wait_for_live_readers(lock, pid, 1)) {
            return 1;
        }

        yield();     

        i++;

    } while (1);

    return 1;

}

/*
 * atomically add a pid (which represents a thread in a process) to a fixed size array
 *
 */
static int add_pid_to_array(volatile pid_t *array, size_t array_ln, pid_t old, pid_t new) {

    for (int i = 0; i < array_ln; i++) {
        if (cas(array + i, old, new)) {
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
int read_lock(struct readlock *lock, pid_t pid) {

    do {
        int                                 tries = 1000;

        ensure_liveness(lock, pid);
                                                                                      /* ensure that any checker can complete */
        while (add_pid_to_array(lock->pids, THREAD_LIMIT, 0, pid) == 0) {
            yield();

            wait_for_barrier(lock, pid);                                              /* allow write locks by waiting for lockers to complete */
        }

        do {
            int32_t                         readers = lock->readers;
    
            if (readers < THREAD_LIMIT) {
                if (cas(&lock->readers, readers, readers + 1)) {
                    return 1;
                }
            } else if (wait_for_counted_readers(lock, 100) == 0) {
                break;                                                                /* too much contention or blockage */
            }
            yield();

        } while (--tries);

        while (add_pid_to_array(lock->pids, THREAD_LIMIT, pid, 0) == 0) {             /* should never fail */
            yield();
        }

        wait_for_live_readers(lock, pid, 1);                                          /* ensure robustly that writers momentarily go to zero */

    } while (1);

}

/*
 * non-waiting read lock
 *
 */
int read_lock_try(struct readlock *lock, pid_t pid, int tries) {

    if (add_pid_to_array(lock->pids, THREAD_LIMIT, 0, pid) == 0) {
        return 0;
    }

    do {
        int32_t                             readers = lock->readers;

        if (readers < THREAD_LIMIT && cas(&lock->readers, readers, readers + 1)) {
            return 1;
        }

        yield();            

    } while (--tries);

    while (add_pid_to_array(lock->pids, THREAD_LIMIT, pid, 0) == 0) {                 /* should never fail */
        yield();            
    }

    return 0;

}

/*
 * non-blocking attempt to get write lock
 *
 */
int read_try_unique(struct readlock *lock, int tries) {

    do {

        if (cas(&lock->readers, 1, THREAD_LIMIT)) {
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
int read_release_unique(struct readlock *lock) {

    do {
        if (cas(&lock->readers, THREAD_LIMIT, 1)) {
            return 1;
        }

        yield();            

    } while (1);

}

/*
 * release of write lock
 *
 */
int read_release_all(struct readlock *lock, pid_t pid) {

    do {
        if (cas(&lock->readers, THREAD_LIMIT, 0)) {
            break;
        }

        yield();            

    } while (1);

    while (add_pid_to_array(lock->pids, THREAD_LIMIT, pid, 0) == 0) {                 /* should never fail */
        yield();            
    }

    return 1;

}

/*
 * release of read lock
 *
 */
int read_release(struct readlock *lock, pid_t pid) {

    int32_t                                 readers = lock->readers;

    do {
        if (readers) {
            if (cas(&lock->readers, readers, readers - 1)) {
                break;
            }
        } else {
            break;
        }
        
        yield();            

        readers = lock->readers;

    } while (1);

    while (add_pid_to_array(lock->pids, THREAD_LIMIT, pid, 0) == 0) {                 /* should never fail */
        yield();            
    }

    return 1;

}

