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
#include "am.h"
#include "utility.h"
#include "version.h"
#include "thread.h"
#if defined(__sun)
#include <port.h>
#endif
#if defined(__APPLE__)
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#define AM_MIN_THREADS_POOL 2
#define AM_THREADS_POOL_LINGER 30 /* sec */

/* helper structure to wrap various callbacks, args and platforms */
struct am_callback_args {
    void *args;
    void (*callback)(void *);
};

#ifdef _WIN32
static INIT_ONCE worker_pool_initialized = INIT_ONCE_STATIC_INIT;
static PTP_CALLBACK_ENVIRON worker_env = NULL;
static PTP_POOL worker_pool = NULL;
static PTP_CLEANUP_GROUP worker_pool_cleanup = NULL;
#else
static pthread_once_t worker_pool_initialized = PTHREAD_ONCE_INIT;
static pthread_once_t worker_pool_main_initialized = PTHREAD_ONCE_INIT;
static sigset_t fillset;

enum {
    AM_THREADPOOL_WAIT = 0x01,
    AM_THREADPOOL_DESTROY = 0x02
};

struct am_threadpool_work {
    void (*func) (void *);
    void *arg;
    struct am_threadpool_work *next;
};

struct am_threadpool {
    pthread_mutex_t lock;
    pthread_cond_t busy;
    pthread_cond_t work;
    pthread_cond_t wait;
    struct am_threadpool_work *head;
    struct am_threadpool_work *tail;
    pthread_attr_t attr;
    int flag;
    int linger; /* number of seconds excess idle worker threads (greater than min_threads) linger before exiting */
    int min_threads; /* minimum number of threads kept in the pool */
    int max_threads; /* maximum number of threads that can be in the pool */
    int num_threads; /* current number of worker threads */
    int idle; /* number of idle worker threads */

    struct am_threadpool_active {
        pthread_t thread;
        struct am_threadpool_active *next;
    } *active; /* list of active threads */
};

static struct am_threadpool *worker_pool = NULL;
static struct am_threadpool *worker_pool_main = NULL;

static void *do_work(void *arg);

static int create_worker(struct am_threadpool *pool) {
    sigset_t oset;
    int error;
    pthread_t thread;
    pthread_sigmask(SIG_SETMASK, &fillset, &oset);
    error = pthread_create(&thread, &pool->attr, do_work, pool);
    pthread_sigmask(SIG_SETMASK, &oset, NULL);
    return error;
}

static void worker_cleanup(void *arg) {
    struct am_threadpool *pool = (struct am_threadpool *) arg;
    --pool->num_threads;
    if (pool->flag & AM_THREADPOOL_DESTROY) {
        if (pool->num_threads == 0) {
            pthread_cond_broadcast(&pool->busy);
        }
    } else if (pool->head != NULL && pool->num_threads < pool->max_threads &&
            create_worker(pool) == 0) {
        pool->num_threads++;
    }
    pthread_mutex_unlock(&pool->lock);
}

static void worker_notify(struct am_threadpool *pool) {
    if (pool->head == NULL && pool->active == NULL) {
        pool->flag &= ~AM_THREADPOOL_WAIT;
        pthread_cond_broadcast(&pool->wait);
    }
}

static void work_cleanup(void *arg) {
    struct am_threadpool *pool = (struct am_threadpool *) arg;
    pthread_t thread = pthread_self();
    struct am_threadpool_active *a, **b;

    pthread_mutex_lock(&pool->lock);
    for (b = &pool->active; (a = *b) != NULL; b = &a->next) {
        if (a->thread == thread) {
            *b = a->next;
            break;
        }
    }
    if (pool->flag & AM_THREADPOOL_WAIT) {
        worker_notify(pool);
    }
}

void am_clock_gettime(struct timespec *ts) {
#ifdef __APPLE__ 
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_REALTIME, ts);
#endif
}

static void cleanup_unlock_mutex(void *arg) {
    pthread_mutex_unlock(arg);
}

static void *do_work(void *arg) {
    struct am_threadpool *pool = (struct am_threadpool *) arg;
    struct am_threadpool_work *cur;
    struct am_threadpool_active active;
    int timed_out;
    struct timespec ts;
    void (*func) (void *arg);
    void *func_arg;

    /* worker thread main loop */
    pthread_mutex_lock(&pool->lock);
    /* maintain pool integrity in case work function calls pthread_exit() */
    pthread_cleanup_push(worker_cleanup, pool);
    active.thread = pthread_self();

    while (1) {
        /* reset (this) thread signal mask and cancellation state back to the initial values 
         * (since the last work performed) */
        pthread_sigmask(SIG_SETMASK, &fillset, NULL);
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

        timed_out = 0;

        pool->idle++;
        if (pool->flag & AM_THREADPOOL_WAIT) {
            worker_notify(pool);
        }
        while (pool->head == NULL && !(pool->flag & AM_THREADPOOL_DESTROY)) {
            if (pool->num_threads <= pool->min_threads) {
                pthread_cond_wait(&pool->work, &pool->lock);
            } else {
                am_clock_gettime(&ts);
                ts.tv_sec += pool->linger;
                if (pool->linger == 0 || pthread_cond_timedwait(&pool->work, &pool->lock, &ts) == ETIMEDOUT) {
                    timed_out = 1;
                    break;
                }
            }
        }
        pool->idle--;

        if (pool->flag & AM_THREADPOOL_DESTROY) {
            /* pool is being destroyed - exit now */
            break;
        }

        if ((cur = pool->head) != NULL) {
            timed_out = 0;
            /* take out am_threadpool_work from the list and execute it */
            func = cur->func;
            func_arg = cur->arg;

            pool->head = cur->next;
            if (cur == pool->tail) {
                pool->tail = NULL;
            }
            active.next = pool->active;
            pool->active = &active;
            pthread_mutex_unlock(&pool->lock);

            /* do the actual work */
            pthread_cleanup_push(work_cleanup, pool);
            free(cur);
            func(func_arg);
            pthread_cleanup_pop(1);
        }
        if (timed_out && pool->num_threads > pool->min_threads) {
            /* thread timed out (waiting for work) and 
             * the number of workers exceeds the minimum - exit now */
            break;
        }
    }
    pthread_cleanup_pop(1);
    return NULL;
}

#endif

static
#ifdef _WIN32
BOOL CALLBACK
#else
void
#endif
create_threadpool(
#ifdef _WIN32
        PINIT_ONCE io, PVOID p, PVOID *c
#endif
        ) {
#ifdef _WIN32

    worker_pool = CreateThreadpool(NULL);
    if (worker_pool == NULL) {
        return FALSE;
    }

    SetThreadpoolThreadMaximum(worker_pool, AM_MAX_THREADS_POOL);
    SetThreadpoolThreadMinimum(worker_pool, AM_MIN_THREADS_POOL);

    worker_env = LocalAlloc(LPTR, sizeof (TP_CALLBACK_ENVIRON));
    if (worker_env == NULL) {
        CloseThreadpool(worker_pool);
        worker_pool = NULL;
        return FALSE;
    }
    InitializeThreadpoolEnvironment(worker_env);
    SetThreadpoolCallbackPool(worker_env, worker_pool);
    worker_pool_cleanup = CreateThreadpoolCleanupGroup();
    if (worker_pool_cleanup == NULL) {
        DestroyThreadpoolEnvironment(worker_env);
        LocalFree(worker_env);
        CloseThreadpool(worker_pool);
        worker_pool = NULL;
        worker_env = NULL;
        return FALSE;
    }
    SetThreadpoolCallbackCleanupGroup(worker_env, worker_pool_cleanup, NULL);
    return TRUE;

#else
    if (worker_pool != NULL) return;

    sigfillset(&fillset);

    worker_pool = (struct am_threadpool *) malloc(sizeof (struct am_threadpool));
    if (worker_pool == NULL) {
        return;
    }

    worker_pool->active = NULL;
    worker_pool->head = worker_pool->tail = NULL;
    worker_pool->flag = 0;
    worker_pool->linger = AM_THREADS_POOL_LINGER;
    worker_pool->min_threads = AM_MIN_THREADS_POOL;
    worker_pool->max_threads = AM_MAX_THREADS_POOL;
    worker_pool->num_threads = 0;
    worker_pool->idle = 0;

    pthread_attr_init(&worker_pool->attr);
    pthread_attr_setdetachstate(&worker_pool->attr, PTHREAD_CREATE_DETACHED);

    pthread_mutex_init(&worker_pool->lock, NULL);
    pthread_cond_init(&worker_pool->busy, NULL);
    pthread_cond_init(&worker_pool->work, NULL);
    pthread_cond_init(&worker_pool->wait, NULL);
#endif
}

#ifndef _WIN32

static void create_threadpool_main() {

    if (worker_pool_main != NULL) return;

    sigfillset(&fillset);

    worker_pool_main = (struct am_threadpool *) malloc(sizeof (struct am_threadpool));
    if (worker_pool_main == NULL) {
        return;
    }

    worker_pool_main->active = NULL;
    worker_pool_main->head = worker_pool_main->tail = NULL;
    worker_pool_main->flag = 0;
    worker_pool_main->linger = AM_THREADS_POOL_LINGER;
    worker_pool_main->min_threads = AM_MIN_THREADS_POOL;
    worker_pool_main->max_threads = AM_MAX_THREADS_POOL;
    worker_pool_main->num_threads = 0;
    worker_pool_main->idle = 0;

    pthread_attr_init(&worker_pool_main->attr);
    pthread_attr_setdetachstate(&worker_pool_main->attr, PTHREAD_CREATE_DETACHED);

    pthread_mutex_init(&worker_pool_main->lock, NULL);
    pthread_cond_init(&worker_pool_main->busy, NULL);
    pthread_cond_init(&worker_pool_main->work, NULL);
    pthread_cond_init(&worker_pool_main->wait, NULL);
}

#endif

/* Init thread pool in worker/child process */
void am_worker_pool_init() {
#ifdef _WIN32
    InitOnceExecuteOnce(&worker_pool_initialized, create_threadpool, NULL, NULL);
#else
    pthread_once(&worker_pool_initialized, create_threadpool);
#endif
}

/* Init thread pool in main process */
void am_worker_pool_init_main() {
#ifndef _WIN32
    pthread_once(&worker_pool_main_initialized, create_threadpool_main);
#endif
}

/**
 * Reset worker pool initialize-once flag. Must not be used outside unit-test module.
 */
void am_worker_pool_init_reset() {
#ifdef _WIN32
    INIT_ONCE once = INIT_ONCE_STATIC_INIT;
#else
    pthread_once_t once = PTHREAD_ONCE_INIT;
#endif
    memcpy(&worker_pool_initialized, &once, sizeof (worker_pool_initialized));
}

#ifdef _WIN32

static void CALLBACK worker_dispatch_callback(PTP_CALLBACK_INSTANCE instance, void *arg) {
    struct am_callback_args *cba = (struct am_callback_args *) arg;
    if (cba != NULL && cba->callback != NULL) {
        cba->callback(cba->args);
    }
    am_free(cba);
}

#endif

int am_worker_dispatch(void (*worker_f)(void *), void *arg) {
#ifdef _WIN32
    BOOL status = FALSE;
    struct am_callback_args *cb_arg;

    if (worker_pool == NULL || worker_env == NULL) {
        return AM_ENOTSTARTED;
    }

    cb_arg = (struct am_callback_args *) malloc(sizeof (struct am_callback_args));
    if (cb_arg != NULL) {
        cb_arg->args = arg;
        cb_arg->callback = worker_f;
        status = TrySubmitThreadpoolCallback(worker_dispatch_callback, cb_arg, worker_env);
    }
    return status == FALSE ? AM_ENOMEM : AM_SUCCESS;
#else
    struct am_threadpool_work *cur;
    struct am_threadpool *pool = NULL;

    if (worker_pool != NULL) {
        /* we've been requested to run a job from within a worker process */
        pool = worker_pool;
    } else if (worker_pool_main != NULL) {
        /* or from within main process */
        pool = worker_pool_main;
    }

    if (pool == NULL) return AM_EFAULT;

    cur = (struct am_threadpool_work *) malloc(sizeof (struct am_threadpool_work));
    if (cur == NULL) {
        return AM_ENOMEM;
    }

    cur->func = worker_f;
    cur->arg = arg;
    cur->next = NULL;

    pthread_mutex_lock(&pool->lock);

    if (pool->head == NULL) {
        pool->head = cur;
    } else {
        pool->tail->next = cur;
    }
    pool->tail = cur;

    if (pool->idle > 0) {
        /* if there is an idle worker in the pool - wake it up */
        pthread_cond_signal(&pool->work);
    } else if (pool->num_threads < pool->max_threads &&
            create_worker(pool) == 0) {
        /* new worker scheduled */
        pool->num_threads++;
    }

    pthread_mutex_unlock(&pool->lock);
    return AM_SUCCESS;
#endif
}

#ifndef _WIN32

static void worker_pool_shutdown(struct am_threadpool **threadpool) {
    struct am_threadpool_active *active;
    struct am_threadpool_work *work;
    struct am_threadpool *pool;

    if (threadpool == NULL || *threadpool == NULL) return;
    pool = *threadpool;

    pthread_mutex_lock(&pool->lock);
    pthread_cleanup_push(cleanup_unlock_mutex, &pool->lock);

    pool->flag |= AM_THREADPOOL_DESTROY;
    pthread_cond_broadcast(&pool->work);

    /* cancel all active workers */
    for (active = pool->active; active != NULL; active = active->next) {
        pthread_cancel(active->thread);
    }

    /* wait for all active workers to finish */
    while (pool->active != NULL) {
        pool->flag |= AM_THREADPOOL_WAIT;
        pthread_cond_wait(&pool->wait, &pool->lock);
    }

    while (pool->num_threads != 0) {
        pthread_cond_wait(&pool->busy, &pool->lock);
    }
    pthread_cleanup_pop(1);

    for (work = pool->head; work != NULL; work = pool->head) {
        pool->head = work->next;
        free(work);
    }

    pthread_attr_destroy(&pool->attr);
    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->busy);
    pthread_cond_destroy(&pool->work);
    pthread_cond_destroy(&pool->wait);
    free(pool);
    *threadpool = NULL;
}

#endif

/* Shut down thread pool in worker/child process */
void am_worker_pool_shutdown() {
#ifdef _WIN32
    if (worker_pool_cleanup != NULL) {
        CloseThreadpoolCleanupGroupMembers(worker_pool_cleanup, FALSE, NULL);
        CloseThreadpoolCleanupGroup(worker_pool_cleanup);
    }
    if (worker_env != NULL) {
        DestroyThreadpoolEnvironment(worker_env);
        LocalFree(worker_env);
    }
    if (worker_pool != NULL) {
        CloseThreadpool(worker_pool);
    }
    worker_pool_cleanup = NULL;
    worker_pool = NULL;
    worker_env = NULL;
#else
    worker_pool_shutdown(&worker_pool);
#endif
}

/* Shut down thread pool in main process (does not affect worker/child process pool(s). */
void am_worker_pool_shutdown_main() {
#ifndef _WIN32
    pthread_once_t once = PTHREAD_ONCE_INIT;
    worker_pool_shutdown(&worker_pool_main);
    /* reset main process pool init flag */
    memcpy(&worker_pool_main_initialized, &once, sizeof (worker_pool_main_initialized));
#endif
}

am_event_t *create_event() {
    am_event_t *e = malloc(sizeof (am_event_t));
    if (e != NULL) {
#ifdef _WIN32
        e->event = CreateEventA(NULL, TRUE, FALSE, NULL);
#else
#ifdef __APPLE__
        e->sem = malloc(sizeof (semaphore_t));
#else
        e->sem = malloc(sizeof (sem_t));
#endif   
        if (e->sem == NULL) {
            free(e);
            return NULL;
        }
#ifdef __APPLE__
        e->status = semaphore_create(mach_task_self(), e->sem, SYNC_POLICY_FIFO, 0);
        if (e->status != KERN_SUCCESS) {
#else
        e->status = sem_init(e->sem, 0, 0);
        if (e->status == -1) {
#endif   
            AM_FREE(e->sem, e);
            return NULL;
        }
        e->allocated = AM_TRUE;
#endif
    }
    return e;
}

am_event_t *create_named_event(const char *name, void *sem) {
    am_event_t *e = malloc(sizeof (am_event_t));
    if (e != NULL) {
#ifdef _WIN32
        SECURITY_DESCRIPTOR sec_descr;
        SECURITY_ATTRIBUTES sec_attr, *sec = NULL;
        if (InitializeSecurityDescriptor(&sec_descr, SECURITY_DESCRIPTOR_REVISION) &&
                SetSecurityDescriptorDacl(&sec_descr, TRUE, (PACL) NULL, FALSE)) {
            sec_attr.nLength = sizeof (SECURITY_ATTRIBUTES);
            sec_attr.lpSecurityDescriptor = &sec_descr;
            sec_attr.bInheritHandle = TRUE;
            sec = &sec_attr;
        }
        e->event = CreateEventA(sec, TRUE, FALSE, name);
        if (e->event == NULL && GetLastError() == ERROR_ACCESS_DENIED) {
            e->event = OpenEventA(SYNCHRONIZE, FALSE, name);
        }
        if (e->event == NULL) {
            free(e);
            e = NULL;
        }
#else
#ifdef __APPLE__
        e->sem = (semaphore_t *) sem;
#else
        e->sem = (sem_t *) sem;
#endif
        if (e->sem == NULL) {
            free(e);
            return NULL;
        }
#ifdef __APPLE__
        e->status = semaphore_create(mach_task_self(), e->sem, SYNC_POLICY_FIFO, 0);
        if (e->status != KERN_SUCCESS) {
#else
        e->status = sem_init(e->sem, 1, 0);
        if (e->status == -1) {
#endif
            free(e);
            return NULL;
        }
        e->allocated = AM_FALSE;
#endif
    }
    return e;
}

void set_event(am_event_t *e) {
    if (e != NULL) {
#ifdef _WIN32
        SetEvent(e->event);
#else
#ifdef __APPLE__
        e->status = semaphore_signal(*e->sem);
#else
        e->status = sem_post(e->sem);
#endif
#endif
    }
}

#if !defined(_WIN32) && !defined(__APPLE__)

static inline int sem_wait_nointr(sem_t *sem) {
    while (sem_wait(sem)) {
        if (errno == EINTR) errno = 0;
        else return -1;
    }
    return 0;
}

static inline int sem_timedwait_nointr(sem_t *sem, const struct timespec *abs_timeout) {
    while (sem_timedwait(sem, abs_timeout)) {
        if (errno == EINTR) errno = 0;
        else return -1;
    }
    return 0;
}
#endif

int wait_for_event(am_event_t *e, int timeout) {
    int r = 0;
    if (e != NULL) {
#ifdef _WIN32
        DWORD rv = WaitForSingleObject(e->event, timeout > 0 ? timeout : INFINITE);
        if (rv == WAIT_OBJECT_0) {
            ResetEvent(e->event);
            return r;
        }
        r = AM_ETIMEDOUT;
#else
        if (timeout <= 0) {
#ifdef __APPLE__
            e->status = semaphore_wait(*e->sem);
#else
            e->status = sem_wait_nointr(e->sem);
#endif  
        } else {

#define timespecadd(vvp, uvp) do { \
        (vvp)->tv_sec += (uvp)->tv_sec; \
        (vvp)->tv_nsec += (uvp)->tv_nsec; \
        if ((vvp)->tv_nsec >= 1000000000) { \
            (vvp)->tv_sec++; \
            (vvp)->tv_nsec -= 1000000000; \
        } \
    } while (0)

#ifdef __APPLE__
            const unsigned sec = timeout / 1000;
            const int nsec = ((int) timeout - (sec * 1000)) * 1000000;
            const mach_timespec_t t = {sec, nsec};
            e->status = semaphore_timedwait(*e->sem, t);
            if (e->status == KERN_OPERATION_TIMED_OUT) {
                r = AM_ETIMEDOUT;
            }
#else
            struct timespec start, end;
            am_clock_gettime(&start);
            end.tv_sec = timeout / 1000;
            end.tv_nsec = timeout % 1000 * 1000000;
            timespecadd(&end, &start);
            e->status = sem_timedwait_nointr(e->sem, &end);
            if (errno == ETIMEDOUT) {
                r = AM_ETIMEDOUT;
            }
#endif
        }
#endif
    }
    return r;
}

void close_event(am_event_t **e) {
    am_event_t *event = e != NULL ? *e : NULL;
    if (event != NULL) {
#ifdef _WIN32
        CloseHandle(event->event);
#else
#ifdef __APPLE__
        event->status = semaphore_destroy(mach_task_self(), *event->sem);
#else
        event->status = sem_destroy(event->sem);
#endif   
        if (event->allocated)
            free(event->sem);
#endif
        free(event);
        *e = NULL;
    }
}

#ifdef _WIN32

static void CALLBACK timer_callback(void *args, BOOLEAN tw_fired) {
    struct am_callback_args *cba = (struct am_callback_args *) args;
    if (cba != NULL && cba->callback != NULL) {
        cba->callback(cba->args);
    }
}

#elif defined (LINUX) || defined(AIX)

static void timer_callback(union sigval si) {
    struct am_callback_args *cba = (struct am_callback_args *) si.sival_ptr;
    if (cba != NULL && cba->callback != NULL) {
        cba->callback(cba->args);
    }
}

#endif

am_timer_event_t *am_create_timer_event(int type, unsigned int interval, void *args, void (*callback)(void *)) {
#if defined (__sun)
    port_notify_t pnotif;
    struct sigevent se;
#elif defined (LINUX) || defined(AIX)
    struct sigevent se;
#endif
    am_timer_event_t *e = calloc(1, sizeof (am_timer_event_t));
    if (e != NULL) {
        if (interval == 0) {
            e->error = AM_EINVAL;
            return e;
        }
        e->init_status = AM_ENOTSTARTED;
        e->type = type;
        e->interval = interval;
        e->args = malloc(sizeof (struct am_callback_args));
        if (e->args == NULL) {
            e->error = AM_ENOMEM;
            return e;
        }
        ((struct am_callback_args *) e->args)->args = args;
        ((struct am_callback_args *) e->args)->callback = callback;

        e->exit_ev = create_event();
        if (e->exit_ev == NULL) {
            e->error = AM_ENOMEM;
            return e;
        }
#if defined(__sun)
        e->port = port_create();
        if (e->port == -1) {
            e->error = errno;
            return e;
        }
        pnotif.portnfy_port = e->port;
        pnotif.portnfy_user = e->args;
        se.sigev_notify = SIGEV_PORT;
        se.sigev_value.sival_ptr = &pnotif;
        e->error = timer_create(CLOCK_REALTIME, &se, &e->tick);
        if (e->error == -1) {
            e->error = errno;
        }
#elif defined(__APPLE__)
        e->tick = kqueue();
        if (e->tick == -1) {
            e->error = errno;
            return e;
        }
#elif defined(_WIN32)
        e->tick_q = CreateTimerQueue();
        if (e->tick_q == NULL) {
            e->error = GetLastError();
            return e;
        }
        if (CreateTimerQueueTimer(&e->tick, e->tick_q,
                (WAITORTIMERCALLBACK) timer_callback, e->args, interval * 1000,
                type == AM_TIMER_EVENT_ONCE ? 0 : interval * 1000, WT_EXECUTELONGFUNCTION) == 0) {
            e->error = GetLastError();
            return e;
        }
#else
        se.sigev_notify = SIGEV_THREAD;
        se.sigev_value.sival_ptr = e->args;
        se.sigev_notify_function = timer_callback;
        se.sigev_notify_attributes = NULL;
        e->error = timer_create(CLOCK_REALTIME, &se, &e->tick);
        if (e->error == -1) {
            e->error = errno;
        }
#endif
    }
    return e;
}

static void *timer_event_loop(void *args) {
    am_timer_event_t *e = (am_timer_event_t *) args;

#if defined(__sun)

    port_event_t ev;
    struct am_callback_args *cba;
    struct itimerspec ts;
    if (e->error == 0 && e->tick > 0) {
        ts.it_value.tv_sec = e->interval;
        ts.it_value.tv_nsec = 0;
        ts.it_interval.tv_sec = e->type == AM_TIMER_EVENT_ONCE ? 0 : e->interval;
        ts.it_interval.tv_nsec = 0;
        e->error = timer_settime(e->tick, 0, &ts, 0);
    } else {
        if (e->error == 0) {
            e->error = AM_EINVAL;
        }
        return NULL;
    }

    while (1) {
        if (port_get(e->port, &ev, NULL) < 0) {
            break;
        }
        if (ev.portev_source != PORT_SOURCE_TIMER) {
            break;
        }
        cba = (struct am_callback_args *) ev.portev_user;
        if (cba == NULL || cba->callback == NULL) {
            break;
        }
        cba->callback(cba->args);
    }

#elif defined(__APPLE__)

    int n;
    u_short flags = EV_ADD | EV_ENABLE;
    struct kevent ch, ev;
    struct am_callback_args *cba = (struct am_callback_args *) e->args;
    if (cba == NULL || cba->callback == NULL) {
        return NULL;
    }
    if (e->type == AM_TIMER_EVENT_ONCE) {
        flags |= EV_ONESHOT;
    }

    /* set event */
    EV_SET(&ch, 1, EVFILT_TIMER, flags, NOTE_SECONDS, e->interval, NULL);
    kevent(e->tick, &ch, 1, NULL, 0, NULL);

    while (1) {
        n = kevent(e->tick, NULL, 0, &ev, 1, NULL); /* retrieve event */
        if (n <= 0 || (ev.flags & EV_ERROR)) {
            break;
        }
        cba->callback(cba->args);
    }

#else

#ifndef _WIN32

    struct itimerspec ts;
    if (e->error == 0 && e->tick > 0) {
        ts.it_value.tv_sec = e->interval;
        ts.it_value.tv_nsec = 0;
        ts.it_interval.tv_sec = e->type == AM_TIMER_EVENT_ONCE ? 0 : e->interval;
        ts.it_interval.tv_nsec = 0;
        e->error = timer_settime(e->tick, 0, &ts, 0);
    } else {
        if (e->error == 0) {
            e->error = AM_EINVAL;
        }
        return NULL;
    }

#endif

    while (1) {
        if (wait_for_event(e->exit_ev, 1000) == 0) {
            continue;
        }
        break;
    }
#endif
    return NULL;
}

void am_start_timer_event(am_timer_event_t *e) {
    if (e == NULL || e->error != 0) return;
#ifdef _WIN32
    if ((e->tick_thr = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) timer_event_loop, e, 0, NULL)) != NULL) {
        e->init_status = AM_SUCCESS;
    }
#else
    if (pthread_create(&e->tick_thr, NULL, timer_event_loop, e) == 0) {
        e->init_status = AM_SUCCESS;
    }
#endif
}

void am_close_timer_event(am_timer_event_t *e) {
    if (e == NULL) return;

    set_event(e->exit_ev);

#if defined(__sun)

    close(e->port);
    timer_delete(e->tick);

#elif defined(__APPLE__)

    close(e->tick);

#elif defined(_WIN32)

    if (e->init_status == AM_SUCCESS) {
        WaitForSingleObject(e->tick_thr, INFINITE);
    }
    if (e->tick_q != NULL) {
        if (e->tick != NULL) {
            DeleteTimerQueueTimer(e->tick_q, e->tick, NULL);
        }
        DeleteTimerQueue(e->tick_q);
    }
    if (e->init_status == AM_SUCCESS) {
        CloseHandle(e->tick_thr);
    }

#else

    timer_delete(e->tick);

#endif

#ifndef _WIN32
    if (e->init_status == AM_SUCCESS) {
        pthread_join(e->tick_thr, NULL);
    }
#endif

    close_event(&e->exit_ev);
    am_free(e->args);
    free(e);
}
