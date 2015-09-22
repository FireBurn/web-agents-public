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
 * Copyright 2014 - 2015 ForgeRock AS.
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

#ifdef _WIN32
static INIT_ONCE worker_pool_initialized = INIT_ONCE_STATIC_INIT;
static TP_CALLBACK_ENVIRON worker_env;
static PTP_POOL worker_pool = NULL;
static PTP_CLEANUP_GROUP worker_pool_cleanup = NULL;
#else
static int worker_pool_atfork = 0;
static sigset_t fillset;

enum {
    AM_THREADPOOL_WAIT = 0x01,
    AM_THREADPOOL_DESTROY = 0x02
};

struct am_threadpool_work {
    void (*func) (void *, void *);
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

static void worker_pool_unlock_all() {
    pthread_mutex_unlock(&worker_pool->lock);
}

static void worker_pool_lock_all() {
    pthread_mutex_lock(&worker_pool->lock);
}

static void worker_pool_fork_handler() {
    struct am_threadpool_work *work;

    for (work = worker_pool->head; work != NULL; work = worker_pool->head) {
        worker_pool->head = work->next;
        free(work);
    }

    pthread_attr_destroy(&worker_pool->attr);
    pthread_cond_destroy(&worker_pool->busy);
    pthread_cond_destroy(&worker_pool->work);
    pthread_cond_destroy(&worker_pool->wait);
    pthread_mutex_init(&worker_pool->lock, NULL);
    free(worker_pool);
    worker_pool = NULL;
}

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

static void am_clock_gettime(struct timespec *ts) {
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
    void (*func) (void *arg_not_used, void *arg);
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
            func(NULL, func_arg);
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

    InitializeThreadpoolEnvironment(&worker_env);
    SetThreadpoolCallbackPool(&worker_env, worker_pool);
    worker_pool_cleanup = CreateThreadpoolCleanupGroup();
    if (worker_pool_cleanup == NULL) {
        DestroyThreadpoolEnvironment(&worker_env);
        CloseThreadpool(worker_pool);
        worker_pool = NULL;
        return FALSE;
    } else {
        SetThreadpoolCallbackCleanupGroup(&worker_env, worker_pool_cleanup, NULL);
    }
    return TRUE;

#else
    if (worker_pool != NULL) return;

    sigfillset(&fillset);

    if (!worker_pool_atfork && pthread_atfork(worker_pool_lock_all,
            worker_pool_unlock_all, worker_pool_fork_handler) != 0) {
        return; /* ENOMEM */
    }
    worker_pool_atfork = 1;

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

void am_worker_pool_init() {
#ifdef _WIN32
    InitOnceExecuteOnce(&worker_pool_initialized, create_threadpool, NULL, NULL);
#else
    create_threadpool();
#endif
}

/**
 * Reset worker pool initialize-once flag. Must not be used outside unit-test module.
 */
void am_worker_pool_init_reset() {
#ifdef _WIN32
    INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    memcpy(&worker_pool_initialized, &once, sizeof (worker_pool_initialized));
#endif
}

int am_worker_dispatch(void (*worker_f)(void *, void *), void *arg) {
#ifdef _WIN32
    BOOL status = TrySubmitThreadpoolCallback(worker_f, arg, &worker_env);
    return status == FALSE ? AM_ENOMEM : AM_SUCCESS;
#else
    struct am_threadpool_work *cur;

    if (worker_pool == NULL) return AM_EFAULT;

    cur = (struct am_threadpool_work *) malloc(sizeof (struct am_threadpool_work));
    if (cur == NULL) {
        return AM_ENOMEM;
    }

    cur->func = worker_f;
    cur->arg = arg;
    cur->next = NULL;

    pthread_mutex_lock(&worker_pool->lock);

    if (worker_pool->head == NULL) {
        worker_pool->head = cur;
    } else {
        worker_pool->tail->next = cur;
    }
    worker_pool->tail = cur;

    if (worker_pool->idle > 0) {
        /* if there is an idle worker in the pool - wake it up */
        pthread_cond_signal(&worker_pool->work);
    } else if (worker_pool->num_threads < worker_pool->max_threads &&
            create_worker(worker_pool) == 0) {
        /* new worker scheduled */
        worker_pool->num_threads++;
    }

    pthread_mutex_unlock(&worker_pool->lock);
    return AM_SUCCESS;
#endif
}

void am_worker_pool_shutdown() {
#ifdef _WIN32
    CloseThreadpoolCleanupGroupMembers(worker_pool_cleanup, TRUE, NULL);
    CloseThreadpoolCleanupGroup(worker_pool_cleanup);
    DestroyThreadpoolEnvironment(&worker_env);
    CloseThreadpool(worker_pool);
    worker_pool_cleanup = NULL;
#else
    struct am_threadpool_active *active;
    struct am_threadpool_work *work;

    if (worker_pool == NULL) return;

    pthread_mutex_lock(&worker_pool->lock);
    pthread_cleanup_push(cleanup_unlock_mutex, &worker_pool->lock);

    worker_pool->flag |= AM_THREADPOOL_DESTROY;
    pthread_cond_broadcast(&worker_pool->work);

    /* cancel all active workers */
    for (active = worker_pool->active; active != NULL; active = active->next) {
        pthread_cancel(active->thread);
    }

    /* wait for all active workers to finish */
    while (worker_pool->active != NULL) {
        worker_pool->flag |= AM_THREADPOOL_WAIT;
        pthread_cond_wait(&worker_pool->wait, &worker_pool->lock);
    }

    while (worker_pool->num_threads != 0) {
        pthread_cond_wait(&worker_pool->busy, &worker_pool->lock);
    }
    pthread_cleanup_pop(1);

    for (work = worker_pool->head; work != NULL; work = worker_pool->head) {
        worker_pool->head = work->next;
        free(work);
    }

    pthread_attr_destroy(&worker_pool->attr);
    pthread_mutex_destroy(&worker_pool->lock);
    pthread_cond_destroy(&worker_pool->busy);
    pthread_cond_destroy(&worker_pool->work);
    pthread_cond_destroy(&worker_pool->wait);
    free(worker_pool);
#endif
    worker_pool = NULL;
}

am_event_t *create_event() {
    am_event_t *e = malloc(sizeof (am_event_t));
    if (e != NULL) {
#ifdef _WIN32
        e->e = CreateEventA(NULL, FALSE, FALSE, NULL);
#else
        pthread_mutexattr_t a;
        pthread_mutexattr_init(&a);
        pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&e->m, &a);
        pthread_cond_init(&e->c, NULL);
        e->e = 0;
        pthread_mutexattr_destroy(&a);
#endif
    }
    return e;
}

void set_event(am_event_t *e) {
    if (e != NULL) {
#ifdef _WIN32
        SetEvent(e->e);
#else
        pthread_mutex_lock(&e->m);
        e->e = 1;
        pthread_cond_broadcast(&e->c);
        pthread_mutex_unlock(&e->m);
#endif
    }
}

void reset_event(am_event_t *e) {/*optional*/
    if (e != NULL) {
#ifdef _WIN32
        ResetEvent(e->e);
#else
        pthread_mutex_lock(&e->m);
        e->e = 0;
        pthread_cond_broadcast(&e->c);
        pthread_mutex_unlock(&e->m);
#endif
    }
}

int wait_for_event(am_event_t *e, int timeout) {
    int r = 0;
    if (e != NULL) {
#ifdef _WIN32
        DWORD rv = WaitForSingleObject(e->e, timeout > 0 ? timeout : INFINITE);
        if (rv != WAIT_OBJECT_0) {
            r = AM_ETIMEDOUT;
        }
#else
        pthread_mutex_lock(&e->m);
        while (!e->e) {
            if (timeout <= 0) {
                pthread_cond_wait(&e->c, &e->m);
            } else {
                struct timeval now = {0, 0};
                struct timespec ts = {0, 0};
                long tv_sec_from_nsec;
                gettimeofday(&now, NULL);
                ts.tv_sec = now.tv_sec;
                ts.tv_nsec = now.tv_usec * 1000;
                ts.tv_nsec += timeout * 1000000;
                tv_sec_from_nsec = ts.tv_nsec / 1000000000L;
                ts.tv_sec += tv_sec_from_nsec;
                ts.tv_nsec -= (tv_sec_from_nsec * 1000000000L);
                if (pthread_cond_timedwait(&e->c, &e->m, &ts) == ETIMEDOUT) {
                    r = AM_ETIMEDOUT;
                    break;
                }
            }
        }
        if (r == 0) {
            /* resets the event state to nonsignaled after a single waiting thread has been released */
            e->e = 0;
        }
        pthread_mutex_unlock(&e->m);
#endif
    }
    return r;
}

void close_event(am_event_t **e) {
    am_event_t *event = e != NULL ? *e : NULL;
    if (event != NULL) {
        set_event(event);
#ifdef _WIN32
        CloseHandle(event->e);
#else
        pthread_mutex_destroy(&event->m);
        pthread_cond_destroy(&event->c);
#endif
        free(event);
        *e = NULL;
    }
}

struct timer_callback_args {
    void *args;
    void (*callback)(void *);
};

#ifdef _WIN32

static void timer_callback(void *args, BOOLEAN tw_fired) {
    struct timer_callback_args *cba = (struct timer_callback_args *) args;
    if (cba != NULL && cba->callback != NULL) {
        cba->callback(cba->args);
    }
}

#elif defined (LINUX) || defined(AIX)

static void timer_callback(union sigval si) {
    struct timer_callback_args *cba = (struct timer_callback_args *) si.sival_ptr;
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
        e->args = malloc(sizeof (struct timer_callback_args));
        if (e->args == NULL) {
            e->error = AM_ENOMEM;
            return e;
        }
        ((struct timer_callback_args *) e->args)->args = args;
        ((struct timer_callback_args *) e->args)->callback = callback;

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
    struct timer_callback_args *cba;
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
        cba = (struct timer_callback_args *) ev.portev_user;
        if (cba == NULL || cba->callback == NULL) {
            break;
        }
        cba->callback(cba->args);
    }

#elif defined(__APPLE__)

    int n;
    u_short flags = EV_ADD | EV_ENABLE;
    struct kevent ch, ev;
    struct timer_callback_args *cba = (struct timer_callback_args *) e->args;
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
        if (wait_for_event(e->exit_ev, 1000) != AM_ETIMEDOUT) {
            break;
        }
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
