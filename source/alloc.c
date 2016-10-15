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
 * This is an allocator for shared memory that divides the memory into clusters and directs threads to use
 * clusters largely in isolation from eachother to avoid contention. It uses course-grained atomic locking 
 * on each cluster. Each cluster has variable sized memory blocks and multiple free lists embedded in the free
 * memory blocks. 
 *
 * The CAS lock operations are performed for each cluster, so since the locks and the free list are used
 * together, they are combined into a single structre (cluster_header_t) to take account of hardware cache lines.
 * The structure (cluster_header_t) is also padded to prevent false sharing.
 *
 * This version is not not limited to a small number of threads and seems to scale well - which here means
 * means that there isn't too much added contention.
 *
 * This is faster than the OS X allocator (magazine_malloc) for small allocations (< 4K). Problems with
 * larger allocations are addressed by separate free lists for different block sizes.
 *
 * Note: this uses the idiom ~value and ~0 to test and set 0xffffffffu.
 *
 */

#include "platform.h"
#include "am.h"
#include "utility.h"
#include "log.h"

#include "alloc.h"
#include "share.h"

#ifndef offsetof
#define offsetof(type, field)               ( (char *)(&((type *)0)->field) - (char *)0 )
#endif

#if defined _WIN32

#define incr(p)                             InterlockedIncrement(p)
#define casv(p, old, new)                   InterlockedCompareExchange(p, new, old)
#define cas(p, old, new)                    (casv(p, old, new) == (old))
#define yield()                             SwitchToThread()
#define pause(n)                            Sleep((n) / 1000)

#elif defined(__sun)

#include <sys/atomic.h>
#define incr(p)                             atomic_add_32_nv((volatile uint32_t *)(p), 1)
#define casv(p, old, new)                   atomic_cas_32((volatile uint32_t *)(p), (uint32_t)(old), (uint32_t)(new))
#define cas(p, old, new)                    (atomic_cas_32((volatile uint32_t *)(p), (uint32_t)(old), (uint32_t)(new)) == (old))
#define yield()                             sched_yield()
#define pause(n)                            usleep(n)

#else

#define incr(p)                             __sync_fetch_and_add(p, 1)
#define casv(p, old, new)                   __sync_val_compare_and_swap(p, old, new)
#define cas(p, old, new)                    __sync_bool_compare_and_swap(p, old, new)
#define yield()                             sched_yield()
#define pause(n)                            usleep(n)

#endif

#define CLUSTER_FREELISTS                   4
#define MIN_SPLIT_BLOCKSIZE                 24
#define VALIDATION_LOCK                     -1


#define HDR(ofs)                            ( (block_header_t *)( ((char *)cluster_base) + (ofs) ) )
#define OFS(ptr)                            ( (offset) ( ( (char *)(ptr) ) - ( (char *)(cluster_base) ) ) )
#define USR(ofs)                            ((char *)cluster_base) + ((ofs) + block_data_offset)

#define UP64(i)                             ( ((i)+0x7u) & ~ 0x7u )                   /* 8 byte alignment */


#define spinlock                            volatile int32_t
#define spinlock_init                       0

#if defined _WIN32
#define spinlock_unlock(l)                  InterlockedExchange(l, 0)
#elif defined(__sun)
#define spinlock_unlock(l)                  atomic_swap_32((volatile uint32_t *)(l), 0)
#else
#define spinlock_unlock(l)                  __sync_lock_release(l)
#endif

#if defined _WIN32
#define align_win(n)                        __declspec(align(n))
#define align_attr(n)                       
#else
#define align_win(n)                   
#define align_attr(n)                       __attribute__((aligned(n)))
#endif

typedef struct {
    align_win(64) volatile uint32_t cluster_capacity align_attr(64);
    align_win(64) volatile uint32_t number_of_clusters align_attr(64);
    align_win(64) volatile uint32_t seed align_attr(64);
    align_win(64) volatile int32_t error align_attr(64);
    align_win(64) volatile pid_t checker align_attr(64);
} ctl_header_t;


typedef struct {

    volatile uint32_t                       locks, size;
    
    union {

        uint8_t                             data[1];
        
        struct {

            volatile offset                 p, n;
            
        } free;
        
    } u;
    
} block_header_t;


typedef struct {

    align_win(256)  spinlock                lock align_attr(256);
    
    volatile offset                         free[CLUSTER_FREELISTS];
     
} cluster_header_t;

static ctl_header_t                        *ctlblock = 0;

static cluster_header_t                    *cluster_hdrs = 0;

static void                                *cluster_base = 0;

static am_shm_t                            *ctlblock_pool = 0, *cluster_hdrs_pool = 0, *cluster_base_pool = 0;

#define cluster_lock(c)                     cluster_hdrs[c].lock

#define cluster_free_lists(c)               cluster_hdrs[c].free

static const size_t                         block_data_offset = offsetof(block_header_t, u.data);


extern int master_recovery_process(pid_t pid);


/*
 * check whether a process is dead
 *
 */
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
 * trigger agent memory reset
 *
 */
void agent_memory_error() {
    static const char                      *thisfunc = "agent_memory_error():";

    if (cas(&ctlblock->error, 0, 1)) {
        AM_LOG_ERROR(0, "%s triggering memory cleardown", thisfunc);
    } else {
        AM_LOG_DEBUG(0, "%s memory cleardown already triggered", thisfunc);
    }

}

/*
 * test memory and trigger reset if it is unrecoverable
 *
 */
int try_validate(pid_t pid) {
    static const char                      *thisfunc = "try_validate():";

    if (ctlblock->error) {
        return 1;
    } else {
        AM_LOG_DEBUG(0, "%s process %"PR_L64" checking memory slowdown", thisfunc, (int64_t)pid);

        if (agent_memory_check(pid, 0, 0)) {
            agent_memory_error();

            return 1;
        }
    }
    return 0;

}

/*
 * respond to memory reset triggers
 *
 */
void agent_memory_validate(pid_t pid) {
    static const char                      *thisfunc = "agent_memory_validate():";

    pid_t                                   checker;

    if (ctlblock->error == 0) {
        return;
    }

    do {
        if (( checker = casv(&ctlblock->checker, 0, pid) )) {
            if (process_dead(checker)) {   
                AM_LOG_DEBUG(0, "%s recovery: recovery process %"PR_L64" is dead, trying process %"PR_L64"",
                                thisfunc, (int64_t)checker, (int64_t)pid);
                cas(&ctlblock->checker, checker, 0);   
            } else {
                yield();                                                              /* NOTE: this is quite a tight loop, monitoring recovery */
            }
        } else {
            AM_LOG_ERROR(0, "%s recovery: starting recovery process in %"PR_L64"", thisfunc, (int64_t)pid);

            if (master_recovery_process(pid) == 0) {
                cas(&ctlblock->error, 1, 0);

                AM_LOG_ERROR(0, "%s recovery: ending recovery in process %"PR_L64"", thisfunc, (int64_t)pid);
            } else {
                AM_LOG_ERROR(0, "%s recovery: abandoning recovery in process %"PR_L64"", thisfunc, (int64_t)pid);
            }
            cas(&ctlblock->checker, pid, 0);

        }

    } while (ctlblock->error);

}

/*
 * get new seed for memory operations, distributing operations to clusters on round-robin basis
 *
 */
uint32_t agent_memory_seed() {
     return incr(&ctlblock->seed) % ctlblock->number_of_clusters;
}

/*
 * free list choice: 4 lists, returns 3, 2, 1, 0 depending on whether size > 3072, > 2048, > 1024, or smaller (respectively)
 *
 */
static uint32_t free_list_offset_for_size(uint32_t size) {

    uint32_t                                n = size >> 10;

    return (n & ~ 3) ? 3 : n;
    
}

/*
 * acquire a spinlock, but backout and check global errors after a while
 *
 */
static int spinlock_lock(spinlock *l, uint32_t pid) {

    int                                     i = 0;

    do {
        if (cas(l, 0, pid)) {
            return 0;
        }
        yield();

    } while (++i < 1000);

    i = 10;

    do {
        pause(i);

        if (cas(l, 0, pid)) {
            return 0;
        }

        if (i < 100000) {
            i *= 10;                                                                  /* exponential back off to some point when we start checking the memory */
        } else if (try_validate(pid)) {
            return 1;
        }

        yield();

    } while (1);

}

/*
 * add block to freelist with header
 *
 */
static void push_free_ptr(volatile offset *header, offset ofs) {

    block_header_t                         *h = HDR(ofs);

    h->u.free.p = ~ 0;
    h->u.free.n = *header;
    
    if (~ h->u.free.n)
        HDR(h->u.free.n)->u.free.p = ofs;
    
    *header = ofs;
    
}

/*
 * remove block from freelist with header
 *
 */
static void unlink_free_ptr(volatile offset *header, block_header_t *h) {

    if (~ h->u.free.p)
        HDR(h->u.free.p)->u.free.n = h->u.free.n;
    else
        *header = h->u.free.n;
    
    if (~ h->u.free.n)
        HDR(h->u.free.n)->u.free.p = h->u.free.p;
    
}

/*
 * initialise control memory
 *
 */
static void reset_ctlblock(void *cbdata, void *p) {
    ctl_header_t *ctl = p;
    *ctl = (ctl_header_t){
        .seed = 0,
        .checker = 0,
        .error = 0,
        .cluster_capacity = 0,
        .number_of_clusters = 0
    };
}

/*
 * initialise block memory to a set of free blocks for each cluster
 *
 */
static void reset_blocks(void *cbdata, void *p) {
    static const char *thisfunc = "reset_blocks():";
    unsigned char *b = p;

    if (cbdata != NULL) {
        cluster_limit_t *limit = (cluster_limit_t *) cbdata;
        if (ctlblock != NULL) {
            if (limit->size_limit == 0 || limit->size_limit >= MAX_CACHE_MEMORY_SZ ||
                    (limit->size_limit / MAX_CLUSTER_SIZE) >= CLUSTERS) {
                /* when the size is not limited by the system/environment, 
                 * use default number of clusters and their capacity */
                ctlblock->number_of_clusters = CLUSTERS;
                ctlblock->cluster_capacity = limit->orig_size / ctlblock->number_of_clusters;
            } else {
                ctlblock->number_of_clusters = prev_pow_2((limit->size_limit * CLUSTERS) / MAX_CACHE_MEMORY_SZ);
                ctlblock->cluster_capacity = prev_pow_2((uint32_t) limit->size_limit) / ctlblock->number_of_clusters;
            }
            AM_LOG_DEBUG(0, "%s shared memory '%s' segment cluster_capacity: %lu bytes, number_of_clusters: %lu \n",
                    thisfunc, BLOCKFILE, ctlblock->cluster_capacity, ctlblock->number_of_clusters);
        } else {
            AM_LOG_WARNING(0, "%s ctlblock is not available", thisfunc);
        }
    }

    for (unsigned i = 0; i < ctlblock->number_of_clusters; i++) {
        offset ofs = i * ctlblock->cluster_capacity;
        block_header_t *h = (block_header_t *) (b + ofs);

        *h = (block_header_t){.locks = 0, .size = ctlblock->cluster_capacity, .u.free =
            { ~0u, ~0u}};
    }
}

/*
 * initialise cluster header memory to an array of headers, each one with a giant free block
 *
 */
static void reset_headers(void *cbdata, void *p) {

    cluster_header_t                       *ch = p;

    for (unsigned i = 0; i < ctlblock->number_of_clusters; i++, ch++) {   
        offset                              ofs = i * ctlblock->cluster_capacity;
 
        ch->lock = spinlock_init;

        for (int x = 0; x < CLUSTER_FREELISTS; x++) ch->free[x] = ~ 0;

        push_free_ptr(ch->free + free_list_offset_for_size(ctlblock->cluster_capacity), ofs);
    }
}

/*
 * initialise memory for all clusters
 *
 */
void agent_memory_initialise(uint32_t sz, int id) {

    cluster_limit_t limit = {.size_limit = 0u, .orig_size = sz};

    get_memory_segment(&ctlblock_pool, CTLFILE,
            sizeof (ctl_header_t), reset_ctlblock, NULL, id);
    ctlblock = ctlblock_pool->base_ptr;

    get_memory_segment(&cluster_base_pool, BLOCKFILE, sz, reset_blocks, &limit, id);
    cluster_base = cluster_base_pool->base_ptr;

    get_memory_segment(&cluster_hdrs_pool, HEADERFILE,
            sizeof (cluster_header_t) * CLUSTERS, reset_headers, NULL, id);
    cluster_hdrs = cluster_hdrs_pool->base_ptr;
}

/*
 * unmap all clusters and optionally destroy shared resource
 *
 */
void agent_memory_shutdown(int unlink) {

    remove_memory_segment(&ctlblock_pool, unlink);

    remove_memory_segment(&cluster_base_pool, unlink);

    remove_memory_segment(&cluster_hdrs_pool, unlink);
 
}

/*
 * try to remove all shared memory resources
 *
 */
int agent_memory_cleanup(int id) {

    int                                     errors = 0;

    if (delete_memory_segment(CTLFILE, id))
        errors++;

    if (delete_memory_segment(BLOCKFILE, id))
        errors++;

    if (delete_memory_segment(HEADERFILE, id))
        errors++;

    return errors;

}

/*
 * coalesce small series of free blocks
 *
 */
static uint32_t coalesce(volatile offset *free, offset ofs, offset end) {

    offset                                  start = ofs + HDR(ofs)->size, i = start;

    while (i < end) {
        block_header_t                     *h = HDR(i);

        if (h->locks)
            break;
        
        unlink_free_ptr(free + free_list_offset_for_size(h->size), h);
        i += h->size;
    }
    return i - start;
    
}

#define cmp(a, b)                           ( (a) < (b) ? -1 : (a) != (b) )

static int offset_comparator_reverse(const void *a, const void *b) {

    return cmp(*(offset *)b, *(offset *)a);

}

/*
 * coalesce any contiguous blocks in an entire cluster
 *
 */
static int compact_cluster(volatile offset *freelists) {

    offset                                 *buffer = malloc(sizeof(offset) * (ctlblock->cluster_capacity / sizeof(block_header_t)));
    size_t                                  n = 0;
    
    for (int x = 0; x < CLUSTER_FREELISTS; x++)
        for (offset ofs = freelists[x]; ~ ofs; ofs = HDR(ofs)->u.free.n)
            buffer[n++] = ofs;
    
    if (n < 2) {
        free(buffer);

        return 0;
    }

    qsort(buffer, n, sizeof(offset), offset_comparator_reverse);
    
    for (int x = 0; x < CLUSTER_FREELISTS; x++)
        freelists[x] = ~ 0;
    
    register int                            c = 0;
    
    offset                                  base = buffer[0];
    for (unsigned i = 1; i < n; i++) {
        offset                              p = buffer[i];
        
        if (p + HDR(p)->size == base) {
            HDR(p)->size += HDR(base)->size;
            c++;
        } else {
            push_free_ptr(freelists + free_list_offset_for_size(HDR(base)->size), base);
        }
        base = p;
    }
    push_free_ptr(freelists + free_list_offset_for_size(HDR(base)->size), base);

    free(buffer);
    
    return c;
    
}

/*
 * allocation, scan through a clusters' freelists
 *
 */
static void *alloc(volatile offset *freelists, unsigned seq, int32_t type, const uint32_t required) {

    while (seq < CLUSTER_FREELISTS) {
        offset                              ofs = freelists[seq];

        while (~ ofs) {
            block_header_t                 *h = HDR(ofs);
            
            if (h->size < required) {
                ofs = h->u.free.n;
            } else {
                uint32_t                    remainder = h->size - required;

                if (MIN_SPLIT_BLOCKSIZE <= remainder) {
                    HDR(ofs + required)->locks = 0;
                    HDR(ofs + required)->size = remainder;
                    push_free_ptr(freelists + free_list_offset_for_size(remainder), ofs + required);
                    
                    h->size = required;
                }
                h->locks = type;
                unlink_free_ptr(freelists + seq, h);
                
                return USR(ofs);
            }
        }
        seq++;
    }
    return 0;
    
}

/*
 * try allocate within a cluster but perform cluster-wide reorganisation of freelists if allocation fails, then try again
 *
 */
static void *alloc_with_compact(volatile offset *freelists, unsigned seq, int32_t type, const uint32_t required) {

    void                                   *p = 0;
    unsigned                                s = seq;
    
    while (freelists[s] == ~ 0) {
        s++;
        if (s == CLUSTER_FREELISTS)
            return 0;
    }
    
    if (( p = alloc(freelists, s, type, required) ) == 0) {
        if (compact_cluster(freelists)) {
            p = alloc(freelists, seq, type, required);
        }
    }

    return p;
    
}

/*
 * allocate memory within a cluster
 *
 */
void *agent_memory_alloc(pid_t pid, uint32_t cluster, int32_t type, uint32_t size) {

    uint32_t                                required = UP64(block_data_offset + size);

    unsigned                                seq = free_list_offset_for_size(required);
    
    void                                   *p;

    if (spinlock_lock(&cluster_lock(cluster), pid)) {
        return 0;
    }

    p = alloc_with_compact(cluster_free_lists(cluster), seq, type, required);
    spinlock_unlock(&cluster_lock(cluster));
    
    return p;

}

/*
 * free, always trying to coalesce with nearby blocks
 *
 */
int agent_memory_free(pid_t pid, void *p) {

    offset                                  ofs = OFS(p) - block_data_offset;
    block_header_t                         *h = HDR(ofs);

    unsigned                                cluster = ofs / ctlblock->cluster_capacity;
    
    if (spinlock_lock(&cluster_lock(cluster), pid))
        return 0;
    
    h->size += coalesce(cluster_free_lists(cluster), ofs, (cluster + 1) * ctlblock->cluster_capacity);
    h->locks = 0;
    
    push_free_ptr(cluster_free_lists(cluster) + free_list_offset_for_size(h->size), ofs);
    
    spinlock_unlock(&cluster_lock(cluster));
    
    return 1;

}

/*
 * debug utility to query the lock count
 *
 */
int agent_memory_locks(pid_t pid, void *p) {

    offset                                  ofs = OFS(p) - block_data_offset;
    block_header_t                         *h = HDR(ofs);

    unsigned                                cluster = ofs / ctlblock->cluster_capacity;

    if (spinlock_lock(&cluster_lock(cluster), pid))
        return 0;

    int32_t                                 locks = h->locks;

    spinlock_unlock(&cluster_lock(cluster));

    return locks;

}

 
/*
 * identify errors in block formatting within a cluster
 *
 */
static int validate_cluster_format(unsigned cluster) {
    static const char                      *thisfunc = "validate_cluster_format():";

    offset                                  base = cluster * ctlblock->cluster_capacity, end = base + ctlblock->cluster_capacity;

    uint32_t                                used = 0, released = 0;
    int                                     err = 0;

    offset                                 *buffer = malloc(sizeof(offset) * (ctlblock->cluster_capacity / sizeof(block_header_t)));
    size_t                                  n = 0;

    offset                                  ofs;

    if (buffer == 0) {
        AM_LOG_ERROR(0, "%s block validation: unable to allocate memory", thisfunc);

        return 1;
    }

    for (ofs = base; ofs != end; ofs += HDR(ofs)->size) {
        if (ofs < base || end < ofs) {
            AM_LOG_DEBUG(0, "%s block validation: cluster %u block range error after %d: %d", thisfunc, cluster, base, ofs);
            err = 1;

            break;
        }

        if (HDR(ofs)->size < sizeof(block_header_t)) {
            AM_LOG_DEBUG(0, "%s block validation: cluster %u block range error after %d: %d", thisfunc, cluster, base, ofs);
            err = 1;

            break;
        }

        if (HDR(ofs)->locks) {
            used += HDR(ofs)->size;
        } else {
            buffer[n++] = ofs;
        }
    }

    if (err == 0) {
        unsigned                            freelist_offset;

        uint8_t                            *visits = calloc(sizeof(uint8_t), n);      /* FIXME: this should be a bitset */
        offset                             *ptr;

        qsort(buffer, n, sizeof(offset), offset_comparator_reverse);

        for (freelist_offset = 0; freelist_offset < CLUSTER_FREELISTS; freelist_offset++) {
            offset                          prior = ~ 0u;

            for (ofs = cluster_free_lists(cluster)[freelist_offset]; ~ ofs; ofs = HDR(ofs)->u.free.n) {
                if (( ptr = bsearch(&ofs, buffer, n, sizeof(offset), offset_comparator_reverse) ) == 0) {
                    AM_LOG_DEBUG(0, "%s block validation: cluster %u free list %d: entry is not a block offset",
                                     thisfunc, cluster, freelist_offset);
                    err = 1;

                    break;
                }

                unsigned                    v = ptr - buffer;

                if (visits[v]) {
                    AM_LOG_DEBUG(0, "%s block validation: cluster %u, free list %u: cycle detected", thisfunc, cluster, freelist_offset);
                    err = 1;

                    break;
                }
                visits[v] = 1;

                released += HDR(ofs)->size;

                if (HDR(ofs)->u.free.p != prior) {
                    AM_LOG_DEBUG(0, "%s block validation: cluster %u, unexepected prior offset: %u", thisfunc, cluster, HDR(ofs)->u.free.p);
                    err = 1;

                    break;
                }
                prior = ofs;
            }
        }

        if (used + released != ctlblock->cluster_capacity) {
            AM_LOG_DEBUG(0, "%s block validation: missing memory: cluster %u used %u, free %u, (%u out of %d)",
                             thisfunc, cluster, used, released, used + released, ctlblock->cluster_capacity);
            err = 1;
        }

        free(visits);
    }

    free(buffer);

    return err;

}

/*
 * validation - scan all clusters, blocks and freelists, check consistency and some reporting
 *
 * this will unlock clusters after the locker has carashed, but only if the block format passes a validation test
 *
 */
int agent_memory_check(pid_t pid, int verbose, int clearup) {
    static const char                      *thisfunc = "agent_memory_check():";

    int                                     err = 0;
    
    for (unsigned cluster = 0; cluster < ctlblock->number_of_clusters; cluster++) {
        pid_t                               locker;

        int                                 tries = 1000;

        do {
            if (( locker = casv(&cluster_lock(cluster), 0, pid) )) {
                yield();
            } else {
                break;
            }

        } while (--tries);

        if (locker == 0) {
            if (clearup) {
                offset                      base = cluster * ctlblock->cluster_capacity;

                HDR(base)->size = coalesce(cluster_free_lists(cluster), base, base + ctlblock->cluster_capacity);
            }
            spinlock_unlock(&cluster_lock(cluster));
        } else if (locker == VALIDATION_LOCK) {
            AM_LOG_DEBUG(0, "%s cluster %u: validating: validation lock was set", thisfunc, cluster);
        } else if (process_dead(locker)) {
            if (cas(&cluster_lock(cluster), locker, VALIDATION_LOCK)) {
                AM_LOG_DEBUG(0, "%s cluster %u: validating: locking process %"PR_L64" is dead",
                                 thisfunc, cluster, (int64_t)locker);

                if (validate_cluster_format(cluster)) {
                    err = 1;
                } else if (cas(&cluster_lock(cluster), VALIDATION_LOCK, 0)) {
                    AM_LOG_DEBUG(0, "%s cluster %u: unlocking cluster", thisfunc, cluster);
                } else {
                    AM_LOG_ERROR(0, "%s cluster %u: unlocking cluster failed", thisfunc, cluster);
                }
            }
        }
    }

    return err;

}

/*
 * for all clusters, wait for any locker to complete and reset the block structure and free lists
 *
 */
void agent_memory_reset(pid_t pid) {
    static const char                      *thisfunc = "agent_memory_reset():";

    unsigned                                cluster;
    pid_t                                   locker;

    for (cluster = 0; cluster < ctlblock->number_of_clusters; cluster++) {
        while (( locker = casv(&cluster_lock(cluster), 0, pid) )) {
            if (locker == VALIDATION_LOCK) {
                if (cas(&cluster_lock(cluster), locker, pid)) {
                    break;
                }
            } else if (process_dead(locker)) {
                AM_LOG_DEBUG(0, "%s memory barrier: locking process %"PR_L64" is dead", thisfunc, (int64_t)locker);
                if (cas(&cluster_lock(cluster), locker, pid)) {
                    break;
                }
            } else {
                AM_LOG_DEBUG(0, "%s memory barrier: locking process %"PR_L64" is active", thisfunc, (int64_t)locker);
                yield();
            }
        }

        int                                 i;

        offset                              ofs = cluster * ctlblock->cluster_capacity;
        block_header_t                     *h = HDR(ofs);

        *h = (block_header_t) { .locks = 0, .size = ctlblock->cluster_capacity, .u.free = { ~ 0u, ~ 0u } };

        for (i = 0; i < CLUSTER_FREELISTS; i++)
            cluster_free_lists(cluster)[i] = ~ 0;

        push_free_ptr(cluster_free_lists(cluster) + free_list_offset_for_size(h->size), ofs);

        spinlock_unlock(&cluster_lock(cluster));
    }
}

/*
 * garbage collection, where the caller determines whether blocks can be straightforwardly freed
 *
 */
void agent_memory_scan(pid_t pid, int (*checker)(void *cbdata, pid_t pid, int32_t type, void *p), void *cbdata) {
    static const char *thisfunc = "agent_memory_scan():";
    unsigned cluster;
    int c = 0;
    uint32_t free = 0;

    if (ctlblock == NULL)
        return;

    for (cluster = 0; cluster < ctlblock->number_of_clusters; cluster++) {
        const offset base = cluster * ctlblock->cluster_capacity, end = base + ctlblock->cluster_capacity;
        offset ofs = base;

        if (spinlock_lock(&cluster_lock(cluster), pid)) {
            AM_LOG_ERROR(0, "%s unable to scan cluster %u, abandoning gc scan", thisfunc, cluster);

            return;
        }

        while (ofs != end) {
            block_header_t *h = HDR(ofs);

            if (h->locks) {
                if (checker(cbdata, pid, h->locks, USR(ofs))) {
                    h->size += coalesce(cluster_free_lists(cluster), ofs, end);
                    h->locks = 0;

                    push_free_ptr(cluster_free_lists(cluster) + free_list_offset_for_size(h->size), ofs);
                    c++;
                }
            }

            if (h->locks == 0) {
                free += h->size;
            }

            ofs += h->size;
        }
        spinlock_unlock(&cluster_lock(cluster));
    }

    AM_LOG_DEBUG(0, "%s blocks unlinked during scan: %d, current memory free: %f", thisfunc, c,
            (float) free / (float) (ctlblock->number_of_clusters * ctlblock->cluster_capacity));
}

/*
 * print agent memory
 *
 */
static void analyse_cluster(int cluster, uint32_t *use_ptr, uint32_t *free_ptr, uint32_t *block_ptr, uint32_t *freelists) {
    static const char                      *thisfunc = "analyse_cluster():";

    offset                                  base = cluster * ctlblock->cluster_capacity, end = base + ctlblock->cluster_capacity;

    uint32_t                                used = 0, free = 0, blocks = 0;

    uint32_t                                locks[4] = { 0, 0, 0, 0 }, overflows = 0;

    for (offset ofs = base; ofs != end; ofs += HDR(ofs)->size) {
        int                                 lock = HDR(ofs)->locks;
        uint32_t                            sz = HDR(ofs)->size;

        if (lock == 0) {
            free += sz;
            locks[lock]++;

            freelists[free_list_offset_for_size(sz)]++;
        } else if (lock < 4) {
            used += sz;
            locks[lock]++;
        } else {
            overflows++;
        }

        blocks++;
    }

    AM_LOG_DEBUG(0, "%s cluster %5u: used %8u, free %8u, blocks %5u locks types [%5u, %5u, %5u, %5u, (%u)]",
                      thisfunc, cluster, used, free, blocks, locks[0], locks[1], locks[2], locks[3], overflows);

    *use_ptr += used;
    *free_ptr += free;
    *block_ptr += blocks;

}

/*
 * debug utility to print stats for each cluster
 *
 */
void agent_memory_print(pid_t pid) {
    static const char                      *thisfunc = "agent_memory_print():";

    uint32_t                                used = 0, free = 0, blocks = 0;

    uint32_t                                freelists[CLUSTER_FREELISTS];

    for (int hdr = 0; hdr < CLUSTER_FREELISTS; hdr++) {
        freelists[hdr] = 0;
    }

    for (unsigned cluster = 0; cluster < ctlblock->number_of_clusters; cluster++) {
        if (spinlock_lock(&cluster_lock(cluster), pid)) {
            AM_LOG_ERROR(0, "%s abandoning scan of cluster %u", thisfunc, cluster);

            break;
        }

        analyse_cluster(cluster, &used, &free, &blocks, freelists);

        spinlock_unlock(&cluster_lock(cluster));
    }

    AM_LOG_DEBUG(0, "%s avg blocks per cluster %f, blocks in use %u, free %u", thisfunc, (float)blocks / ctlblock->number_of_clusters, used, free);
    for (int x = 0; x < CLUSTER_FREELISTS; x++) {
        AM_LOG_DEBUG(0, "%s blocks in freelists type %d: %u ", thisfunc, x, freelists[x]); 
    }

}

offset agent_memory_offset(void *ptr) {

    return (offset)(((char *)ptr) - (char *)cluster_base);

}

void *agent_memory_ptr(offset ofs) {

    return ((char *)cluster_base) + ofs;

}

