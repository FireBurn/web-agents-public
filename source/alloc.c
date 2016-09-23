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
 * a cluster largely in isolation from eachother to avoid contention. It uses course-grained atomic locking 
 * on each cluster. Each cluster has free lists embedded in the free memory blocks. 
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
 * Note: this uses (~ value) and ~ 0 to test and set -1.
 *
 */

#include "platform.h"
#include "am.h"
#include "utility.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <sched.h>

#include "alloc.h"
#include "share.h"

#ifndef offsetof
#define offsetof(type, field)               ( (char *)(&((type *)0)->field) - (char *)0 )
#endif

#define spinlock                            volatile int32_t
#define spinlock_init                       0

#define spinlock_unlock(l)                  __sync_lock_release(l)

#define incr(p, v)                          __sync_fetch_and_add((p), (v))
#define cas(p, old, new)                    __sync_bool_compare_and_swap(p, old, new)
#define casv(p, old, new)                   __sync_val_compare_and_swap(p, old, new)
#define yield()                             sched_yield()


#define CLUSTER_FREELISTS                   4
#define MIN_SPLIT_BLOCKSIZE                 24
#define VALIDATION_LOCK                     -1


#define HDR(ofs)                            ( (block_header_t *)( ((char *)_base) + (ofs) ) )
#define OFS(ptr)                            ( (offset) ( ( (char *)(ptr) ) - ( (char *)(_base) ) ) )
#define USR(ofs)                            ((char *)_base) + ((ofs) + block_data_offset)

#define UP64(i)                             ( ((i)+0x7u) & ~ 0x7u )                   /* 8 byte alignment */


typedef union
{
    volatile uint64_t                       value;

    unsigned char                           padding[32];

} padded_counter_t;


typedef struct
{
    padded_counter_t                        tx_start;

    volatile int32_t                        error;
    volatile pid_t                          checker;

} ctl_header_t;


typedef struct
{
    volatile uint32_t                       locks, size;
    
    union
    {
        uint8_t                             data[0];
        
        struct
        {
            volatile offset                 p, n;
            
        } free;
        
    } u;
    
} block_header_t;


typedef struct
{
    spinlock                                lock  __attribute__((aligned(256)));
    
    volatile offset                         free[CLUSTER_FREELISTS];
     
    // int64_t                                 padding[3];

} cluster_header_t;


static uint32_t                             _cluster_capacity;


static ctl_header_t                        *_ctlblock;

static cluster_header_t                    *_cluster_hdrs;

void                                       *_base;

static am_shm_t                            *_ctlblock_pool, *_cluster_hdrs_pool, *_base_pool;



#define cluster_lock(c)                     _cluster_hdrs[c].lock

#define cluster_free_lists(c)               _cluster_hdrs[c].free

static const size_t                         block_data_offset = offsetof(block_header_t, u.data);


extern int master_recovery_process(pid_t pid);


static int process_dead(pid_t pid)
{
    return kill(pid, 0) && errno == ESRCH;

}

void agent_memory_error()
{
    if (cas(&_ctlblock->error, 0, 1))
    {
printf("**** triggering memory cleardown\n");
    }
    else
    {
printf("**** memory cleardown alredy triggered\n");
    }

}

int try_validate(pid_t pid)
{
    if (_ctlblock->error)
    {
        return 1;
    }
    else
    {
printf("%d checking memory slowdown\n", pid);

        if (agent_memory_check(pid, 0, 0))
        {
            agent_memory_error();

            return 1;
        }
    }
    return 0;

}

void agent_memory_validate(pid_t pid)
{
    pid_t                                   checker;

    if (_ctlblock->error == 0)
    {
        return;
    }

    do
    {
        if (( checker = casv(&_ctlblock->checker, 0, pid) ))
        {
            if (process_dead(checker))
            {   
printf("**** cleardown process %d is dead, %d resetting checker\n", checker, pid);
                cas(&_ctlblock->checker, checker, 0);   
            }
            else
            {
                usleep(1000);
            }
        }
        else
        {
printf("**** starting recovery process in %d\n", pid);

            if (master_recovery_process(pid) == 0)
            {
                cas(&_ctlblock->error, 1, 0);

printf("**** ending recovery process in %d\n", pid);
            }
            else
            {
printf("**** abandoning recovery process in %d\n", pid);
            }
            cas(&_ctlblock->checker, pid, 0);

        }

    } while (_ctlblock->error);

}

/*
 * connect and get new seed for transactions, also checking for global locks
 *
 */
uint32_t agent_memory_seed()
{
     return (incr(&_ctlblock->tx_start.value, 1) & 0xffffffff) % CLUSTERS;

}

/*
 * free list choice: 4 lists, returns 3, 2, 1, 0 depending on whether size > 3072, > 2048, > 1024, or smaller (respectively)
 *
 */
inline static uint32_t free_list_offset_for_size(uint32_t size)
{
    uint32_t                                n = size >> 10;

    return (n & ~ 3) ? 3 : n;
    
}

/*
 * acquire a spinlock, but backout and check global errors after a while
 *
 */
static inline int spinlock_lock(spinlock *l, uint32_t pid)
{
    int                                     i = 0;

    do
    {
        if (cas(l, 0, pid))
        {
            return 0;
        }
        yield();

    } while (++i < 1000);

    i = 10;

    do
    {
        usleep(i);

        if (cas(l, 0, pid))
        {
            return 0;
        }

        if (i < 100000)
        {
            i *= 10;                                                                  /* exponential back off to some point when we start checking the memory */
        }
        else if (try_validate(pid))
        {
            return 1;
        }

    } while (1);

}

/*
 * add block to freelist with header
 *
 */
inline static void push_free_ptr(volatile offset *header, offset ofs)
{
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
inline static void unlink_free_ptr(volatile offset *header, block_header_t *h)
{
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
static void reset_ctlblock(void *cbdata, void *p)
{
    ctl_header_t                          *ctl = p;

    *ctl = (ctl_header_t) { .tx_start.value = 0, .checker = 0, .error = 0 };

}

/*
 * initialise block memory to a set of free blocks for each cluster
 *
 */
static void reset_blocks(void *cbdata, void *p)
{
    unsigned char                          *base = p;

    for (unsigned i = 0; i < CLUSTERS; i++)
    {
        offset                              ofs = i * _cluster_capacity;
        block_header_t                     *h = (block_header_t *)(base + ofs);

        *h = (block_header_t) { .locks = 0, .size = _cluster_capacity, .u.free = { ~ 0, ~ 0 } };
    }
}

/*
 * initialise cluster header memory to an array of headers, each one with a giant free block
 *
 */
static void reset_headers(void *cbdata, void *p)
{
    cluster_header_t                       *ch = p;

    for (unsigned i = 0; i < CLUSTERS; i++, ch++)
    {   
        offset                              ofs = i * _cluster_capacity;
 
        ch->lock = spinlock_init;

        for (int x = 0; x < CLUSTER_FREELISTS; x++) ch->free[x] = ~ 0;

        push_free_ptr(ch->free + free_list_offset_for_size(_cluster_capacity), ofs);
    }
}

/*
 * initialise memory for all clusters
 *
 */
void agent_memory_initialise(uint32_t sz, int id)
{
    _cluster_capacity = sz / CLUSTERS;
    
    get_memory_segment(&_ctlblock_pool, CTLFILE, sizeof(ctl_header_t), reset_ctlblock, 0, id);
    _ctlblock = _ctlblock_pool->base_ptr;

    get_memory_segment(&_base_pool, BLOCKFILE, sz, reset_blocks, 0, id);
    _base = _base_pool->base_ptr;

    get_memory_segment(&_cluster_hdrs_pool, HEADERFILE, sizeof(cluster_header_t) * CLUSTERS, reset_headers, 0, id);
    _cluster_hdrs = _cluster_hdrs_pool->base_ptr;

}

/*
 * unmap all clusters and optionally destroy shared resource
 *
 */
void agent_memory_destroy(int unlink)
{
    remove_memory_segment(&_ctlblock_pool, unlink);

    remove_memory_segment(&_base_pool, unlink);

    remove_memory_segment(&_cluster_hdrs_pool, unlink);
 
}


/*
 * coalesce small series of free blocks
 *
 */
static uint32_t coalesce(volatile offset *free, offset ofs, offset end)
{
    offset                                  start = ofs + HDR(ofs)->size, i = start;

    while (i < end)
    {
        block_header_t                     *h = HDR(i);

        if (h->locks)
            break;
        
        unlink_free_ptr(free + free_list_offset_for_size(h->size), h);
        i += h->size;
    }
    return i - start;
    
}

#define cmp(a, b)                           ( (a) < (b) ? -1 : (a) != (b) )

static int offset_comparator_reverse(const void *a, const void *b)
{
    return cmp(*(offset *)b, *(offset *)a);

}

/*
 * coalesce any contiguous blocks in an entire cluster
 *
 */
static int compact_cluster(volatile offset *freelists)
{
    offset                                 *buffer = malloc(sizeof(offset) * (_cluster_capacity / sizeof(block_header_t)));
    size_t                                  n = 0;
    
    for (int x = 0; x < CLUSTER_FREELISTS; x++)
        for (offset ofs = freelists[x]; ~ ofs; ofs = HDR(ofs)->u.free.n)
            buffer[n++] = ofs;
    
    if (n < 2)
    {
        free(buffer);

        return 0;
    }

    qsort(buffer, n, sizeof(offset), offset_comparator_reverse);
    
    for (int x = 0; x < CLUSTER_FREELISTS; x++)
        freelists[x] = ~ 0;
    
    register int                            c = 0;
    
    offset                                  base = buffer[0];
    for (unsigned i = 1; i < n; i++)
    {
        offset                              p = buffer[i];
        
        if (p + HDR(p)->size == base)
        {
            HDR(p)->size += HDR(base)->size;
            c++;
        }
        else
        {
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
static void *alloc(volatile offset *freelists, unsigned seq, int32_t type, const uint32_t required)
{
    while (seq < CLUSTER_FREELISTS)
    {
        offset                              ofs = freelists[seq];

        while (~ ofs)
        {
            block_header_t                 *h = HDR(ofs);
            
            if (h->size < required)
            {
                ofs = h->u.free.n;
            }
            else
            {
                uint32_t                    remainder = h->size - required;

                if (MIN_SPLIT_BLOCKSIZE <= remainder)
                {
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
static void *alloc_with_compact(volatile offset *freelists, unsigned seq, int32_t type, const uint32_t required)
{
    void                                   *p = 0;
    unsigned                                s = seq;
    
    while (freelists[s] == ~ 0)
    {
        s++;
        if (s == CLUSTER_FREELISTS)
        {
            return 0;
        }
    }
    
    if (( p = alloc(freelists, s, type, required) ) == 0)
    {
        if (compact_cluster(freelists))
        {
            p = alloc(freelists, seq, type, required);
        }
    }

    return p;
    
}

/*
 * allocate memory within a cluster
 *
 */
void *agent_memory_alloc(pid_t pid, uint32_t cluster, int32_t type, uint32_t size)
{
    uint32_t                                required = UP64(block_data_offset + size);

    unsigned                                seq = free_list_offset_for_size(required);
    
    void                                   *p;

    if (spinlock_lock(&cluster_lock(cluster), pid))
    {
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
int agent_memory_free(pid_t pid, void *p)
{
    offset                                  ofs = OFS(p) - block_data_offset;
    block_header_t                         *h = HDR(ofs);

    unsigned                                cluster = ofs / _cluster_capacity;
    
    if (spinlock_lock(&cluster_lock(cluster), pid))
        return 0;
    
    h->size += coalesce(cluster_free_lists(cluster), ofs, (cluster + 1) * _cluster_capacity);
    h->locks = 0;
    
    push_free_ptr(cluster_free_lists(cluster) + free_list_offset_for_size(h->size), ofs);
    
    spinlock_unlock(&cluster_lock(cluster));
    
    return 1;

}

int agent_memory_locks(pid_t pid, void *p)
{
    offset                                  ofs = OFS(p) - block_data_offset;
    block_header_t                         *h = HDR(ofs);

    unsigned                                cluster = ofs / _cluster_capacity;

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
static int validate_cluster_format(unsigned cluster)
{
    offset                                  base = cluster * _cluster_capacity, end = base + _cluster_capacity;

    uint32_t                                used = 0, released = 0;
    int                                     err = 0;

    offset                                 *buffer = malloc(sizeof(offset) * (_cluster_capacity / sizeof(block_header_t)));
    size_t                                  n = 0;

    offset                                  ofs;

    if (buffer == 0)
    {
        perror("allocating memory for validation");

        return 1;
    }

    for (ofs = base; ofs != end; ofs += HDR(ofs)->size)
    {
        if (ofs < base || end < ofs)
        {
            printf("------ cluster %d block range range error after %d: %d\n", cluster, base, ofs);
            err = 1;

            break;
        }

        if (HDR(ofs)->size < sizeof(block_header_t))
        {
            printf("------ cluster %d block range range error after %d: %d\n", cluster, base, ofs);
            err = 1;

            break;
        }

        if (HDR(ofs)->locks)
        {
            used += HDR(ofs)->size;
        }
        else
        {
            buffer[n++] = ofs;
        }
    }

    if (err == 0)
    {
        unsigned                            freelist_offset;

        uint8_t                            *visits = calloc(sizeof(uint8_t), n);      /* FIXME: this should be a bitset */
        offset                             *ptr;

        qsort(buffer, n, sizeof(offset), offset_comparator_reverse);

        for (freelist_offset = 0; freelist_offset < CLUSTER_FREELISTS; freelist_offset++)
        {
            offset                          prior = ~ 0;

            for (ofs = cluster_free_lists(cluster)[freelist_offset]; ~ ofs; ofs = HDR(ofs)->u.free.n)
            {
                if (( ptr = bsearch(&ofs, buffer, n, sizeof(offset), offset_comparator_reverse) ) == 0)
                {
                    printf("------ cluster %d free list %d: entry is not a block offset\n", cluster, freelist_offset);
                    err = 1;

                    break;
                }

                unsigned                    v = ptr - buffer;

                if (visits[v])
                {
                    printf("------ cluster %d, free list %d: cycle detected\n", cluster, freelist_offset);
                    err = 1;

                    break;
                }
                visits[v] = 1;

                released += HDR(ofs)->size;

                if (HDR(ofs)->u.free.p != prior)
                {
                    printf("------ cluster %d, unexepected value for 'prior': %u\n", cluster, HDR(ofs)->u.free.p);
                    err = 1;

                    break;
                }
                prior = ofs;
            }
        }

        if (used + released != _cluster_capacity)
        {
            printf("------ missing memory: cluster %d used %u, free %u, (%u out of %d)\n", cluster, used, released, used + released, _cluster_capacity);
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
int agent_memory_check(pid_t pid, int verbose, int clearup)
{
    int                                     err = 0;
    
    for (unsigned cluster = 0; cluster < CLUSTERS; cluster++)
    {
        pid_t                               locker;

        int                                 tries = 1000;

        do
        {
            if (( locker = casv(&cluster_lock(cluster), 0, pid) ))
            {
                yield();
            }
            else
            {
                break;
            }

        } while (--tries);

        if (locker == 0)
        {
            if (clearup)
            {
                offset                      base = cluster * _cluster_capacity;

                HDR(base)->size = coalesce(cluster_free_lists(cluster), base, base + _cluster_capacity);
            }
            spinlock_unlock(&cluster_lock(cluster));
        }
        else if (locker == VALIDATION_LOCK)
        {
            // printf("cluster %d: validating: validation lock was set\n", cluster);
        }
        else if (process_dead(locker))
        {
            if (cas(&cluster_lock(cluster), locker, VALIDATION_LOCK))
            {
                printf("cluster %d: validating: locking process %d is dead\n", cluster, locker);

                if (validate_cluster_format(cluster))
                {
                    err = 1;
                }
                else if (cas(&cluster_lock(cluster), VALIDATION_LOCK, 0))
                {
                    printf("cluster %d: unlocking cluster\n", cluster);
                }
                else
                {
                    printf("cluster %d: unlocking cluster failed\n", cluster);
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
void agent_memory_reset(pid_t pid)
{
    unsigned                                cluster;
    pid_t                                   locker;

    for (cluster = 0; cluster < CLUSTERS; cluster++)
    {
        while (( locker = casv(&cluster_lock(cluster), 0, pid) ))
        {
            if (locker == VALIDATION_LOCK)
            {
                if (cas(&cluster_lock(cluster), locker, pid))
                {
                    break;
                }
            }
            else if (process_dead(locker))
            {
printf("***** memory barrier: locking thread %d is dead\n", locker);
                if (cas(&cluster_lock(cluster), locker, pid))
                {
                    break;
                }
            }
            else
            {
printf("***** memory barrier: locking thread %d is active\n", locker);
                usleep(1000);
            }
        }

        int                                 i;

        offset                              ofs = cluster * _cluster_capacity;
        block_header_t                     *h = HDR(ofs);

        *h = (block_header_t) { .locks = 0, .size = _cluster_capacity, .u.free = { ~ 0, ~ 0 } };

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
void agent_memory_scan(pid_t pid, int (*checker)(void *cbdata, pid_t pid, int32_t type, void *p), void *cbdata)
{
    unsigned                                cluster;

    int                                     c = 0;

    uint32_t                                free = 0;

    for (cluster = 0; cluster < CLUSTERS; cluster++)
    {
        const offset                        base = cluster * _cluster_capacity, end = base + _cluster_capacity;
        offset                              ofs = base;

        if (spinlock_lock(&cluster_lock(cluster), pid))
        {
            printf("************ unable to scan cluster %d, getting out\n", cluster);

            return;
        }

#if 0
        compact_cluster(cluster_free_lists(cluster));
#endif
        while (ofs != end)
        {
            block_header_t             *h = HDR(ofs);

            if (h->locks)
            {
                if (checker(cbdata, pid, h->locks, USR(ofs)))
                {
                    h->size += coalesce(cluster_free_lists(cluster), ofs, end);
                    h->locks = 0;

                    push_free_ptr(cluster_free_lists(cluster) + free_list_offset_for_size(h->size), ofs);
                    c++;
                }
            }

            if (h->locks == 0)
            {
                free += h->size;
            }

            ofs += h->size;
        }
        spinlock_unlock(&cluster_lock(cluster));
    }

    printf("unlinked memory blocks -> %d \n", c);
    printf("free -> %f \n", (float)free / (float)(CLUSTERS * _cluster_capacity));

}

/*
 * print agent memory
 *
 */
static void analyse_cluster(int cluster, uint32_t *use_ptr, uint32_t *free_ptr, uint32_t *block_ptr, uint32_t *freelists)
{
    offset                                  base = cluster * _cluster_capacity, end = base + _cluster_capacity;

    uint32_t                                used = 0, free = 0, blocks = 0;

    uint32_t                                locks[4] = { 0, 0, 0, 0 }, overflows = 0;

    for (offset ofs = base; ofs != end; ofs += HDR(ofs)->size)
    {
        int                                 lock = HDR(ofs)->locks;
        uint32_t                            sz = HDR(ofs)->size;

        if (lock == 0)
        {
            free += sz;
            locks[lock]++;

            freelists[free_list_offset_for_size(sz)]++;
        }
        else if (lock < 4)
        {
            used += sz;
            locks[lock]++;
        }
        else
        {
            overflows++;
        }

        blocks++;
    }

    printf("cluster %5d: used %8u, free %8u, blocks %5u ", cluster, used, free, blocks);
    printf("locks:  [%5u, %5u, %5u, %5u] (other %u)\n", locks[0], locks[1], locks[2], locks[3], overflows);

    *use_ptr += used;
    *free_ptr += free;
    *block_ptr += blocks;

}

void agent_memory_print(pid_t pid)
{
    unsigned                                cluster;

    uint32_t                                used = 0, free = 0, blocks = 0;

    uint32_t                                freelists[CLUSTER_FREELISTS];

    for (int hdr = 0; hdr < CLUSTER_FREELISTS; hdr++)
    {
        freelists[hdr] = 0;
    }

    for (cluster = 0; cluster < CLUSTERS; cluster++)
    {
        if (spinlock_lock(&cluster_lock(cluster), pid))
        {
            printf("************ unable to scan cluster %d, getting out\n", cluster);

            break;
        }

        analyse_cluster(cluster, &used, &free, &blocks, freelists);

        spinlock_unlock(&cluster_lock(cluster));
    }

    printf("avg %f blocks per cluster, in use %u, free %u\n", (float)blocks / CLUSTERS, used, free);
    printf("free list sizes: [ "); for (int x = 0; x < CLUSTER_FREELISTS; x++) printf("%u ", freelists[x]); printf("]\n");

}

offset agent_memory_offset(void *ptr)
{
    return (offset)(((char *)ptr) - (char *)_base);

}

void *agent_memory_ptr(offset ofs)
{
    return ((char *)_base) + ofs;

}

