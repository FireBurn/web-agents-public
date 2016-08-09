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

#if NOLOCK
                                                                                      // the following spinlock definitions are only for testing
#define spinlock                            int32_t
#define spinlock_init                       0
#define spinlock_try(l)                     (true)
#define spinlock_lock(l)
#define spinlock_unlock(l)
#define incr(p, v)                          (*(p)) += (v)

#else
#if _DARWIN
#include <libkern/OSAtomic.h>
#define spinlock                            volatile OSSpinLock
#define spinlock_init                       OS_SPINLOCK_INIT
#define spinlock_try(l)                     OSSpinLockTry(l)
#define spinlock_lock(l)                    OSSpinLockLock(l)
#define spinlock_unlock(l)                  OSSpinLockUnlock(l)
#define incr(p, v)                          __sync_fetch_and_add((p), (v))
#define cas(p, old, new)                    __sync_bool_compare_and_swap(p, old, new)

#else
                                                                                      // linux and optionally OS-X
#define offsetof(type, field)               ( (char *)(&((type *)0)->field) - (char *)0 )
#define spinlock                            volatile int32_t
#define spinlock_init                       0

#if 1
                                                                                      // barriers: lock "acquire" (loads after), unlock "release" (stores before)
//#define spinlock_try(l)                     ( __sync_lock_test_and_set(l, 1) == 0 )
//#define spinlock_lock(l)                    while ( __sync_lock_test_and_set(l, 1) ) pthread_yield_np()
#define spinlock_unlock(l)                  __sync_lock_release(l)

#else
#define spinlock_try(l)                     __sync_bool_compare_and_swap(l, 0, 1)
#define spinlock_lock(l)                    while ( __sync_bool_compare_and_swap(l, 0, 1) == 0 ) yield()
#define spinlock_unlock(l)                  __sync_bool_compare_and_swap(l, 1, 0)
#endif

#define incr(p, v)                          __sync_fetch_and_add((p), (v))
#define cas(p, old, new)                    __sync_bool_compare_and_swap(p, old, new)
#define yield()                             sched_yield()
#endif

#endif

#define CLUSTERS                            32
#define CLUSTER_FREELISTS                   4
#define MIN_SPLIT_BLOCKSIZE                 24

#define LOCK                                0x80000000                                // arbitrary value for locking

#define HDR(ofs)                            ( (block_header_t *)( ((char *)_base) + (ofs) ) )
#define OFS(ptr)                            ( (offset) ( ( (char *)(ptr) ) - ( (char *)(_base) ) ) )
#define USR(ofs)                            ((char *)_base) + ((ofs) + block_data_offset)

#define UP64(i)                             ( ((i)+0x7u) & ~ 0x7u )                   // 8 byte alignment


typedef union
{
    volatile uint64_t                       value;

    unsigned char                           padding[32];

} padded_counter_t;


typedef struct
{
    padded_counter_t                        n_attach, tx_start;

    volatile uint64_t                       lock;

} ctl_header_t;


typedef struct
{
    volatile int32_t                        locks, size;
    
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
    spinlock                                lock;
    
    volatile offset                         free[CLUSTER_FREELISTS];
    
    int64_t                                 padding[3];
    
} cluster_header_t;


static ctl_header_t                        *_ctlblock;

static cluster_header_t                    *_cluster_hdrs;

static int32_t                              _cluster_capacity;

static void                                *_base;

#define cluster_lock(c)                     (_cluster_hdrs[c].lock)

#define cluster_free_lists(c)               (_cluster_hdrs[c].free)

static const size_t                         block_data_offset = offsetof(block_header_t, u.data);

/*
 * number of memory clusters
 *
 */
int agent_memory_clusters()
{
    return CLUSTERS;

}

offset agent_memory_offset(void *ptr)
{
    return ((char *)ptr) - ((char *)_base);

}

void *agent_memory_ptr(offset ofs)
{
    return ((char *)_base) + ofs;

}

/*
 * block/unblock connections
 *
 */
int agent_memory_block(int block)
{
    switch (block)
        {
        case 0:
            return cas(&_ctlblock->lock, 1, 0);                                       // unblock

        case 1:
            return cas(&_ctlblock->lock, 0, 1);                                       // block

        default:
            return cas(&_ctlblock->lock, 1, block);                                   // invalidate blocked memory
        }
}

int try_validate(pid_t pid)
{
    if (_ctlblock->lock == 2)
    {
        printf("memory state broken - get out of here\n");

        return 1;
    }

    if (agent_memory_block(1))
    {
        printf("%d checking memory slow\n", pid);

        if (agent_memory_check(pid, 0, 0))
        {
            printf("invalidating memory state\n");

            agent_memory_block(2);

            return 1;
        }

        agent_memory_block(0);
    }

    return 0;

}

/*
 * connect and get new seed for transactions, also checking for global locks
 *
 */
int32_t agent_memory_seed()
{
    uint64_t                                lock;

    while (( lock = _ctlblock->lock ))
    {
        if (lock == 1)
        {
            printf("waiting for agent memory\n");
            sleep(1);
        }
        else
        {
            printf("agent memory is not available (%lu)\n", (unsigned long)lock);
            return ~ 0;
        }
        sync();
    }
    return (incr(&_ctlblock->tx_start.value, 1) & 0xffffffff) % CLUSTERS;

}

/*
 * free list choice: 4 lists, returns 3, 2, 1, 0 depending on whether size > 3072, > 2048, > 1024, or smaller (respectively)
 *
 */
inline static int32_t free_list_offset_for_size(int32_t size)
{
    int32_t n = size >> 10;

    return (n & ~ 3) ? 3 : n;
    
}

static int inline spinlock_try(volatile int32_t *l, uint32_t pid)
{
    return cas(l, 0, pid);

}

/*
 * acquire a spinlock, but backout and check global errors after a while
 *
 */
static inline int spinlock_lock(volatile int32_t *l, uint32_t pid)
{
    int                                     i = 0;

    do
    {
        if (cas(l, 0, pid))
            return 0;

        yield();

    } while (++i < 1000);

    i = 10;

    do
    {
        usleep(i);

        if (cas(l, 0, pid))
            return 0;

        if (i < 1000000)
        {
            i *= 10;
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

    *ctl = (ctl_header_t) { .n_attach.value = 0, .tx_start.value = 0, .lock = 0 };

}

/*
 * initialise block memory to a set of free blocks for each cluster
 *
 */
static void reset_blocks(void *cbdata, void *p)
{
    unsigned char                          *base = p;

    for (int i = 0; i < CLUSTERS; i++)
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

    for (int i = 0; i < CLUSTERS; i++, ch++)
    {   
        offset                              ofs = i * _cluster_capacity;

        *ch = (cluster_header_t) { .lock = spinlock_init, .free = { ~ 0, ~ 0, ~ 0, ofs } };
    }
}

/*
 * initialise memory for all clusters
 *
 */
void agent_memory_initialise(int32_t sz)
{
    void                                   *p;

    _cluster_capacity = sz;
    
#if INHEAP
    posix_memalign(&p, 4096, sizeof(ctl_header_t));
    _ctlblock = p;

    posix_memalign(&p, 4096, sz * CLUSTERS);
    _base = p;

    posix_memalign(&p, 4096, sizeof(cluster_header_t) * CLUSTERS);
    _cluster_hdrs = p;

    reset_ctlblock(_ctlblock);
    reset_blocks(_base);
    reset_headers(_cluster_hdrs);
#else
    get_memory_segment(&p, CTLFILE, sizeof(ctl_header_t), reset_ctlblock, 0);
    _ctlblock = p;

    get_memory_segment(&p, BLOCKFILE, sz * CLUSTERS, reset_blocks, 0);
    _base = p;

    get_memory_segment(&p, HEADERFILE, sizeof(cluster_header_t) * CLUSTERS, reset_headers, 0);
    _cluster_hdrs = p;
#endif

    incr(&_ctlblock->n_attach.value, 1);

}

/*
 * unmap all clusters and optionally destroy shared resource
 *
 */
void agent_memory_destroy(int unlink)
{
    incr(&_ctlblock->n_attach.value, -1);

#if INHEAP
    free(_ctlblock);

    free(_base);

    free(_cluster_hdrs);
#else
    remove_memory_segment(_ctlblock, CTLFILE, unlink, sizeof(ctl_header_t));

    remove_memory_segment(_base, BLOCKFILE, unlink, _cluster_capacity * CLUSTERS);

    remove_memory_segment(_cluster_hdrs, HEADERFILE, unlink, sizeof(cluster_header_t) * CLUSTERS);
#endif
 
}


/*
 * coalesce small series of free blocks
 *
 */
static int32_t coalesce(volatile offset *free, offset ofs, int32_t end)
{
    int32_t                                 start = ofs + HDR(ofs)->size, i = start;

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
    int                                     n = 0;
    
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
    for (int i = 1; i < n; i++)
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
static void *alloc(volatile offset *freelists, int32_t seq, int32_t type, const int32_t required)
{
    while (seq < CLUSTER_FREELISTS)
    {
        offset                              ofs = freelists[seq];

        while (~ ofs)
        {
            block_header_t                 *h = HDR(ofs);
            int32_t                         remainder = h->size - required;
            
            if (0 <= remainder)
            {
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
            ofs = h->u.free.n;
        }
        seq++;
    }
    return 0;
    
}

/*
 * perform cluster-wide reorganisation of freelists if allocation fails, and try again
 *
 */
static void *alloc_with_compact(volatile int32_t *freelists, int32_t seq, int32_t type, const int32_t required)
{
    void                                   *p = 0;
    
    while (seq < CLUSTER_FREELISTS && freelists[seq] == ~ 0)
    {
        seq++;
    }
    
    if (seq < CLUSTER_FREELISTS)
    {
        if (( p = alloc(freelists, seq, type, required) ) == 0)
        {
            if (compact_cluster(freelists))
            {
                p = alloc(freelists, seq, type, required);
            }
        }
    }
    return p;
    
}

/*
 * allocate memory with a seed, but not restricted to a cluster
 *
 */
void *agent_memory_alloc_seed(pid_t pid, int32_t cluster, int32_t type, int32_t size)
{
    int32_t                                 required = UP64(block_data_offset + size);
    int32_t                                 seq = free_list_offset_for_size(required);
    
    void                                   *p;
    
    for (int i = 0; i < 1000; i++)
    //while (1)
    {
        if (cluster == CLUSTERS)
        {
            cluster = 0;
        }
        
        if (spinlock_try(&cluster_lock(cluster), pid))
        {
            p = alloc_with_compact(cluster_free_lists(cluster), seq, type, required);
            spinlock_unlock(&cluster_lock(cluster));
            
            if (p)
            {
                return p;
            }
        }
        cluster++;

        yield();
    }

printf("failed after 1000 tries\n");
    return 0;
    
}

/*
 * allocate memory within a cluster
 *
 */
void *agent_memory_alloc(pid_t pid, int32_t cluster, int32_t type, int32_t size)
{
    int32_t                                 required = UP64(block_data_offset + size);
    int32_t                                 seq = free_list_offset_for_size(required);
    
    void                                   *p;

    spinlock_lock(&cluster_lock(cluster), pid);
    
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

    int32_t                                 cluster = ofs / _cluster_capacity;
    
    spinlock_lock(&cluster_lock(cluster), pid);
    
if (h->locks == 0)
{
printf("***************** oh, a double free here\n");
return 0;
}
    h->size += coalesce(cluster_free_lists(cluster), ofs, (cluster + 1) * _cluster_capacity);
    h->locks = 0;
    
    push_free_ptr(cluster_free_lists(cluster) + free_list_offset_for_size(h->size), ofs);
    
    spinlock_unlock(&cluster_lock(cluster));
    
    return 1;

}

/*
 * identify errors in block formatting within a cluster
 *
 */
static int validate_cluster_format(int cluster, size_t *p_used, size_t *p_free, size_t *p_blocks, size_t *freelist_stats)
{
    offset                                  base = cluster * _cluster_capacity, end = base + _cluster_capacity;

    size_t                                  used = 0, released = 0, blocks = 0;
    int                                     err = 0;

    offset                                 *buffer = malloc(sizeof(offset) * (_cluster_capacity / sizeof(block_header_t)));
    int                                     n = 0;

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
            printf("cluster %d block range range error after %d: %d\n", cluster, base, ofs);
            err = 1;

            break;
        }

        if (HDR(ofs)->size < sizeof(block_header_t))
        {
            printf("cluster %d block range range error after %d: %d\n", cluster, base, ofs);
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

        blocks++;
    }

    if (err == 0)
    {
        int                                 freelist_offset;

        uint64_t                           *visits = calloc(sizeof(uint64_t), n);     // FIXME: this sbould be a bitset 
        offset                             *ptr;

        qsort(buffer, n, sizeof(offset), offset_comparator_reverse);

        for (freelist_offset = 0; freelist_offset < CLUSTER_FREELISTS; freelist_offset++)
        {
            for (ofs = cluster_free_lists(cluster)[freelist_offset]; ~ ofs; ofs = HDR(ofs)->u.free.n)
            {
                if (( ptr = bsearch(&ofs, buffer, n, sizeof(offset), offset_comparator_reverse) ) == 0)
                {
                    printf("cluster %d free list %d: entry is not a block offset\n", cluster, freelist_offset);
                    err = 1;

                    break;
                }

                int                         v = ptr - buffer;

                if (visits[v])
                {
                    printf("cluster %d, free list %d: cycle detected\n", cluster, freelist_offset);
                    err = 1;

                    break;
                }
                visits[v] = 1;

                released += HDR(ofs)->size;

                freelist_stats[freelist_offset]++;
            }
        }

        if (used + released != _cluster_capacity)
        {
            printf("missing memory: cluster %d used %lu, free %ld, (%lu out of %d)\n", cluster, used, released, used + released, _cluster_capacity);
            err = 1;
        }

        free(visits);
    }

    if (err == 0)
    {
        *p_used += used;
        *p_free += released;

        *p_blocks += blocks;
    }

    free(buffer);

    return err;

}

/*
 * validation - scan all clusters, blocks and freelists, check consistency and some reporting
 *
 * it might be possible to fix up, for example lock errors here, at some point
 *
 */
int agent_memory_check(pid_t pid, int verbose, int clearup)
{
    size_t                                  used = 0, free = 0, blocks = 0;
    int                                     err = 0;
    
    size_t                                  free_lists[CLUSTER_FREELISTS];
    
    for (int hdr = 0; hdr < CLUSTER_FREELISTS; hdr++)
    {
        free_lists[hdr] = 0;
    }
    
    for (int32_t cluster = 0; cluster < CLUSTERS; cluster++)
    {
        int                                 lock = 0;
        int                                 i = 0;

        do
        {
            if (( lock = spinlock_try(&cluster_lock(cluster), pid) ))
            {
                break;
            }
            yield();

        } while (i++ < 1000);

        if (lock)
        {
            if (clearup)
            {
                offset                      base = cluster * _cluster_capacity;

                HDR(base)->size = coalesce(cluster_free_lists(cluster), base, base + _cluster_capacity);
            }
        }
        else
        {
            printf("checking lock on cluster %d\n", cluster);

            if (kill(cluster_lock(cluster), 0) == 0)
            {
                printf("cluster %d locking process is active (skipping)\n", cluster);

                continue;
            }
            else if (errno == ESRCH)
            {
                printf("cluster %d locking process is dead\n", cluster);
            }
            else
            {
                perror("error identifying locking process");
            }
        }

        if (validate_cluster_format(cluster, &used, &free, &blocks, free_lists))
        {
            err = 1;
        }
        else
        {
            spinlock_unlock(&cluster_lock(cluster));
        }
    }

    printf("free list sizes: [ "); for (int x = 0; x < CLUSTER_FREELISTS; x++) printf("%lu ", (unsigned long)free_lists[x]); printf("]\n");
    
    printf("avg %f blocks per cluster, in use %lu, free %lu\n", (float)blocks / CLUSTERS, (unsigned long)used, (unsigned long)free);

    return err;

}

/*
 * garbage collection, where the caller determines whether blocks can be straightforwardly freed
 *
 */
void agent_memory_scan(pid_t pid, int (*checker)(void *cbdata, pid_t pid, int32_t type, void *p), void *cbdata)
{
    int                                     c = 0;

    for (int32_t cluster = 0; cluster < CLUSTERS; cluster++)
    {
        int                                 lock = 0;
        int                                 i = 0;

        do
        {
            if (( lock = spinlock_try(&cluster_lock(cluster), pid) ))
            {
                break;
            }
            yield();

        } while (i++ < 1000);

        if (lock)
        {
            const offset                    base = cluster * _cluster_capacity, end = base + _cluster_capacity;
            offset                          ofs = base;

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
#if 1
                        h->size += coalesce(cluster_free_lists(cluster), ofs, end);
                        h->locks = 0;

                        push_free_ptr(cluster_free_lists(cluster) + free_list_offset_for_size(h->size), ofs);
#endif
                        c++;
                    }
                }
                ofs += h->size;
            }
            spinlock_unlock(&cluster_lock(cluster));
        }
        else
        {
            printf("unable to visit cluster %d\n", cluster);
        }
    }
    printf("unlinked memory -> %d \n", c);

}

