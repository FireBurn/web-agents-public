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
 * this version of a cache will lock at the hash level, which simplifies greatly with conflicting entries to the
 * same collision list
 *
 * because of the vaguaries of cache deletion with concurrent adds, it is possible that there is no point in time
 * at which entries are actually removed
 *
 * this is making atomic changes to the colision list, but because there can be concurrent operations on the same 
 * key there might be duplicate keys in any collision list. but only the first ones are reachable
 * 
 * this requires that the background gc thread needs to find out whether a block is (1) linked to the index, and
 * (2) linked to the index but is unreachable in this sense: an entry in the collision list overrides it.
 *
 */

#include "platform.h"
#include "am.h"
#include "utility.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>

#include "alloc.h"
#include "share.h"

#include "cache.h"
#include "rwlock.h"

#define STATFILE                            "stats"
#define LOCKFILE                            "lockfile"
#define HASHFILE                            "hashtable"

#define MAX_CACHE_MEMORY_SZ                 0x80000000

#define N_LOCKS                             4096

#define HASH_SZ                             6151

#define BUCKET_SZ                           256

#define GC_MARKER                           0xa4420810u

#define cas(p, old, new)                    __sync_bool_compare_and_swap((p), (old), (new))
#define casv(p, old, new)                   __sync_val_compare_and_swap((p), (old), (new))

#define incr(p, v)                          __sync_fetch_and_add((p), (v))
#define yield()                             sched_yield()

#ifdef GC_STATS
#define incr_gc_stat(p, v)                  incr(p, v)
#else
#define incr_gc_stat(p, v)
#endif

#ifndef offsetof
#define offsetof(type, field)               ( (char *)(&((type *)0)->field) - (char *)0 )
#endif

#define USER                                1
#define CACHE                               2

struct user_entry
{
    uint32_t                                hash, check, gcdata;

    uint32_t                                ln;
    uint8_t                                 data[0];                                  /* NOTE: this is 64 bit aligned */

};

struct cache_entry
{
    uint32_t                                hash, check, gcdata;

    volatile offset                         bucket[BUCKET_SZ];
    
    volatile uint32_t                       expires[BUCKET_SZ];

    volatile uint32_t                       cycles[BUCKET_SZ];

};

union cache_stat
{
    volatile uint64_t                       v;

    uint8_t                                 padding[16];

};

struct cache_gc_stat
{
    union cache_stat                        leaked, cleared, collected;

};

struct stats
{
    int64_t                                 basetime;

    union cache_stat                        reads, updates, writes, fails, deletes, expires, usage;

    struct cache_gc_stat                    cache, data;

};

static const size_t                         user_hdr_sz = offsetof(struct user_entry, data);

static struct stats                        *stats;

static struct readlock                     *locks;

static offset                              *hashtable;

static am_shm_t                            *stats_pool, *locks_pool, *hashtable_pool;


#define lock_for_hash(h)                    (locks + ((h) & (N_LOCKS - 1)))


static void reset_stats(void *cbdata, void *p)
{
    struct stats                           *stats = p;

    memset(stats, 0, sizeof(struct stats));

    stats->basetime = time(0);
    
    printf("cache stats reset\n");
}

static void reset_hashtable(void *cbdata, void *p)
{
    offset                                 *table = p;

    int                                     i;

    for (i = 0; i < HASH_SZ; i++)
    {
        table[i] = ~ 0;
    }

    printf("cache hashtable reset\n");
}

static void reset_locks(void *cbdata, void *p)
{
    struct readlock                        *locks = p;

    int                                     i;

    for (i = 0; i < N_LOCKS; i++)
    {
        locks[i] = readlock_init;
    }

    printf("cache locks reset\n");

}

/*
 * next power of 2 for a uint32
 *
 * (taken from https://graphics.stanford.edu/~seander/bithacks.html)
 *
 */
static uint32_t next_pow_2(uint32_t v)
{
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;

    return v;

}

/*
 * the agent cache memory size can be constrained by the AGENT_CACHE_SIZE environment variable
 *
 */
uint32_t cache_memory_size()
{
    char                                   *env = getenv("AM_MAX_SESSION_CACHE_SIZE");

    if (env)
    {
        char                               *endp = 0;
        uint32_t                            v = strtoul(env, &endp, 0);

        if (env < endp && *endp == '\0' && 0 < v && v < MAX_CACHE_MEMORY_SZ)
        {
            /* whole string is digits (dec, hex or octal) not 0 and less than our hard max */

            return next_pow_2(v);
        }
        printf("cache size spec %s not used\n", env);
    }

    return MAX_CACHE_MEMORY_SZ;

}

int cache_initialise(int id)
{
    uint32_t                                sz = cache_memory_size();

    agent_memory_initialise(sz, id);

    get_memory_segment(&stats_pool, STATFILE, sizeof(struct stats), reset_stats, 0, id);
    stats = stats_pool->base_ptr;

    get_memory_segment(&locks_pool, LOCKFILE, sizeof(struct readlock) * N_LOCKS, reset_locks, 0, id);
    locks = locks_pool->base_ptr;

    get_memory_segment(&hashtable_pool, HASHFILE, sizeof(offset) * HASH_SZ, reset_hashtable, 0, id);
    hashtable = hashtable_pool->base_ptr;

    return 0;

}

void cache_reinitialise()
{
    reset_hashtable(0, hashtable);

}

int cache_shutdown(int destroy)
{
    remove_memory_segment(&stats_pool, destroy);

    remove_memory_segment(&locks_pool, destroy);

    remove_memory_segment(&hashtable_pool, destroy);

    agent_memory_destroy(destroy);

    return 0;

}

int cache_readlock_p(uint32_t hash, pid_t pid)
{
    return read_lock(lock_for_hash(hash), pid);

}

int cache_readlock_try_p(uint32_t hash, pid_t pid, int tries)
{
    return read_lock_try(lock_for_hash(hash), pid, tries);

}

int cache_readlock_release_p(uint32_t hash, pid_t pid)
{
    return read_release(lock_for_hash(hash), pid);

}

int cache_readlock_try_unique(uint32_t hash)
{
    return read_try_unique(lock_for_hash(hash), 5);

}

int cache_readlock_release_unique(uint32_t hash)
{
    return read_release_unique(lock_for_hash(hash));

}

int cache_readlock_release_all_p(uint32_t hash, pid_t pid)
{
    return read_release_all(lock_for_hash(hash), pid);

}

void cache_readlock_total_barrier(pid_t pid)
{
    int                                     i;

    for (i = 0; i < N_LOCKS; i++)
    {
        wait_for_barrier(locks + i, pid);
    }

}

int cache_readlock_block_all(pid_t pid)
{
    int                                     i;

    for (i = 0; i < N_LOCKS; i++)
    {
        if (read_block(locks + i, pid) == 0)
        {
            break;
        }
    }

    if (i == N_LOCKS)
    {
        return 0;
    }

printf("unable to block cache lock %d\n", i);

    while (i--)
    {
        read_unblock(locks + i, pid);
    }

    return 1;

}

void cache_readlock_unblock_all(pid_t pid)
{
    int                                     i = N_LOCKS;

    while (i--)
    {
        read_unblock(locks + i, pid);
    }

}

/*
 * expiry time is represented as a 32 bit seconds value, relative to the cache shared start time
 *
 */
static uint32_t relative_time(int64_t t)
{
    return (t - stats->basetime) & 0xffffffff;

}

static void unlink_entry(pid_t pid, uint32_t hash, struct cache_entry *e, int i, offset ofs)
{
    if (cas(e->bucket + i, ofs, ~ 0))
    {
        if (cache_readlock_try_unique(hash))
        {
            agent_memory_free(pid, agent_memory_ptr(ofs));                            /* failures here can be gc'd later */

            cache_readlock_release_unique(hash);
incr_gc_stat(&stats->data.cleared.v, 1);
        }
        else
        {
incr_gc_stat(&stats->data.leaked.v, 1);
        }

        uint32_t                            ex = e->expires[i];                       /* expiry time high to avoid immediate expiry when created */

        while (cas(e->expires + i, ex, ~ 0) == 0)
        {
            ex = e->expires[i];
        }
    }

}

/*
 * remove cach entries that are the same as callers' data 
 *
 * this doesn't ensure that other entries are not added concurrently
 *
 */
static void purge_identical_entries(pid_t pid, uint32_t hash, struct cache_entry *e, int i, void *data, int (*identity)(void *, void *))
{
    while (i < BUCKET_SZ)
    {
        offset                              ofs = e->bucket[i];

        if (~ ofs)
        {
            struct user_entry              *p = agent_memory_ptr(ofs);

            if (identity(data, p->data))
            {
                unlink_entry(pid, hash, e, i, ofs);
            }
        }
        i++;
    }

}

/*
 * how many bits are set in a word?
 *
 * (taken from https://graphics.stanford.edu/~seander/bithacks.html)
 *
 */
static inline uint32_t bits(uint32_t v)
{
    v = v - ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    return ((v + (v >> 4) & 0xf0f0f0f) * 0x1010101) >> 24;

}

/*
 * low usage is determined by not used recently, and
 * not used within 32 cycles
 *
 */
static int low_usage(uint32_t cycles)
{
    if (cycles < 0x200000)                                                             /* not set in recent cycles */
    {
        uint32_t                            c = bits(cycles); 
        
        if (c < 6)
        {
            return 1;                                                                  /* less than 6 accesses in last 32 cycles */
        }
//printf("high usage: (%u: use cycles = %u) \n", cycles, c);
    }
    return 0;

}

/*
 * remove expired entries from a cache collision list
 *
 */
static int purge_expired_entries(pid_t pid, uint32_t hash, struct cache_entry *e, int64_t now)
{
    int                                     i, n = 0;

    uint32_t                                t = relative_time(now);

    for (i = 0; i < BUCKET_SZ; i++)
    {
        offset                              ofs = e->bucket[i];

        if (~ ofs)
        {
            if (e->expires[i] < t)
            {
                unlink_entry(pid, hash, e, i, ofs);
                n++;
incr(&stats->expires.v, 1);
            }
            else if (low_usage(e->cycles[i]))
            {
                unlink_entry(pid, hash, e, i, ofs);                                   /* low recent use */
                n++;
incr(&stats->usage.v, 1);
            }
            else                                                                      /* shift entry use counts */
            {
                uint32_t                     cycles;

                do
                {
                    cycles = e->cycles[i];

                } while (cas(e->cycles + i, cycles, cycles >> 1) == 0);
            }
        }
    }
    return n;

}

/*
 * remove expired cache entries, all in one go
 *
 * NOTE: this could be done in multiple threads, but the performance problem issue would only be the dispersed memory access
 *
 */
void cache_purge_expired_entries(pid_t pid)
{
    int                                     n = 0;

    offset                                  ofs;
    int                                     i;

    for (i = 0; i < HASH_SZ; i++)
    {
        if (cache_readlock_p(i, pid))
        {
            if (~ ( ofs = hashtable[i] ))
            {
                n += purge_expired_entries(pid, i, agent_memory_ptr(ofs), time(0));
            }
            cache_readlock_release_p(i, pid);
        }
    }

    if (n)
    {
        printf("******** unlinked expired entries: %d\n", n);
    }

}

/*
 * replace any existing entry, then purge subsequent entries; if existing entry was found, link newentry to the
 * head of the hash table collision list (so that it will override) and the purge subsequent entries (which might have
 * appeared recenty).
 *
 * NOTE: it might be better to just have a new entry with the data, then subsequent versions will be unreachable so that
 * they can be purged
 *
 */
int cache_add(uint32_t h, void *data, size_t ln, int64_t expires, int (*identity)(void *, void *))
{
    offset                                  ofs;
    struct cache_entry                     *e;

    offset                                  new;
    struct user_entry                      *u;

    int                                     i;

    pid_t                                   pid = getpid();

    uint32_t                                hash = h % HASH_SZ;
    uint32_t                                seed = agent_memory_seed();               /* use seed to direct user to new memory cluster */

    agent_memory_validate(pid);

    if (cache_readlock_p(hash, pid) == 0)
    {
        printf("readlock failure\n");

        return 1;
    }

    if (( u = agent_memory_alloc(pid, seed, USER, user_hdr_sz + ln) ))
    {
        u->hash = hash;
        u->check = ~ hash;                                                           /* this is to validate the hash */

        u->ln = ln;

        memcpy(u->data, data, ln);

        new = agent_memory_offset(u);
    }
    else
    {
        cache_readlock_release_p(hash, pid);                                          /* agent memory allocation failure */
incr(&stats->fails.v, 1);
        return 1;
    }

    ofs = hashtable[hash];

    if (~ ofs)
    {
        e = agent_memory_ptr(hashtable[hash]);
    }
    else if (( e = agent_memory_alloc(pid, seed, CACHE, sizeof(struct cache_entry)) ))
    {
        e->hash = hash;
        e->check = ~ hash;                                                            /* this is for validating the hash */

        for (i = 0; i < BUCKET_SZ; i++) e->bucket[i] = ~ 0;
        for (i = 0; i < BUCKET_SZ; i++) e->expires[i] = 0;
        for (i = 0; i < BUCKET_SZ; i++) e->cycles[i] = ~ 0;

        hashtable[hash] = agent_memory_offset(e);
    }
    else
    {
        cache_readlock_release_p(hash, pid);
incr(&stats->fails.v, 1);
        return 1;
    }

    for (i = 0; i < BUCKET_SZ; i++)
    {
        offset                              v = casv(e->bucket + i, ~ 0, new);

        if (v == ~ 0)
        {
incr(&stats->writes.v, 1);
            break;
        }
        else
        {
            struct user_entry              *p = agent_memory_ptr(v);

            if (identity(data, p->data))
            {
                while (cas(e->bucket + i, v, new) == 0)
                {
                    v = e->bucket[i];
                }

                if (~ v)
                {
                    if (cache_readlock_try_unique(hash))
                    {
                        agent_memory_free(pid, agent_memory_ptr(v));

                        cache_readlock_release_unique(hash);
incr_gc_stat(&stats->data.cleared.v, 1);
                    }
                    else
                    {
incr_gc_stat(&stats->data.leaked.v, 1);
                    }
incr(&stats->updates.v, 1);
                }
                break;
            }
        }
    }

    if (i < BUCKET_SZ)
    {
        uint32_t                            t = relative_time(expires);

        uint32_t                            ex = e->expires[i];

        while (cas(e->expires + i, ex, t) == 0)
        {
            ex = e->expires[i];
        }

        uint32_t                            cycles = e->cycles[i];
        
        while (cas(e->cycles + i, cycles, 0x80000000) == 0)
        {
            cycles = e->cycles[i];
        }

        purge_identical_entries(pid, hash, e, i + 1, data, identity);
    }
    else
    {
        // printf("out of bucket space\n");
    }

    cache_readlock_release_p(hash, pid);

    return i == BUCKET_SZ;

}

/*
 * remove anything that matches from the collsion list
 *
 */
void cache_delete(uint32_t h, void *data, int (*identity)(void *, void *))
{
    pid_t                                   pid = getpid();

    uint32_t                                hash = h % HASH_SZ;

    agent_memory_validate(pid);

    if (cache_readlock_p(hash, pid))
    {
        offset                              ofs = hashtable[hash];

        if (~ ofs)
        {
            purge_identical_entries(pid, hash, agent_memory_ptr(ofs), 0, data, identity);
        }
        cache_readlock_release_p(hash, pid);
incr(&stats->deletes.v, 1);
    }

}

/*
 * note: this might be silly because read locks should be very short-lived, but the caller should
 * release this read lock.
 *
 */
int cache_get_readlocked_ptr(uint32_t h, void **addr, uint32_t *ln, void *data, int64_t now, int (*identity)(void *, void *))
{
    pid_t                                   pid = getpid();

    uint32_t                                hash = h % HASH_SZ;

    uint32_t                                t = relative_time(now);

    offset                                  ofs;
   
    agent_memory_validate(pid);

    if (cache_readlock_p(hash, pid) == 0)
    {
        return 1;
    }

    ofs = hashtable[hash];

    if (~ ofs)
    {
        int                                 i;
        struct cache_entry                 *e = agent_memory_ptr(ofs);

        for (i = 0; i < BUCKET_SZ; i++)
        {
            offset                          u = e->bucket[i];

            if (~ u)
            {
                struct user_entry          *p = agent_memory_ptr(u);

                if (identity(data, p->data))
                {
                    if (e->expires[i] < t)
                        break;

                    uint32_t                cycles = e->cycles[i];

                    while ((cycles & 0x80000000) == 0)
                    {
                        if (cas(e->cycles + i, cycles, cycles | 0x80000000))
                            break;

                        cycles = e->cycles[i];
                    }

                    *addr = p->data;
                    *ln = p->ln;
incr(&stats->reads.v, 1);
                    return 0;
                }
            }
        }
    }

    cache_readlock_release_p(hash, pid);

    return 1;

}

void cache_release_readlocked_ptr(uint32_t h)
{
    pid_t                                   pid = getpid();

    uint32_t                                hash = h % HASH_SZ;

    cache_readlock_release_p(hash, pid);

}


static int cache_object_reachable(void *data, uint32_t hash)
{
    const offset                            target = agent_memory_offset(data);

    return target == hashtable[hash];

}

static int user_object_reachable(void *data, uint32_t hash)
{
    const offset                            target = agent_memory_offset(data);

    offset                                  ofs = hashtable[hash];

    if (~ ofs)
    {
        struct cache_entry                 *e = agent_memory_ptr(ofs);
        int                                 i;

        for (i = 0; i < BUCKET_SZ; i++)
        {
            if (target == e->bucket[i])
            {
                return 1;
            }
        }
    }
    return 0;

}

/*
 * NOTE: this is called when the memory cluster of p is locked, so we know that it is safe to get the hash code
 * of p, although it could be changing
 *
 * NOTE: if the hash code has not yet been set, we can't tell whether the block is in use or not - it can be
 * in-progress. So we will record in gcdata a marker to indicate that it has been observed, and if the hash is
 * still uninitialised in a subsequent gc sweep (when the marker has been set) then it can be released.
 *
 */
static int cache_garbage_checker(void *cbdata, pid_t pid, int32_t type, void *p)
{
    uint32_t                                hash;

    switch (type)
        {
        case USER:
            hash = ((struct user_entry *)p)->hash;                            /* this is called when the memory cluster is locked */
            if (hash != ~ ((struct user_entry *)p)->check)
            {
                if (((struct user_entry *)p)->gcdata == (hash ^ GC_MARKER))
                {
                    return 1;                                                 /* this has been seen in a prior gc sweep, let it go */
                }
                ((struct user_entry *)p)->gcdata = hash ^ GC_MARKER;
                return 0;                                                     /* this might still be in use, the hash not yet assigned */
            }

            if (cache_readlock_try_p(hash, pid, 10))
            {
                if (user_object_reachable(p, hash) == 0)
                {
                    if (cache_readlock_try_unique(hash))
                    {
                        cache_readlock_release_all_p(hash, pid);
incr_gc_stat(&stats->data.collected.v, 1);
                        
                        return 1;                                             /* no new threads can reach this block, and it isn't being read */
                    }
                }
                cache_readlock_release_p(hash, pid);
            }
            break;

        case CACHE:
            hash = ((struct cache_entry *)p)->hash;
            if (hash != ~ ((struct cache_entry *)p)->check)
            {
                if (((struct cache_entry *)p)->gcdata == (hash ^ GC_MARKER))  /* as above: wait until its been seen before in this state */
                {
                    return 1;
                }
                ((struct cache_entry *)p)->gcdata = hash ^ GC_MARKER;
                return 0;
            }

            if (cache_readlock_try_p(hash, pid, 10))
            {
                if (cache_object_reachable(p, hash) == 0)
                {
                    if (cache_readlock_try_unique(hash))
                    {
                        cache_readlock_release_all_p(hash, pid);
incr_gc_stat(&stats->cache.collected.v, 1);

                        return 1;                                             /* no new threads can reach this block, and it isn't being read */
                    }
                }
                cache_readlock_release_p(hash, pid);
            }
            break;
        }

    return 0;

}

void cache_garbage_collect()
{
    agent_memory_scan(getpid(), cache_garbage_checker, 0);

}

static unsigned long get_and_reset(volatile uint64_t *p)
{
    uint64_t                                old = *p;

    while (cas(p, old, 0ul) == 0)
    {
        usleep(1);
        old = *p;
    }
    return (unsigned long)old;

}

void cache_stats()
{
    printf("throughput:\n");
    printf("reads:   %lu\n", get_and_reset(&stats->reads.v));    
    printf("writes:  %lu\n", get_and_reset(&stats->writes.v));    
    printf("updates: %lu\n", get_and_reset(&stats->updates.v));    
    printf("deletes: %lu\n", get_and_reset(&stats->deletes.v));    
    printf("fails:   %lu\n", get_and_reset(&stats->fails.v));    
    printf("expires: %lu\n", get_and_reset(&stats->expires.v));    
    printf("usage:   %lu\n", get_and_reset(&stats->usage.v));    

#ifdef GC_STATS
    printf("cache objects:\n");
    printf("leaked: %lu\n", get_and_reset(&stats->cache.leaked.v));    
    printf("cleared: %lu\n", get_and_reset(&stats->cache.cleared.v));    
    printf("collected: %lu\n", get_and_reset(&stats->cache.collected.v));    

    printf("user objects:\n");
    printf("leaked: %lu\n", get_and_reset(&stats->data.leaked.v));    
    printf("cleared: %lu\n", get_and_reset(&stats->data.cleared.v));    
    printf("collected: %lu\n", get_and_reset(&stats->data.collected.v));    
#endif
}

int master_recovery_process(pid_t pid)
{
printf("**** blocking cache locks \n");
    if (cache_readlock_block_all(pid))
    {
        return 1;
    }

printf("**** reinitialising cache \n");
    cache_reinitialise();

printf("**** resetting memory clusters\n");
    agent_memory_reset(pid);

printf("**** unblocking cache locks\n");
    cache_readlock_unblock_all(pid);

    return 0;

}

