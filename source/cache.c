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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "platform.h"
#include "am.h"

#include "utility.h"
#include "alloc.h"
#include "share.h"

#include "cache.h"
#include "rwlock.h"

#define STATFILE                            "/stats"
#define LOCKFILE                            "/lockfile"
#define HASHFILE                            "/hashtable"

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

};

union _stat
{
    volatile uint64_t                       v;

    uint8_t                                 padding[16];

};

struct garbage_stat
{
    union _stat                              leaked, cleared, collected;

};

struct stats
{
    int64_t                                 basetime;

    union _stat                              reads, updates, writes, deletes, expires;

    struct garbage_stat                     cache, data;

};

static const size_t                         user_hdr_sz = offsetof(struct user_entry, data);

am_shm_t                                    *stats = NULL;

am_shm_t                                    *locks = NULL;

am_shm_t                                    *hashtable = NULL;


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

int cache_initialise(int id)
{
    am_shm_t                                   *p;

    agent_memory_initialise(4096*1024, id);

    get_memory_segment(&p, STATFILE, sizeof(struct stats), reset_stats, 0, id);
    stats = p;

    get_memory_segment(&p, LOCKFILE, sizeof(struct readlock) * N_LOCKS, reset_locks, 0, id);
    locks = p;

    get_memory_segment(&p, HASHFILE, sizeof(offset) * HASH_SZ, reset_hashtable, 0, id);
    hashtable = p;

    return 0;

}

void cache_reinitialise()
{
    reset_hashtable(0, ((offset*)(hashtable->base_ptr)));

}

int cache_shutdown()
{
    remove_memory_segment(&stats);

    remove_memory_segment(&locks);

    remove_memory_segment(&hashtable);

    agent_memory_destroy();

    return 0;

}

#define lock_for_hash(h)                    (((struct readlock*)(locks->base_ptr)) + ((h) & (N_LOCKS - 1)))


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
    return read_try_unique(lock_for_hash(hash), 30);

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
        wait_for_barrier(((struct readlock*)(locks->base_ptr)) + i, pid);
    }

}

int cache_readlock_block_all(pid_t pid)
{
    int                                     i;

    for (i = 0; i < N_LOCKS; i++)
    {
        if (read_block(((struct readlock*)(locks->base_ptr)) + i, pid) == 0)
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
        read_unblock(((struct readlock*)(locks->base_ptr)) + i, pid);
    }

    return 1;

}

void cache_readlock_unblock_all(pid_t pid)
{
    int                                     i = N_LOCKS;

    while (i--)
    {
        read_unblock(((struct readlock*)(locks->base_ptr)) + i, pid);
    }

}

/*
 * expiry time is represented as a 32 bit seconds value, relative to the cache shared start time
 *
 */
static uint32_t relative_time(int64_t t)
{
    return (t - ((struct stats*)(stats->base_ptr))->basetime) & 0xffffffff;

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
                if (cas(e->bucket + i, ofs, ~ 0))
                {
                    if (cache_readlock_try_unique(hash))
                    {
                        agent_memory_free(pid, p);                                    /* failures here can be gc'd later */

                        cache_readlock_release_unique(hash);
incr_gc_stat(&((struct stats*)(stats->base_ptr))->data.cleared.v, 1);
                    }
                    else
                    {
incr_gc_stat(&((struct stats*)(stats->base_ptr))->data.leaked.v, 1);
                    }
                }
            }
        }
        i++;
    }

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
            struct user_entry              *p = agent_memory_ptr(ofs);

            if (e->expires[i] < t)
            {
                if (cas(e->bucket + i, ofs, ~ 0))
                {
                    if (cache_readlock_try_unique(hash))
                    {
                        agent_memory_free(pid, p);                                    /* failures here can be gc'd later */

                        cache_readlock_release_unique(hash);
incr_gc_stat(&((struct stats*)(stats->base_ptr))->data.cleared.v, 1);
                        n++;
                    }
                    else
                    {
incr_gc_stat(&((struct stats*)(stats->base_ptr))->data.leaked.v, 1);
                    }
incr(&((struct stats*)(stats->base_ptr))->expires.v, 1);
                }
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
            if (~ ( ofs = ((offset*)(hashtable->base_ptr))[i] ))
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
    struct user_entry                      *np;

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

    if (( np = agent_memory_alloc(pid, seed, USER, user_hdr_sz + ln) ))
    {
        np->hash = hash;
        np->check = ~ hash;                                                           /* this is to validate the hash */

        np->ln = ln;

        memcpy(np->data, data, ln);

        new = agent_memory_offset(np);
    }
    else
    {
        cache_readlock_release_p(hash, pid);                                          /* agent memory allocation failure */
        return 1;
    }

    ofs = ((offset*)(hashtable->base_ptr))[hash];

    if (~ ofs)
    {
        e = agent_memory_ptr(((offset*)(hashtable->base_ptr))[hash]);
    }
    else if (( e = agent_memory_alloc(pid, seed, CACHE, sizeof(struct cache_entry)) ))
    {
        e->hash = hash;
        e->check = ~ hash;                                                            /* this is for validating the hash */

        for (i = 0; i < BUCKET_SZ; i++) e->bucket[i] = ~ 0;
        for (i = 0; i < BUCKET_SZ; i++) e->expires[i] = 0;

        ((offset*)(hashtable->base_ptr))[hash] = agent_memory_offset(e);
    }
    else
    {
        cache_readlock_release_p(hash, pid);
        return 1;
    }

    for (i = 0; i < BUCKET_SZ; i++)
    {
        offset                              v = casv(e->bucket + i, ~ 0, new);

        if (v == ~ 0)
        {
incr(&((struct stats*)(stats->base_ptr))->writes.v, 1);
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
incr_gc_stat(&((struct stats*)(stats->base_ptr))->data.cleared.v, 1);
                    }
                    else
                    {
incr_gc_stat(&((struct stats*)(stats->base_ptr))->data.leaked.v, 1);
                    }
incr(&((struct stats*)(stats->base_ptr))->updates.v, 1);
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
        offset                              ofs = ((offset*)(hashtable->base_ptr))[hash];

        if (~ ofs)
        {
            purge_identical_entries(pid, hash, agent_memory_ptr(ofs), 0, data, identity);
        }
        cache_readlock_release_p(hash, pid);
incr(&((struct stats*)(stats->base_ptr))->deletes.v, 1);
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

    ofs = ((offset*)(hashtable->base_ptr))[hash];

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

                    *addr = p->data;
                    *ln = p->ln;
incr(&((struct stats*)(stats->base_ptr))->reads.v, 1);
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

    return target == ((offset*)(hashtable->base_ptr))[hash];

}

static int user_object_reachable(void *data, uint32_t hash)
{
    const offset                            target = agent_memory_offset(data);

    offset                                  ofs = ((offset*)(hashtable->base_ptr))[hash];

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
printf("*******hashcode was corrupt\n");
                    return 1;                                                 /* this has been seen in a prior gc sweep, let it go */
                }
printf("*******that was a potentially corrupt user data hashcode\n");
                ((struct user_entry *)p)->gcdata = hash ^ GC_MARKER;
                return 0;                                                     /* this might still be in use, the hash not yet assigned */
            }

            if (cache_readlock_try_p(hash, pid, 100))
            {
                if (user_object_reachable(p, hash) == 0)
                {
                    if (cache_readlock_try_unique(hash))
                    {
                        cache_readlock_release_all_p(hash, pid);
incr_gc_stat(&((struct stats*)(stats->base_ptr))->data.collected.v, 1);
                        
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
printf("*******hashcode  was corrupt\n");
                    return 1;
                }
printf("*******that was a potentially corrupt internal object hashcode\n");
                ((struct cache_entry *)p)->gcdata = hash ^ GC_MARKER;
                return 0;
            }

            if (cache_readlock_try_p(hash, pid, 100))
            {
                if (cache_object_reachable(p, hash) == 0)
                {
                    if (cache_readlock_try_unique(hash))
                    {
                        cache_readlock_release_all_p(hash, pid);
incr_gc_stat(&((struct stats*)(stats->base_ptr))->cache.collected.v, 1);

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
    printf("reads: %lu\n", get_and_reset(&((struct stats*)(stats->base_ptr))->reads.v));    
    printf("writes: %lu\n", get_and_reset(&((struct stats*)(stats->base_ptr))->writes.v));    
    printf("updates: %lu\n", get_and_reset(&((struct stats*)(stats->base_ptr))->updates.v));    
    printf("deletes: %lu\n", get_and_reset(&((struct stats*)(stats->base_ptr))->deletes.v));    
    printf("expires: %lu\n", get_and_reset(&((struct stats*)(stats->base_ptr))->expires.v));    

#ifdef GC_STATS
    printf("cache objects:\n");
    printf("leaked: %lu\n", get_and_reset(&((struct stats*)(stats->base_ptr))->cache.leaked.v));    
    printf("cleared: %lu\n", get_and_reset(&((struct stats*)(stats->base_ptr))->cache.cleared.v));    
    printf("collected: %lu\n", get_and_reset(&((struct stats*)(stats->base_ptr))->cache.collected.v));    

    printf("user objects:\n");
    printf("leaked: %lu\n", get_and_reset(&((struct stats*)(stats->base_ptr))->data.leaked.v));    
    printf("cleared: %lu\n", get_and_reset(&((struct stats*)(stats->base_ptr))->data.cleared.v));    
    printf("collected: %lu\n", get_and_reset(&((struct stats*)(stats->base_ptr))->data.collected.v));    
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

