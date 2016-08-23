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
#include <unistd.h>
#include <errno.h>

#include <sys/sem.h>

#include "alloc.h"
#include "share.h"

#include "cache.h"
#include "rwlock.h"

#define STATFILE                            "/tmp/stats"
#define LOCKFILE                            "/tmp/lockfile"
#define HASHFILE                            "/tmp/hashtable"

#define N_LOCKS                             4096

#define HASH_SZ                             4657

#define GC_MARKER                           0xa4420810u

#define cas(p, old, new)                    __sync_bool_compare_and_swap(p, old, new)
#define incr(p, v)                          __sync_fetch_and_add((p), (v))
#define sync()                              __sync_synchronize()

#ifdef GS_STATS
#define incr_gc_stat(p, v)                  incr(p, v)
#else
#define incr_gc_stat(p, v)
#endif

#define offsetof(type, field)               ( (char *)(&((type *)0)->field) - (char *)0 )

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

    volatile int64_t                        expires;

    volatile offset                         user, next;
    
};

union stat
{
    volatile uint64_t                       v;

    uint8_t                                 padding[16];

};

struct garbage_stat
{
    union stat                              leaked, cleared, collected;

};

struct stats
{
    union stat                              reads, updates, writes, deletes, expires;

    struct garbage_stat                     cache, data;

};

static const size_t                         user_hdr_sz = offsetof(struct user_entry, data);

static struct stats                        *stats;

static struct readlock                     *locks;

static offset                              *hashtable;


static void reset_stats(void *cbdata, void *p)
{
    memset(p, 0, sizeof(struct stats));

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

int cache_initialise()
{
    void                                   *p;

    get_memory_segment(&p, STATFILE, sizeof(struct stats), reset_stats, 0);
    stats = p;

    get_memory_segment(&p, LOCKFILE, sizeof(struct readlock) * N_LOCKS, reset_locks, 0);
    locks = p;

    get_memory_segment(&p, HASHFILE, sizeof(offset) * HASH_SZ, reset_hashtable, 0);
    hashtable = p;

    return 0;

}

void cache_reinitialise()
{
    reset_hashtable(0, hashtable);

}

int cache_shutdown(int destroy)
{
    remove_memory_segment(stats, STATFILE, destroy, sizeof(struct stats));

    remove_memory_segment(locks, LOCKFILE, destroy, sizeof(struct readlock) * N_LOCKS);

    remove_memory_segment(hashtable, HASHFILE, destroy, sizeof(offset) * HASH_SZ);

    return 0;

}

#define lock_for_hash(h)                    (locks + ((h) % N_LOCKS))


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
    return read_try_unique(lock_for_hash(hash), 1);

}

int cache_readlock_release_unique(uint32_t hash)
{
    return read_release_unique(lock_for_hash(hash));

}

int cache_readlock_release_all_p(uint32_t hash, pid_t pid)
{
    return read_release_all(lock_for_hash(hash), pid);

}

void cache_readlock_release(uint32_t hash)
{
    cache_readlock_release_p(hash, getpid());

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
 * remove cach entries that are the same as callers' data 
 *
 * this doesn't ensure that other entries are not added concurrently
 *
 */
static void purge_identical_entries(pid_t pid, uint32_t hash, volatile offset *ptr, void *data, int (*identity)(void *, void *))
{
    offset                                  ofs;

    ofs = *ptr;
    while (~ ofs)
    {
        struct cache_entry                 *e = agent_memory_ptr(ofs);
        struct user_entry                  *p = agent_memory_ptr(e->user);

        if (identity(data, p->data))                                                  /* a version for checking the identity */
        {
            if (cas(ptr, ofs, e->next))
            {
                                                                                      /* e is now unreachable by new readers */
                if (cache_readlock_try_unique(hash))
                {
                    p = agent_memory_ptr(e->user);                                    /* no other extant readers, cannot now be changed */

                    agent_memory_free(pid, e);                                        /* failures here can be gc'd later */
                    agent_memory_free(pid, p);

                    cache_readlock_release_unique(hash);
incr_gc_stat(&stats->cache.cleared.v, 1);
incr_gc_stat(&stats->data.cleared.v, 1);
                }
                else
                {
incr_gc_stat(&stats->cache.leaked.v, 1);
incr_gc_stat(&stats->data.leaked.v, 1);
                }
            }
            else
            {
                                                                                      /* <- e was already unlinked */
            }
        }
        else
        {
            ptr = &e->next;
        }
        ofs = *ptr;
    }

}

/*
 * remove expired entries from a cache collision list
 *
 */
static int purge_expired_entries(pid_t pid, uint32_t hash, volatile offset *ptr, int64_t now)
{
    offset                                  ofs;

    int                                     n = 0;

    ofs = *ptr;
    while (~ ofs)
    {
        struct cache_entry                 *e = agent_memory_ptr(ofs);

        if (e->expires < now)                                                         /* a version for checking the expiry */
        {
            if (cas(ptr, ofs, e->next))
            {
                                                                                      /* e is now unreachable by new readers */
                if (cache_readlock_try_unique(hash))
                {
                    struct user_entry      *p = agent_memory_ptr(e->user);            /* no other extant readers, this cannot now be changed */

                    agent_memory_free(pid, e);                                        /* failures here can be gc'd later */
                    agent_memory_free(pid, p);

                    cache_readlock_release_unique(hash);
incr_gc_stat(&stats->cache.cleared.v, 1);
incr_gc_stat(&stats->data.cleared.v, 1);
                }
                else
                {
incr_gc_stat(&stats->cache.leaked.v, 1);
incr_gc_stat(&stats->data.leaked.v, 1);
                }

incr(&stats->expires.v, 1);
                n++;
            }
            else
            {
                                                                                      /* <- e was already unlinked */
            }
        }
        else
        {
            ptr = &e->next;
        }
        ofs = *ptr;
    }
    return n;

}

/*
 * remove expired cache entries, all in one go
 *
 * NOTE: this could be done in multiple threads, but the performance problem issue would only be the dispersed memory access
 *
 */
void cache_purge_expired_entries(pid_t pid, int64_t now)
{
    int                                     n = 0;

    int                                     i;

    for (i = 0; i < HASH_SZ; i++)
    {
        if (cache_readlock_p(i, pid))
        {
            n += purge_expired_entries(pid, i, hashtable + i, now);

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
int cache_add(uint32_t hash, void *data, size_t ln, int64_t expires, int (*identity)(void *, void *))
{
    offset                                  ofs;
    struct cache_entry                     *ne;

    offset                                  new;
    struct user_entry                      *np;

    pid_t                                   pid = getpid();

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

    ofs = hashtable[hash];

    while (~ ofs)
    {
        struct cache_entry                 *e = agent_memory_ptr(ofs);
        struct user_entry                  *p = agent_memory_ptr(e->user);            /* this is read locked, and identity will not change */

        if (identity(data, p->data))                                                  /* if we find an entry, we can replace it */
        {
            offset                          old;

            do
            {
                old = e->user;

            } while (cas(&e->user, old, new) == 0);

            cas(&e->user, e->expires, expires);                                       /* atomically change expiry time on cache entry */
                                                                                      /* the replaced user data is inaccessible to new readers */
            if (cache_readlock_try_unique(hash))
            {
                p = agent_memory_ptr(old);                                            /* no other readers - cannot change now */

                agent_memory_free(pid, p);                                            /* free the replaced version, which can have no readers */

                cache_readlock_release_unique(hash);

incr_gc_stat(&stats->data.cleared.v, 1);
            }
            else
            {
incr_gc_stat(&stats->data.leaked.v, 1);
            }

            purge_identical_entries(pid, hash, &e->next, data, identity);

            cache_readlock_release_p(hash, pid);

incr(&stats->updates.v, 1);
            return 0;
        }
        ofs = e->next;
    }

    if (( ne = agent_memory_alloc(pid, seed, CACHE, sizeof(struct cache_entry)) ))
    {
        offset                              eo = agent_memory_offset(ne);             /* new cache entry will be at head of list, to supersede any others */
        
        ne->hash = hash;
        ne->check = ~ hash;                                                           /* this is for validating the hash */
        ne->expires = expires;
        ne->user = new;

        do
        {
            ne->next = hashtable[hash];

        } while (cas(hashtable + hash, ne->next, eo) == 0);
                                                                                      /* e and the user data are now accessible */
        purge_identical_entries(pid, hash, &ne->next, data, identity);

        cache_readlock_release_p(hash, pid);

incr(&stats->writes.v, 1);
        return 0;
    }

    cache_readlock_release_p(hash, pid);                                              /* agent memory allocation failure */

    return 1;

}

/*
 * remove anything that matches from the collsion list
 *
 */
void cache_delete(uint32_t hash, void *data, int (*identity)(void *, void *))
{
    pid_t                                   pid = getpid();

    agent_memory_validate(pid);

    if (cache_readlock_p(hash, pid))
    {
        purge_identical_entries(pid, hash, hashtable + hash, data, identity);

        cache_readlock_release_p(hash, pid);

incr(&stats->deletes.v, 1);
    }

}

/*
 * note: this might be silly because read locks should be very short-lived, but the caller should
 * release this read lock.
 *
 */
int cache_get_readlocked_ptr(uint32_t hash, void **addr, void *data, int (*identity)(void *, void *))
{
    pid_t                                   pid = getpid();

    offset                                  ofs;
   
    agent_memory_validate(pid);

    if (cache_readlock_p(hash, pid) == 0)
    {
        return 1;
    }
    ofs = hashtable[hash];

    while (~ ofs)
    {
        struct cache_entry                 *e = agent_memory_ptr(ofs);
        struct user_entry                  *p = agent_memory_ptr(e->user);

        if (identity(data, p->data))
        {
            *addr = p->data;

incr(&stats->reads.v, 1);
            return 0;
        }

        ofs = e->next;
    }

    cache_readlock_release_p(hash, pid);

    return 1;

}

static int cache_object_reachable(void *data, uint32_t hash)
{
    const offset                            target = agent_memory_offset(data);

    offset                                  ofs = hashtable[hash];

    while (~ ofs)
    {   
        struct cache_entry                 *e = agent_memory_ptr(ofs);

        if (target == ofs)
        {
            return 1;
        }
        ofs = e->next;
    }
    return 0;

}

static int user_object_reachable(void *data, uint32_t hash)
{
    const offset                            target = agent_memory_offset(data);

    offset                                  ofs = hashtable[hash];

    while (~ ofs)
    {
        struct cache_entry                 *e = agent_memory_ptr(ofs);

        if (target == e->user)
        {
            return 1;
        }
        ofs = e->next;
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
printf("*******that was a corrupt hashcode\n");
                if (((struct user_entry *)p)->gcdata == (hash ^ GC_MARKER))
                {
                    return 1;                                                 /* this has been seen in a prior gc sweep, let it go */
                }
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
printf("*******that was a corrupt hashcode\n");
                if (((struct cache_entry *)p)->gcdata == (hash ^ GC_MARKER))  /* as above: wait until its been seen before in this state */
                {
                    return 1;
                }
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

static int64_t get_and_reset(volatile uint64_t *p)
{
    uint64_t                                old = *p;

    while (cas(p, old, 0ul) == 0)
    {
        usleep(1);
        old = *p;
    }
    return old;

}

void cache_stats()
{
    printf("throughput:\n");
    printf("reads: %llu\n", get_and_reset(&stats->reads.v));    
    printf("writes: %llu\n", get_and_reset(&stats->writes.v));    
    printf("updates: %llu\n", get_and_reset(&stats->updates.v));    
    printf("deletes: %llu\n", get_and_reset(&stats->deletes.v));    
    printf("expires: %llu\n", get_and_reset(&stats->expires.v));    

#ifdef GS_STATS
    printf("cache objects:\n");
    printf("leaked: %llu\n", get_and_reset(&stats->cache.leaked.v));    
    printf("cleared: %llu\n", get_and_reset(&stats->cache.cleared.v));    
    printf("collected: %llu\n", get_and_reset(&stats->cache.collected.v));    

    printf("user objects:\n");
    printf("leaked: %llu\n", get_and_reset(&stats->data.leaked.v));    
    printf("cleared: %llu\n", get_and_reset(&stats->data.cleared.v));    
    printf("collected: %llu\n", get_and_reset(&stats->data.collected.v));    
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

