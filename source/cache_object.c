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
#include "list.h"
#include "cache.h"

/*
 * Session and Policy response attribute cache
 * ===============================================================
 * key: 'token value'
 * 
 * Policy Change event cache
 * ===============================================================
 * key: AM_POLICY_CHANGE_KEY
 * 
 * PDP cache:
 * ===============================================================
 * key: 'uuid value'
 * 
 */

#define key_ln(blob)                    *(uint32_t *)(((char *)(blob)) + 1)
#define key_addr(blob)                   (((char *)(blob)) + 1 + sizeof(uint32_t))

/*
 * boolean test of equality between two msgpac blobs, a and b, which have been serialised such that the
 * key (ln, data) appears immediately after a header as layed out above
 *
 */
static int key_equality(void *a, void *b)
{
    uint32_t                             len = key_ln(a);

    return len == key_ln(b) && memcmp(key_addr(a), key_addr(b), ntohl(len)) == 0;

}

/*
 * delete cache entry. 
 *
 */
int am_remove_cache_entry(unsigned long instance, const char *key)
{
    struct cache_object_ctx              ctx;

    int                                  status = AM_SUCCESS;

    uint32_t                             hash = am_hash(key);

    cache_object_ctx_init(&ctx);
    cache_object_write_key(&ctx, (char *)key);

    if (ctx.error)
    {
        status = ctx.error;
    }
    else
    {
        cache_delete(hash, ctx.data, key_equality);
    }

    cache_object_ctx_destroy(&ctx);
    return status;

}

/*
 * get (readlocked) memory in shared cache
 *
 */
static int cache_fetch_readable(uint32_t hash, char *key, void **data_addr, uint32_t *sz_addr)
{
    struct cache_object_ctx              ctx;

    int                                  status = 0;

    cache_object_ctx_init(&ctx);
    cache_object_write_key(&ctx, key);

    if (ctx.error)
    {
        status = ctx.error;
    }
    else if (cache_get_readlocked_ptr(hash, data_addr, sz_addr, ctx.data, time(0), key_equality))
    {
        status = AM_NOT_FOUND;
    }

    cache_object_ctx_destroy(&ctx);
    return status;

}

/*
 * get validation time in for all policies
 *
 */
int am_check_policy_cache_epoch(uint64_t policy_created)
{
    struct cache_object_ctx              ctx;
    int                                  status;

    uint32_t                             hash = am_hash(AM_POLICY_CHANGE_KEY);

    void                                *shm_data;                                    /* pointer into hash table */
    uint32_t                             shm_data_sz;

    uint64_t                             epoch_start;

    if (( status = cache_fetch_readable(hash, (char *)AM_POLICY_CHANGE_KEY, &shm_data, &shm_data_sz) ))
    {
        if (status == AM_NOT_FOUND)
        {
            return AM_SUCCESS;                                                        /* no epoch set */
        }
        return status;
    }

    cache_object_ctx_init_data(&ctx, shm_data, (size_t)shm_data_sz);
    cache_object_skip_key(&ctx);
    am_policy_epoch_deserialise(&ctx, &epoch_start);

    cache_release_readlocked_ptr(hash);

    status = ctx.error;
    cache_object_ctx_destroy(&ctx);

    if (status)
    {
        return status;
    }

    if (policy_created < epoch_start)
    {
        return AM_ETIMEDOUT;                                                          /* policy crated before the epoch */
    }

    return status;

}

/*
 * set validation time for all policies
 *
 */
int am_set_policy_cache_epoch(uint64_t epoch_start)
{
    struct cache_object_ctx              ctx;
    int                                  status;

    uint32_t                             hash = am_hash(AM_POLICY_CHANGE_KEY);

    cache_object_ctx_init(&ctx);
    cache_object_write_key(&ctx, (char *)AM_POLICY_CHANGE_KEY);
    am_policy_epoch_serialise(&ctx, epoch_start);

    if (ctx.error)
    {
        status = ctx.error;
    }
    else if (cache_add(hash, ctx.data, ctx.data_size, ~0, key_equality))
    {
        status = AM_ERROR;                                                            /* failure here is significant */
    }
    else
    {
        status = AM_SUCCESS;
    }

    cache_object_ctx_destroy(&ctx);
    return status;

}

/*
 * deserialise cached pdp data entry
 *
 */
int am_get_pdp_cache_entry(am_request_t *request, const char *key, char **url, char **file, char **content_type, int *method)
{
    struct cache_object_ctx              ctx;
    int                                  status;

    uint32_t                             hash = am_hash(key);

    void                                *shm_data;                                    /* pointer into hash table */
    uint32_t                             shm_data_sz;

    if (cache_fetch_readable(hash, (char *)key, &shm_data, &shm_data_sz))
    {
        return AM_NOT_FOUND;
    }

    cache_object_ctx_init_data(&ctx, shm_data, (size_t)shm_data_sz);
    cache_object_skip_key(&ctx);
    am_pdp_entry_deserialise(&ctx, url, file, content_type, method);

    cache_release_readlocked_ptr(hash);

    status = ctx.error;
    cache_object_ctx_destroy(&ctx);

    return status;

}

/*
 * cache serialised pdp data
 *
 */
int am_add_pdp_cache_entry(am_request_t *request, const char *key, const char *url, const char *file, const char *content_type, int method)
{
    struct cache_object_ctx              ctx;
    int                                  status;

    uint32_t                             hash = am_hash(key);

    int64_t                              expires = time(0) + request->conf->pdp_cache_valid;

    cache_object_ctx_init(&ctx);
    cache_object_write_key(&ctx, (char *)key);
    am_pdp_entry_serialise(&ctx, url, file, content_type, method);

    if (ctx.error)
    {
        status = ctx.error;
    }
    else if (cache_add(hash, ctx.data, ctx.data_size, expires, key_equality))
    {
        status = AM_ERROR;                                                            /* failure here is significant */
    }
    else
    {
        status = AM_SUCCESS;
    }

    cache_object_ctx_destroy(&ctx);
    return status;

}

/*
 * get ttl for session
 *
 */
static int get_session_ttl(am_request_t *request, struct am_namevalue *session)
{
    int                                  ttl = request->conf->token_cache_valid;
    int                                  max_caching = get_ttl_value(session, "maxcaching", ttl, AM_TRUE);
    int                                  timeleft = get_ttl_value(session, "timeleft", ttl, AM_FALSE);

    if (max_caching < ttl)
    {
        ttl = max_caching;
    }

    if (timeleft < ttl)
    {
        ttl = timeleft;
    }

    return ttl;

}

/*
 * deserialise cached policy and session data
 *
 */
int am_get_session_policy_cache_entry(am_request_t *request, const char *key, struct am_policy_result **policy, struct am_namevalue **session, uint64_t *ts)
{
    uint32_t                             hash = am_hash(key);

    struct cache_object_ctx              ctx;
    int                                  status;

    void                                *shm_data;                                    /* pointer into hash table */
    uint32_t                             shm_data_sz;

    if (cache_fetch_readable(hash, (char *)key, &shm_data, &shm_data_sz))
    {
        return AM_NOT_FOUND;
    }

    cache_object_ctx_init_data(&ctx, shm_data, (size_t)shm_data_sz);
    cache_object_skip_key(&ctx);
    *policy = am_policy_result_deserialise(&ctx);
    *session = am_name_value_deserialise(&ctx);

    cache_release_readlocked_ptr(hash);

    status = ctx.error;
    cache_object_ctx_destroy(&ctx);

    return status;

}

/*
 * cache policy and session data, add existing policies for other resources, overriding existing policies for the same resources
 *
 */
int am_add_session_policy_cache_entry(am_request_t *request, const char *key, struct am_policy_result *policy, struct am_namevalue *session)
{
    int                                  status;

    uint32_t                             hash = am_hash(key);

    struct am_policy_result             *merged = policy;

    struct cache_object_ctx              ctx;

    void                                *shm_data;                                    /* pointer into hash table */
    uint32_t                             shm_data_sz;

    if (cache_fetch_readable(hash, (char *)key, &shm_data, &shm_data_sz) == 0)
    {
        struct am_policy_result         *cached;

        cache_object_ctx_init_data(&ctx, shm_data, (size_t)shm_data_sz);
        cache_object_skip_key(&ctx);
        cached = am_policy_result_deserialise(&ctx);                                  /* read cached policy */

        cache_release_readlocked_ptr(hash);

        status = ctx.error;
        cache_object_ctx_destroy(&ctx);

        if (status)
        {
            return status;                                                            /* serialisation problem */
        }

        while (cached)                                                                /* add existing policies, new ones override */
        {
            struct am_policy_result     *p;

            for (p = policy; p; p = p->next)
            {
                if (strcmp(cached->resource, p->resource) == 0)
                    break;
            }

            struct am_policy_result     *next = cached->next;

            if (p)
            {
                cached->next = 0;                                                     /* discard existing policy */
                delete_am_policy_result_list(&cached);
            }
            else
            {
                cached->next = merged;                                                /* merge (prepend) existing policy */
                merged = cached;
            }

            cached = next;
        }
    }

    int                                  ttl = get_session_ttl(request, session);

    cache_object_ctx_init(&ctx);
    cache_object_write_key(&ctx, (char *)key);
    am_policy_result_serialise(&ctx, merged);
    am_name_value_serialise(&ctx, session);

    if (ctx.error)
    {
        status = ctx.error;
    }
    else if (cache_add(hash, ctx.data, ctx.data_size, time(0) + ttl, key_equality))
    {
        status = AM_ERROR;
    }
    else
    {
        status = AM_SUCCESS;
    }

    cache_object_ctx_destroy(&ctx);

    while (merged != policy)                                                          /* free merged policy */
    {
        struct am_policy_result         *next = merged->next;

        merged->next = 0;
        delete_am_policy_result_list(&merged);

        merged = next;
    }

    return status;

}

int am_cache_init(int instance)
{
    (instance);
    return 0;

}

int am_cache_shutdown()
{
    cache_shutdown();
    return 0;

}

void am_cache_destroy() {
//    cache_initialise(0);
    cache_shutdown();

}

