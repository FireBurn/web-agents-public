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
#include "list.h"

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

enum {
    AM_CACHE_SESSION = 0x1, /* cache entry type - session data */
    AM_CACHE_PDP = 0x2, /* cache entry type - pdp data */
    AM_CACHE_POLICY = 0x4, /* cache entry type - policy response */
    AM_CACHE_POLICY_RESPONSE_A = 0x8, /* attribute identifiers in policy response data (list) */
    AM_CACHE_POLICY_RESPONSE_D = 0x10,
    AM_CACHE_POLICY_ACTION = 0x20,
    AM_CACHE_POLICY_ADVICE = 0x40,
    AM_CACHE_POLICY_ALLOW = 0x80,
    AM_CACHE_POLICY_DENY = 0x100
};

/**
 * These constants are used with the three integer array entries in the array "size"
 * in the am_cache_entry_data structure.  Since the same elements are used in different circumstances
 * to mean different things, the same value is defined multiple times depending on what is being
 * stored.
 */
#define URL_LENGTH          0
#define FILENAME_LENGTH     1
#define CONTENT_TYPE_LENGTH 2

#define RESOURCE_LENGTH     0
#define RESOURCE_UNUSED_1   1
#define RESOURCE_UNUSED_2   2

#define NAME_LENGTH         0
#define VALUE_LENGTH        1
#define NAME_VALUE_UNUSED   2

struct am_cache_entry_data {
    unsigned int type;
    int index;
    int scope;
    char method;
    uint64_t ttl;
    size_t size[3];
    struct offset_list lh;
    char value[1]; /* format: value\0value\0value\0 */
};

struct am_cache_entry {
    char key[AM_HASH_TABLE_KEY_SIZE];
    time_t ts; /* create timestamp */
    int valid; /* entry is valid, in sec */
    unsigned long instance_id;
    struct offset_list data;
    struct offset_list lh; /* collisions */
};

struct am_cache {
    size_t count;
    struct offset_list table[AM_HASH_TABLE_SIZE]; /* first,last */
};

static am_shm_t *cache = NULL;

/**
 * Get a copy of the shared memory area handle pointed to by "cache".
 */
am_shm_t* get_cache(void) {
    return cache;
}

int am_cache_init(int id) {
    size_t i;
    if (cache != NULL) return AM_SUCCESS;

    cache = am_shm_create(get_global_name("am_shared_cache", id), sizeof(struct am_cache) +
            (sizeof(struct am_cache_entry) + sizeof(struct am_cache_entry_data)) * 2048);
    if (cache == NULL) {
        return AM_ERROR;
    }
    if (cache->error != AM_SUCCESS) {
        return cache->error;
    }

    if (cache->init) {
        struct am_cache *cache_data = (struct am_cache *) am_shm_alloc(cache, sizeof(struct am_cache));
        if (cache_data == NULL) {
            return AM_ENOMEM;
        }
        am_shm_lock(cache);
        cache_data->count = 0;
        /* initialize head nodes */
        for (i = 0; i < AM_HASH_TABLE_SIZE; i++) {
            cache_data->table[i].next = cache_data->table[i].prev = 0;
        }
        /* store table offset (for other processes) */
        am_shm_set_user_offset(cache, AM_GET_OFFSET(cache->pool, cache_data));
        am_shm_unlock(cache);
    }

    return AM_SUCCESS;
}

int am_cache_shutdown() {
    am_shm_shutdown(cache);
    cache = NULL;
    return AM_SUCCESS;
}

/**
 * Utterly destroy the shared memory area handle pointed to by "cache", i.e. delete/unlink
 * the shared memory block, destroy the locks, shared memory files and process-wide
 * mutexes.
 *
 * CALL THIS FUNCTION WITH EXTREME CARE.  It is intended for test cases ONLY, so each
 * test case can start with a clean slate.
 */
void am_cache_destroy() {
    am_shm_destroy(cache);
    cache = NULL;
}

static struct am_cache * get_cache_header_data() {
    return (struct am_cache *)am_shm_get_user_pointer(cache);
}

static unsigned int index_for(unsigned int tablelength, unsigned int hashvalue) {
    return (hashvalue % tablelength);
}

/**
 * Get cache entry. The function must be called while holding the mutex (am_shm_lock).
 */
static struct am_cache_entry *get_cache_entry(const char *key, int *index) {
    struct am_cache_entry *element, *tmp, *head;
    unsigned int key_hash;
    int entry_index;
    
    struct am_cache *cache_data = get_cache_header_data();
    if (cache_data == NULL) {
        return NULL;
    }

    key_hash = am_hash(key);
    entry_index = index_for(AM_HASH_TABLE_SIZE, key_hash);
    head = (struct am_cache_entry *) AM_GET_POINTER(cache->pool, cache_data->table[entry_index].prev);

    AM_OFFSET_LIST_FOR_EACH(cache->pool, head, element, tmp, struct am_cache_entry) {
        if (strcmp(key, element->key) == 0) {
            if (index) {
                *index = entry_index;
            }
            return element;
        }
    }
    return NULL;
}

/**
 * Delete cache entry. The function must be called while holding the mutex (am_shm_lock).
 */
static int delete_cache_entry(int entry_index, struct am_cache_entry *element) {

    struct am_cache_entry_data *i, *tmp, *head;
    struct am_cache *cache_data;

    if (element == NULL) {
        return AM_EINVAL;
    }

    cache_data = get_cache_header_data();
    if (cache_data == NULL) {
        return AM_EINVAL;
    }
    
    /* cleanup cache entry data */
    head = (struct am_cache_entry_data *) AM_GET_POINTER(cache->pool, element->data.prev);

    AM_OFFSET_LIST_FOR_EACH(cache->pool, head, i, tmp, struct am_cache_entry_data) {
        am_shm_free(cache, i);
    }

    /* remove a node from a doubly linked list */
    if (element->lh.prev == 0) {
        cache_data->table[entry_index].prev = element->lh.next;
    } else {
        ((struct am_cache_entry *) AM_GET_POINTER(cache->pool, element->lh.prev))->lh.next = element->lh.next;
    }

    if (element->lh.next == 0) {
        cache_data->table[entry_index].next = element->lh.prev;
    } else {
        ((struct am_cache_entry *) AM_GET_POINTER(cache->pool, element->lh.next))->lh.prev = element->lh.prev;
    }
    return AM_SUCCESS;
}

/**
 * Delete cache entry element. The function must be called while holding the mutex (am_shm_lock).
 */
static int delete_cache_entry_element_by_index(struct am_cache_entry *entry, int index) {

    struct am_cache_entry_data *i, *tmp, *head;

    if (entry == NULL) {
        return AM_EINVAL;
    }

    /* cleanup cache entry element data */
    head = (struct am_cache_entry_data *) AM_GET_POINTER(cache->pool, entry->data.prev);

    AM_OFFSET_LIST_FOR_EACH(cache->pool, head, i, tmp, struct am_cache_entry_data) {
        if (i->index == index) {
            /* remove a node from a doubly linked list */
            if (i->lh.prev == 0) {
                entry->data.prev = i->lh.next;
            } else {
                ((struct am_cache_entry_data *) AM_GET_POINTER(cache->pool, i->lh.prev))->lh.next = i->lh.next;
            }

            if (i->lh.next == 0) {
                entry->data.next = i->lh.prev;
            } else {
                ((struct am_cache_entry_data *) AM_GET_POINTER(cache->pool, i->lh.next))->lh.prev = i->lh.prev;
            }
            am_shm_free(cache, i);
        }
    }

    return AM_SUCCESS;
}

/*
 * Remove cache entries that that have expired as of the expiry_time, which would be set
 * to the current time.
 * 
 * Note: this will be called in the memory allocator (shared.c) when memory is low, and it will be
 * enclosed in lock/unlock blocks, so they are not required here.
 *
 * Returns the number of cache entries removed.
 */
int am_purge_caches(time_t expiry_time) {
    struct am_cache_entry *cache_entry, *tmp, *head;
    struct am_cache *cache_data;
    
    int delete_count;
    int i;

    cache_data = get_cache_header_data();
    if (cache_data == NULL) {
        return 0;
    }
    
    delete_count = 0;
    
    for (i = 0; i < AM_HASH_TABLE_SIZE; i++) {
        // NOTE: prev is first, and so is head
        head = (struct am_cache_entry *) AM_GET_POINTER(cache->pool, cache_data->table[i].prev);
        AM_OFFSET_LIST_FOR_EACH(cache->pool, head, cache_entry, tmp, struct am_cache_entry) {
            if (difftime(cache_entry->ts + cache_entry->valid, expiry_time) < 0) {
                // remove the data list from this element
                if (delete_cache_entry(i, cache_entry) == 0) {
                    am_shm_free(cache, cache_entry);
                    delete_count++;
                }
            }
        }
    }
    cache_data->count -= delete_count;
    
    return delete_count;
}

/*
 * Purge caches to the current time
 */
int am_purge_caches_to_now()
{
    return am_purge_caches(time(NULL));
}


/* 
 * Find PDP cache entry (key: uuid value).
 */
int am_get_pdp_cache_entry(am_request_t *request, const char *key, char **data, size_t *data_sz, char **content_type) {
    static const char *thisfunc = "am_get_pdp_cache_entry():";
    int status = AM_NOT_FOUND;
    int entry_index = 0;
    struct am_cache_entry *cache_entry;
    struct am_cache_entry_data *element, *temp, *head;
    struct am_cache *cache_data;
    int lock_status;
    
    if (ISINVALID(key)) {
        return AM_EINVAL;
    }
    
    lock_status = am_shm_lock(cache);
    if (lock_status != AM_SUCCESS) {
        return lock_status;
    }
    
    cache_data = get_cache_header_data();
    if (cache_data == NULL) {
        am_shm_unlock(cache);
        return AM_ENOMEM;
    }

    cache_entry = get_cache_entry(key, &entry_index);
    if (cache_entry == NULL) {
        AM_LOG_WARNING(request->instance_id, "%s failed to locate data for a key (%s)", thisfunc, key);
        am_shm_unlock(cache);
        return AM_NOT_FOUND;
    }

    if (request->conf->pdp_cache_valid > 0) {
        time_t ts = cache_entry->ts;
        ts += request->conf->pdp_cache_valid;
        if (difftime(time(NULL), ts) >= 0) {
            char tsc[32], tsu[32];
            struct tm created, until;
            localtime_r(&cache_entry->ts, &created);
            localtime_r(&ts, &until);
            strftime(tsc, sizeof(tsc), AM_CACHE_TIMEFORMAT, &created);
            strftime(tsu, sizeof(tsu), AM_CACHE_TIMEFORMAT, &until);
            AM_LOG_WARNING(request->instance_id, "%s data for a key (%s) is obsolete (created: %s, valid until: %s)",
                    thisfunc, key, tsc, tsu);

            head = (struct am_cache_entry_data *) AM_GET_POINTER(cache->pool, cache_entry->data.prev);

            AM_OFFSET_LIST_FOR_EACH(cache->pool, head, element, temp, struct am_cache_entry_data) {
                if (element->type == AM_CACHE_PDP && element->size[FILENAME_LENGTH] != 0) {
                    char *file = element->value + element->size[URL_LENGTH] + 1;
                    if (ISVALID(file)) {
                        if (unlink(file) != 0) {
                            AM_LOG_WARNING(request->instance_id, "%s error %d removing file %s",
                                    thisfunc, errno, file);
                        }
                        break;
                    }
                }
            }

            if (!delete_cache_entry(entry_index, cache_entry)) {
                am_shm_free(cache, cache_entry);
                cache_data->count--;
            }
            am_shm_unlock(cache);
            return AM_ETIMEDOUT;
        }
    }

    head = (struct am_cache_entry_data *) AM_GET_POINTER(cache->pool, cache_entry->data.prev);

    AM_OFFSET_LIST_FOR_EACH(cache->pool, head, element, temp, struct am_cache_entry_data) {
        if (element->type == AM_CACHE_PDP
                && element->size[URL_LENGTH] > 0
                && element->size[FILENAME_LENGTH] > 0
                && element->size[CONTENT_TYPE_LENGTH] > 0) {

            size_t size = element->size[URL_LENGTH] + element->size[FILENAME_LENGTH] + 2;
            *data = malloc(size);
            if (*data != NULL) {
                memcpy(*data, element->value, size);
                *data_sz = element->size[URL_LENGTH]; /* report url size only */
            }

            *content_type = malloc(element->size[CONTENT_TYPE_LENGTH] + 1);
            if (*content_type != NULL) {
                memcpy(*content_type, element->value + size, element->size[CONTENT_TYPE_LENGTH]);
                (*content_type)[element->size[CONTENT_TYPE_LENGTH]] = '\0';
            }
            status = AM_SUCCESS;
            break;
        }
    }

    am_shm_unlock(cache);
    return status;
}

/* 
 * Add PDP cache entry (key: uuid value).
 */
int am_add_pdp_cache_entry(am_request_t *request, const char *key, const char *url,
        const char *file, const char *content_type) {
    static const char *thisfunc = "am_add_pdp_cache_entry():";
    unsigned int key_hash;
    int entry_index = 0;
    size_t url_length, file_length, content_type_length;
    struct am_cache_entry *cache_entry;
    int cache_entry_offset;
    struct am_cache_entry_data *cache_entry_data;
    struct am_cache *cache_data;
    size_t entry_data_len;
    int lock_status;
    
    if (ISINVALID(key) || ISINVALID(url) || ISINVALID(file) || ISINVALID(content_type)) {
        return AM_EINVAL;
    }
    if (strlen(key) >= AM_HASH_TABLE_KEY_SIZE) {
        return AM_E2BIG;
    }

    url_length = strlen(url);
    file_length = strlen(file);
    content_type_length = strlen(content_type);

    key_hash = am_hash(key);
    entry_index = index_for(AM_HASH_TABLE_SIZE, key_hash);

    lock_status = am_shm_lock(cache);
    if (lock_status != AM_SUCCESS) {
        return lock_status;
    }
    
    cache_data = get_cache_header_data();
    if (cache_data == NULL) {
        am_shm_unlock(cache);
        return AM_ENOMEM;
    }
    
    cache_entry = get_cache_entry(key, NULL);
    if (cache_entry != NULL) {
        if (!delete_cache_entry(entry_index, cache_entry)) {
            am_shm_free(cache, cache_entry);
            cache_data->count--;
            cache_entry = NULL;
        } else {
            AM_LOG_ERROR(request->instance_id, "%s failed to remove cache entry (%s)",
                    thisfunc, key);
            am_shm_unlock(cache);
            return AM_ERROR;
        }
    }

    cache_entry = am_shm_alloc_and_purge(cache, sizeof(struct am_cache_entry), am_purge_caches_to_now);
    if (cache_entry == NULL) {
        AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes",
                thisfunc, sizeof(struct am_cache_entry));
        am_shm_unlock(cache);
        return AM_ENOMEM;
    }

    cache_data = get_cache_header_data();
    if (cache_data == NULL) {
        am_shm_unlock(cache);
        am_shm_free(cache, cache_entry);
        return AM_ENOMEM;
    }

    cache_entry_offset = AM_GET_OFFSET(cache->pool, cache_entry);
    
    cache_entry->ts = time(NULL);
    cache_entry->valid = request->conf->pdp_cache_valid;
    cache_entry->instance_id = request->instance_id;
    strncpy(cache_entry->key, key, sizeof(cache_entry->key) - 1);

    cache_entry->data.next = cache_entry->data.prev = 0;
    cache_entry->lh.next = cache_entry->lh.prev = 0;
    
    AM_OFFSET_LIST_INSERT(cache->pool, cache_entry, &(cache_data->table[entry_index]), struct am_cache_entry);

    entry_data_len = sizeof(struct am_cache_entry_data) +url_length + file_length + content_type_length + 3;
    cache_entry_data = am_shm_alloc_and_purge(cache, entry_data_len, am_purge_caches_to_now);
    cache_entry = ((struct am_cache_entry *)AM_GET_POINTER(cache->pool, cache_entry_offset));
    
    if (cache_entry_data == NULL) {
        AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes",
                thisfunc, entry_data_len);
        am_shm_unlock(cache);
        return AM_ENOMEM;
    }

    cache_entry_data->type = AM_CACHE_PDP;
    cache_entry_data->method = AM_REQUEST_UNKNOWN;
    cache_entry_data->ttl = 0;

    cache_entry_data->size[URL_LENGTH] = url_length;
    cache_entry_data->size[FILENAME_LENGTH] = file_length;
    cache_entry_data->size[CONTENT_TYPE_LENGTH] = content_type_length;

    mem3cpy(cache_entry_data->value, url, url_length, file, file_length, content_type, content_type_length);

    cache_entry_data->lh.next = cache_entry_data->lh.prev = 0;

    AM_OFFSET_LIST_INSERT(cache->pool, cache_entry_data, &cache_entry->data, struct am_cache_entry_data);

    cache_data->count++;

    am_shm_unlock(cache);
    return AM_SUCCESS;
}

/*
 * Delete a shared cache entry (key: any)
 */
int am_remove_cache_entry(unsigned long instance_id, const char *key) {
    static const char *thisfunc = "am_remove_cache_entry():";
    int entry_index = 0;
    int result;
    struct am_cache_entry *cache_entry;
    struct am_cache *cache_data;

    if (ISINVALID(key)) {
        return AM_EINVAL;
    }
    
    result = am_shm_lock(cache);
    if (result != AM_SUCCESS) {
        return result;
    }
    
    cache_data = get_cache_header_data();
    if (cache_data == NULL) {
        am_shm_unlock(cache);
        return AM_ENOMEM;
    }
    
    cache_entry = get_cache_entry(key, &entry_index);
    if (cache_entry == NULL) {
        AM_LOG_WARNING(instance_id, "%s cache data is not available (%s)", thisfunc, key);
        am_shm_unlock(cache);
        return AM_NOT_FOUND;
    }

    result = delete_cache_entry(entry_index, cache_entry);
    if (result != 0) {
        AM_LOG_ERROR(instance_id, "%s failed to remove cache entry (%s)", thisfunc, key);
    } else {
        am_shm_free(cache, cache_entry);
        cache_data->count--;
        AM_LOG_DEBUG(instance_id, "%s cache entry removed (%s)", thisfunc, key);
    }
    am_shm_unlock(cache);
    return result;
}

/* 
 * Find session/policy response cache entry (key: session token).
 */
int am_get_session_policy_cache_entry(am_request_t *request, const char *key,
        struct am_policy_result **policy, struct am_namevalue **session, time_t *ets) {

    static const char *thisfunc = "am_get_session_policy_cache_entry():";
    int i = -1, entry_index, status = AM_NOT_FOUND;
    struct am_cache_entry *cache_entry;
    struct am_cache_entry_data *a, *tmp, *head;

    struct am_cache *cache_data;
    struct am_namevalue *sesion_attrs = NULL;
    struct am_policy_result *pol_attrs = NULL, *pol_curr = NULL;
    struct am_action_decision *action_curr = NULL;
    int lock_status;
    
    if (ISINVALID(key)) {
        return AM_EINVAL;
    }

    lock_status = am_shm_lock(cache);
    if (lock_status != AM_SUCCESS) {
        return lock_status;
    }
    
    cache_data = get_cache_header_data();
    if (cache_data == NULL) {
        am_shm_unlock(cache);
        return AM_ENOMEM;
    }
    
    cache_entry = get_cache_entry(key, &entry_index);
    if (cache_entry == NULL) {
        AM_LOG_WARNING(request->instance_id, "%s failed to locate data for a key (%s)", thisfunc, key);
        am_shm_unlock(cache);
        return AM_NOT_FOUND;
    }

    if (cache_entry->valid > 0) {
        time_t ts = cache_entry->ts;
        ts += cache_entry->valid;
        if (difftime(time(NULL), ts) >= 0) {
            char tsc[32], tsu[32];
            struct tm created, until;
            localtime_r(&cache_entry->ts, &created);
            localtime_r(&ts, &until);
            strftime(tsc, sizeof(tsc), AM_CACHE_TIMEFORMAT, &created);
            strftime(tsu, sizeof(tsu), AM_CACHE_TIMEFORMAT, &until);
            AM_LOG_WARNING(request->instance_id, "%s data for a key (%s) is obsolete (created: %s, valid until: %s)",
                    thisfunc, key, tsc, tsu);
            if (!delete_cache_entry(entry_index, cache_entry)) {
                am_shm_free(cache, cache_entry);
                cache_data->count--;
            }
            am_shm_unlock(cache);
            return AM_ETIMEDOUT;

            /* expired cache entry use is currently disabled
              *ets = cache_entry->ts;
             */ 
        }
    }

    head = (struct am_cache_entry_data *) AM_GET_POINTER(cache->pool, cache_entry->data.prev);

    AM_OFFSET_LIST_FOR_EACH(cache->pool, head, a, tmp, struct am_cache_entry_data) {

        if (a->type == AM_CACHE_SESSION && a->size[0] > 0 && a->size[1] > 0) {
            struct am_namevalue *el = NULL;
            if (create_am_namevalue_node(a->value, a->size[0], a->value + a->size[0] + 1, a->size[1], &el) == 0) {
                AM_LIST_INSERT(sesion_attrs, el);
            }
        } else if (AM_BITMASK_CHECK(a->type, AM_CACHE_POLICY)) {

            if (i != a->index) {
                struct am_policy_result *el = NULL;
                if (create_am_policy_result_node(a->value, a->size[0], &el) == 0) {
                    AM_LIST_INSERT(pol_attrs, el);
                    el->index = i = a->index;
                    el->scope = a->scope;
                    el->created = cache_entry->ts;
                    pol_curr = el;
                }
            }

            if (pol_curr == NULL) {
                continue;
            }

            if (a->type == AM_CACHE_POLICY && i == a->index && pol_curr != NULL) {
                am_free(pol_curr->resource);
                pol_curr->resource = strndup(a->value, a->size[0]);
                pol_curr->scope = a->scope;
            }

            if (AM_BITMASK_CHECK(a->type, AM_CACHE_POLICY_RESPONSE_A) && a->size[0] > 0 && a->size[1] > 0) {
                struct am_namevalue *el = NULL;
                if (create_am_namevalue_node(a->value, a->size[0], a->value + a->size[0] + 1, a->size[1], &el) == 0) {
                    AM_LIST_INSERT(pol_curr->response_attributes, el);
                }
            }
            if (AM_BITMASK_CHECK(a->type, AM_CACHE_POLICY_RESPONSE_D) && a->size[0] > 0 && a->size[1] > 0) {
                struct am_namevalue *el = NULL;
                if (create_am_namevalue_node(a->value, a->size[0], a->value + a->size[0] + 1, a->size[1], &el) == 0) {
                    AM_LIST_INSERT(pol_curr->response_decisions, el);
                }
            }
            if (AM_BITMASK_CHECK(a->type, AM_CACHE_POLICY_ACTION)) {
                am_bool_t act;
                struct am_action_decision *el = NULL;
                act = TO_BOOL(a->type & AM_CACHE_POLICY_ALLOW);
                if (create_am_action_decision_node(act, a->method, a->ttl, &el) == 0) {
                    AM_LIST_INSERT(pol_curr->action_decisions, el);
                    action_curr = el;
                }
            }
            if (AM_BITMASK_CHECK(a->type, AM_CACHE_POLICY_ADVICE) && a->size[0] > 0 && a->size[1] > 0) {
                struct am_namevalue *el = NULL;
                if (create_am_namevalue_node(a->value, a->size[0], a->value + a->size[0] + 1, a->size[1], &el) == 0) {
                    AM_LIST_INSERT(action_curr->advices, el);
                }
            }
        }
    }

    if (session != NULL) {
        *session = sesion_attrs;
    }
    if (policy != NULL) {
        *policy = pol_attrs;
    }
    if (sesion_attrs != NULL || pol_attrs != NULL) {
        status = AM_SUCCESS;
    }

    am_shm_unlock(cache);
    return status;
}

static int am_store_policy_result_element(am_request_t *request, struct am_policy_result *element,
        int cache_entry_offset, int index) {
    
    static const char *thisfunc = "am_store_policy_result_element():";
    struct am_namevalue *rae, *rat; /* response attributes element, response attributes tmp */
    struct am_namevalue *rde, *rdt; /* response decisions element, responce decisions tmp */
    struct am_action_decision *ae, *at; /* action (decisions) element, action (decisions) tmp */
    struct am_namevalue *aee, *att; /* advices element, advices tmp */

    struct am_cache_entry *cache_entry;
    
    size_t resource_len = strlen(element->resource);
    size_t policy_len = sizeof(struct am_cache_entry_data) + resource_len + 1;
    struct am_cache_entry_data *policy = am_shm_alloc_and_purge(cache, policy_len, am_purge_caches_to_now);
    cache_entry = AM_GET_POINTER(cache->pool, cache_entry_offset);
    
    if (policy == NULL) {
        AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes", thisfunc, policy_len);
        return AM_ENOMEM;
    }

    /* add policy entry (per resource) */
    memset(policy, 0, policy_len);
    policy->type = AM_CACHE_POLICY;
    policy->method = AM_REQUEST_UNKNOWN;
    policy->scope = element->scope;
    policy->index = index;
    policy->ttl = cache_entry->ts + cache_entry->valid;
    policy->size[RESOURCE_LENGTH] = resource_len;
    strcpy(policy->value, element->resource);
    AM_OFFSET_LIST_INSERT(cache->pool, policy, &cache_entry->data, struct am_cache_entry_data);

    /* add response attributes */
    AM_LIST_FOR_EACH(element->response_attributes, rae, rat) {
        size_t attr_len = sizeof(struct am_cache_entry_data) + rae->ns + rae->vs + 2;
        struct am_cache_entry_data *attr = am_shm_alloc_and_purge(cache, attr_len, am_purge_caches_to_now);
        cache_entry = AM_GET_POINTER(cache->pool, cache_entry_offset);
        
        if (attr == NULL) {
            AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes", thisfunc, attr_len);
            return AM_ENOMEM;
        }

        memset(attr, 0, attr_len);
        attr->type = AM_CACHE_POLICY | AM_CACHE_POLICY_RESPONSE_A;
        attr->method = AM_REQUEST_UNKNOWN;
        attr->scope = -1;
        attr->index = index;
        attr->ttl = cache_entry->ts + cache_entry->valid;
        attr->size[NAME_LENGTH] = rae->ns;
        attr->size[VALUE_LENGTH] = rae->vs;
        mem2cpy(attr->value, rae->n, rae->ns, rae->v, rae->vs);
        AM_OFFSET_LIST_INSERT(cache->pool, attr, &cache_entry->data, struct am_cache_entry_data);
    }

    AM_LIST_FOR_EACH(element->action_decisions, ae, at) {

        {
            /* add action decision */
            size_t action_decision_len = sizeof(struct am_cache_entry_data);
            struct am_cache_entry_data *action_decision = am_shm_alloc_and_purge(cache, action_decision_len, am_purge_caches_to_now);
            cache_entry = AM_GET_POINTER(cache->pool, cache_entry_offset);
            
            if (action_decision == NULL) {
                AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes", thisfunc, action_decision_len);
                return AM_ENOMEM;
            }

            memset(action_decision, 0, action_decision_len);
            action_decision->type = AM_CACHE_POLICY | AM_CACHE_POLICY_ACTION;
            if (ae->action) {
                action_decision->type |= AM_CACHE_POLICY_ALLOW;
            } else {
                action_decision->type |= AM_CACHE_POLICY_DENY;
            }
            action_decision->method = ae->method;
            action_decision->ttl = ae->ttl;
            action_decision->scope = -1;
            action_decision->index = index;
            AM_OFFSET_LIST_INSERT(cache->pool, action_decision, &cache_entry->data, struct am_cache_entry_data);
        }

        AM_LIST_FOR_EACH(ae->advices, aee, att) {
            /* add advices */
            size_t advice_len = sizeof(struct am_cache_entry_data) + aee->ns + aee->vs + 2;
            struct am_cache_entry_data *advice = am_shm_alloc_and_purge(cache, advice_len, am_purge_caches_to_now);
            cache_entry = AM_GET_POINTER(cache->pool, cache_entry_offset);
            
            if (advice == NULL) {
                AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes", thisfunc, advice_len);
                return AM_ENOMEM;
            }

            memset(advice, 0, advice_len);
            advice->type = AM_CACHE_POLICY | AM_CACHE_POLICY_ADVICE;
            advice->method = AM_REQUEST_UNKNOWN;
            advice->scope = -1;
            advice->index = index;
            advice->ttl = cache_entry->ts + cache_entry->valid;
            advice->size[NAME_LENGTH] = aee->ns;
            advice->size[VALUE_LENGTH] = aee->vs;
            mem2cpy(advice->value, aee->n, aee->ns, aee->v, aee->vs);
            AM_OFFSET_LIST_INSERT(cache->pool, advice, &cache_entry->data, struct am_cache_entry_data);
        }
    }

    /* add response decisions (profile attributes) */
    AM_LIST_FOR_EACH(element->response_decisions, rde, rdt) {
        size_t profile_attr_len = sizeof(struct am_cache_entry_data) + rde->ns + rde->vs + 2;
        struct am_cache_entry_data *profile_attr = am_shm_alloc_and_purge(cache, profile_attr_len, am_purge_caches_to_now);
        cache_entry = AM_GET_POINTER(cache->pool, cache_entry_offset);

        if (profile_attr == NULL) {
            AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes", thisfunc, profile_attr_len);
            return AM_ENOMEM;
        }

        memset(profile_attr, 0, profile_attr_len);
        profile_attr->type = AM_CACHE_POLICY | AM_CACHE_POLICY_RESPONSE_D;
        profile_attr->method = AM_REQUEST_UNKNOWN;
        profile_attr->scope = -1;
        profile_attr->index = index;
        profile_attr->ttl = cache_entry->ts + cache_entry->valid;
        profile_attr->size[NAME_LENGTH] = rde->ns;
        profile_attr->size[VALUE_LENGTH] = rde->vs;
        mem2cpy(profile_attr->value, rde->n, rde->ns, rde->v, rde->vs);
        AM_OFFSET_LIST_INSERT(cache->pool, profile_attr, &cache_entry->data, struct am_cache_entry_data);
    }

    return AM_SUCCESS;
}

static int am_merge_session_policy_cache_entry(am_request_t *request, const char *key,
        struct am_policy_result *policy, struct am_namevalue *session, struct am_cache_entry *cache_entry) {
    
    static const char *thisfunc = "am_merge_session_policy_cache_entry():";
    struct am_cache_entry_data *cache_entry_data, *tmp, *head;
    int index = 0, j, i = 0, count = 128; /* index_arr size estimate (realloc use only) */
    struct am_policy_result *policy_element, *t, *last_added = NULL;
    int *index_arr, *index_arr_tmp;
    int status = AM_SUCCESS;

    const int cache_entry_offset = AM_GET_OFFSET(cache->pool, cache_entry); /* this is constant after shm_alloc, whereas the pointer isn't */
    head = (struct am_cache_entry_data *) AM_GET_POINTER(cache->pool, cache_entry->data.prev);

    index_arr = (int *) malloc(count * sizeof(int));
    if (index_arr == NULL) {
        return AM_ENOMEM;
    }

    /* find indices to be updated */
    AM_OFFSET_LIST_FOR_EACH(cache->pool, head, cache_entry_data, tmp, struct am_cache_entry_data) {
        if (cache_entry_data->type == AM_CACHE_POLICY) {

            AM_LIST_FOR_EACH(policy, policy_element, t) {
                if (last_added == policy_element) {
                    /* no duplicates in index_arr */
                    continue;
                }
                if (strcmp(cache_entry_data->value, policy_element->resource) == 0) {
                    if (count < i) {
                        count <<= 1; /* double index_arr size */
                        index_arr_tmp = (int *) realloc(index_arr, count * sizeof(int));
                        if (index_arr_tmp == NULL) {
                            am_free(index_arr);
                            return AM_ENOMEM;
                        }
                        index_arr = index_arr_tmp;
                    }
                    index_arr[i++] = cache_entry_data->index;
                    last_added = policy_element;
                }
            }
        }
        index = MAX(index, cache_entry_data->index);
    }

    /* remove entries by index value (linked to this policy cache_entry) */
    for (j = 0; j < i; j++) {
        delete_cache_entry_element_by_index(cache_entry, index_arr[j]);
    }
    
    /* add all entries from a (new) list into the cache (linked to this policy cache_entry) */
    AM_LIST_FOR_EACH(policy, policy_element, t) {
        status = am_store_policy_result_element(request, policy_element, cache_entry_offset, ++index);
        if (status != AM_SUCCESS) {
            AM_LOG_ERROR(request->instance_id, "%s store_policy_result_element failed with '%s' (%d)", thisfunc,
                    am_strerror(status), status);
            break;
        }
    }

    free(index_arr);
    return status;
}

/* 
 * Add session/policy response cache entry (key: session token).
 */
int am_add_session_policy_cache_entry(am_request_t *request, const char *key,
        struct am_policy_result *policy, struct am_namevalue *session) {

    static const char *thisfunc = "am_add_session_policy_cache_entry():";
    unsigned int key_hash;
    int entry_index = 0, max_caching, time_left;

    struct am_cache_entry *cache_entry;
    struct am_cache *cache_data;

    int cache_entry_offset;
    int lock_status;
    
    if (ISINVALID(key) || (policy == NULL && session == NULL)) {
        return AM_EINVAL;
    }
    if (strlen(key) >= AM_HASH_TABLE_KEY_SIZE) {
        return AM_E2BIG;
    }

    key_hash = am_hash(key);
    entry_index = index_for(AM_HASH_TABLE_SIZE, key_hash);

    lock_status = am_shm_lock(cache);
    if (lock_status != AM_SUCCESS) {
        return lock_status;
    }

    cache_entry = get_cache_entry(key, NULL);
    if (cache_entry != NULL) {
        int status = am_merge_session_policy_cache_entry(request, key,
                policy, session, cache_entry);
        am_shm_unlock(cache);
        return status;
    }

    cache_entry = am_shm_alloc_and_purge(cache, sizeof(struct am_cache_entry), am_purge_caches_to_now);
    if (cache_entry == NULL) {
        AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes",
                thisfunc, sizeof(struct am_cache_entry));
        am_shm_unlock(cache);
        return AM_ENOMEM;
    }
    
    cache_data = get_cache_header_data();
    if (cache_data == NULL) {
        am_shm_unlock(cache);
        am_shm_free(cache, cache_entry);
        return AM_ENOMEM;
    }

    cache_entry_offset = AM_GET_OFFSET(cache->pool, cache_entry);
    
    /* maxcaching value is in minutes, timeleft in seconds */
    max_caching = get_ttl_value(session, "maxcaching", request->conf->token_cache_valid, AM_TRUE);
    time_left = get_ttl_value(session, "timeleft", request->conf->token_cache_valid, AM_FALSE);

    cache_entry->ts = time(NULL);
    cache_entry->valid = request->conf->token_cache_valid <= max_caching ?
            request->conf->token_cache_valid : (max_caching < time_left ? max_caching : time_left);
    cache_entry->instance_id = request->instance_id;
    strncpy(cache_entry->key, key, sizeof(cache_entry->key) - 1);

    cache_entry->data.next = cache_entry->data.prev = 0;
    cache_entry->lh.next = cache_entry->lh.prev = 0;

    AM_OFFSET_LIST_INSERT(cache->pool, cache_entry, &(cache_data->table[entry_index]), struct am_cache_entry);
    cache_data->count += 1;

    if (session != NULL) {
        struct am_namevalue *element, *tmp;
        
        AM_LIST_FOR_EACH(session, element, tmp) {
            size_t session_attr_len = sizeof(struct am_cache_entry_data) +element->ns + element->vs + 2;
            struct am_cache_entry_data *session_attr = am_shm_alloc_and_purge(cache, session_attr_len, am_purge_caches_to_now);
            cache_entry = AM_GET_POINTER(cache->pool, cache_entry_offset);
            if (session_attr == NULL) {
                AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes", thisfunc, session_attr_len);
                am_shm_unlock(cache);
                return AM_ENOMEM;
            }
            session_attr->type = AM_CACHE_SESSION;
            session_attr->method = AM_REQUEST_UNKNOWN;
            session_attr->scope = session_attr->index = -1; /* not used in this context */
            session_attr->ttl = cache_entry->ts + cache_entry->valid;

            session_attr->size[NAME_LENGTH] = element->ns;
            session_attr->size[VALUE_LENGTH] = element->vs;
            session_attr->size[NAME_VALUE_UNUSED] = 0;

            mem2cpy(session_attr->value, element->n, element->ns, element->v, element->vs);

            session_attr->lh.next = session_attr->lh.prev = 0;

            AM_OFFSET_LIST_INSERT(cache->pool, session_attr, &cache_entry->data, struct am_cache_entry_data);
        }
    }

    if (policy != NULL) {
        struct am_policy_result *element, *tmp;

        AM_LIST_FOR_EACH(policy, element, tmp) {
            int status = am_store_policy_result_element(request, element, cache_entry_offset, element->index);
            if (status != AM_SUCCESS) {
                AM_LOG_ERROR(request->instance_id, "%s store_policy_result_element failed with '%s' (%d)", thisfunc,
                        am_strerror(status), status);
                am_shm_unlock(cache);
                return status;
            }
        }
    }

    am_shm_unlock(cache);
    return AM_SUCCESS;
}

/**
 * Fetch global policy-resource cache entry (key: AM_POLICY_CHANGE_KEY).
 * 
 * @return AM_SUCCESS if found, AM_NOT_FOUND if not found, AM_ETIMEDOUT if
 * not valid (either obsolete or newer than a reference time)
 */
int am_get_policy_cache_entry(am_request_t *request, const char *key, time_t reference) {
    static const char *thisfunc = "am_get_policy_cache_entry():";
    int entry_index = 0;
    char tsc[32], tsu[32];
    struct tm created, until;
    struct am_cache_entry *cache_entry;
    struct am_cache *cache_data;
    int lock_status;
    
    if (ISINVALID(key)) {
        return AM_EINVAL;
    }
    
    lock_status = am_shm_lock(cache);
    if (lock_status != AM_SUCCESS) {
        return lock_status;
    }
    
    cache_data = get_cache_header_data();
    if (cache_data == NULL) {
        am_shm_unlock(cache);
        return AM_ENOMEM;
    }
    
    cache_entry = get_cache_entry(key, &entry_index);
    if (cache_entry == NULL) {
        /* policy-change cache has no entry yet */
        am_shm_unlock(cache);
        return AM_SUCCESS;
    }

    if (cache_entry->valid > 0) {
        time_t ts = cache_entry->ts;
        ts += cache_entry->valid;
        if (difftime(time(NULL), ts) >= 0) {
            localtime_r(&cache_entry->ts, &created);
            localtime_r(&ts, &until);
            strftime(tsc, sizeof(tsc), AM_CACHE_TIMEFORMAT, &created);
            strftime(tsu, sizeof(tsu), AM_CACHE_TIMEFORMAT, &until);
            AM_LOG_WARNING(request->instance_id, "%s data for a key (%s) is obsolete (created: %s, valid until: %s)",
                    thisfunc, key, tsc, tsu);
            if (!delete_cache_entry(entry_index, cache_entry)) {
                am_shm_free(cache, cache_entry);
                cache_data->count--;
            }
            am_shm_unlock(cache);
            return AM_ETIMEDOUT;
        }
    }

    if (reference > 0 && difftime(cache_entry->ts, reference) >= 0) {
        localtime_r(&cache_entry->ts, &created);
        localtime_r(&reference, &until);
        strftime(tsc, sizeof(tsc), AM_CACHE_TIMEFORMAT, &created);
        strftime(tsu, sizeof(tsu), AM_CACHE_TIMEFORMAT, &until);
        AM_LOG_WARNING(request->instance_id, "%s data for a key (%s) is newer than reference data (created: %s, reference: %s)",
                thisfunc, key, tsc, tsu);
        am_shm_unlock(cache);
        return AM_ETIMEDOUT;
    }

    am_shm_unlock(cache);
    return AM_SUCCESS;
}

/**
 * Add global policy-resource cache entry (key: AM_POLICY_CHANGE_KEY).
 * 
 * @return AM_SUCCESS if operation was successful
 */
int am_add_policy_cache_entry(am_request_t *r, const char *key, int valid) {
    static const char *thisfunc = "am_add_policy_cache_entry():";
    unsigned int key_hash;
    int entry_index = 0;
    struct am_cache_entry *cache_entry;
    struct am_cache *cache_data;
    int lock_status;

    if (ISINVALID(key)) {
        return AM_EINVAL;
    }
    if (strlen(key) >= AM_HASH_TABLE_KEY_SIZE) {
        return AM_E2BIG;
    }

    key_hash = am_hash(key);
    entry_index = index_for(AM_HASH_TABLE_SIZE, key_hash);

    lock_status = am_shm_lock(cache);
    if (lock_status != AM_SUCCESS) {
        return lock_status;
    }
    
    cache_entry = get_cache_entry(key, NULL);
    if (cache_entry != NULL) {
        /* policy-change cache entry exists - update timestamp data */
        cache_entry->ts = time(NULL);
        cache_entry->valid = 0;
        cache_entry->instance_id = r->instance_id;
        am_shm_unlock(cache);
        return AM_SUCCESS;
    }

    cache_entry = am_shm_alloc_and_purge(cache, sizeof(struct am_cache_entry), am_purge_caches_to_now);
    if (cache_entry == NULL) {
        AM_LOG_ERROR(r->instance_id, "%s failed to allocate %ld bytes",
                thisfunc, sizeof(struct am_cache_entry));
        am_shm_unlock(cache);
        return AM_ENOMEM;
    }

    cache_data = get_cache_header_data();
    if (cache_data == NULL) {
        am_shm_unlock(cache);
        am_shm_free(cache, cache_entry);
        return AM_ENOMEM;
    }
    
    cache_entry->ts = time(NULL);
    cache_entry->valid = 0;
    cache_entry->instance_id = r->instance_id;
    strncpy(cache_entry->key, key, sizeof(cache_entry->key) - 1);
    
    cache_entry->data.next = cache_entry->data.prev = 0;
    cache_entry->lh.next = cache_entry->lh.prev = 0;
    
    AM_OFFSET_LIST_INSERT(cache->pool, cache_entry, &(cache_data->table[entry_index]), struct am_cache_entry);
    cache_data->count++;

    am_shm_unlock(cache);
    return AM_SUCCESS;
}
