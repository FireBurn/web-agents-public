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
 * Policy ResourceResult name (only) cache
 * ===============================================================
 * key: 'url value'
 * 
 * PDP cache:
 * ===============================================================
 * key: 'uuid value'
 * 
 */

enum {
    AM_CACHE_SESSION = 1 << 0, /*cache entry type - session data*/
    AM_CACHE_PDP = 1 << 1, /*cache entry type - pdp data*/
    AM_CACHE_POLICY = 1 << 2, /*cache entry type - policy response*/

    AM_CACHE_POLICY_RESPONSE_A = 1 << 3, /*attribute identifiers in policy response data (list)*/
    AM_CACHE_POLICY_RESPONSE_D = 1 << 4,
    AM_CACHE_POLICY_ACTION = 1 << 5,
    AM_CACHE_POLICY_ADVICE = 1 << 6,
    AM_CACHE_POLICY_ALLOW = 1 << 7,
    AM_CACHE_POLICY_DENY = 1 << 8
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
    char value[1]; /*format: value\0value\0value\0 */
};

struct am_cache_entry {
    char key[AM_HASH_TABLE_KEY_SIZE];
    time_t ts; /*create timestamp*/
    int valid; /*entry is valid, in sec*/
    unsigned long instance_id;
    struct offset_list data;
    struct offset_list lh; /*collisions*/
};

struct am_cache {
    size_t count;
    struct offset_list table[AM_HASH_TABLE_SIZE]; /* first,last */
};

static am_shm_t *cache = NULL;

int am_cache_init() {
    size_t i;
    if (cache != NULL) return AM_SUCCESS;

    cache = am_shm_create("am_shared_cache", sizeof (struct am_cache) +
            (sizeof (struct am_cache_entry) + sizeof (struct am_cache_entry_data)) * 2048);
    if (cache == NULL) {
        return AM_ERROR;
    }
    if (cache->error != AM_SUCCESS) {
        return cache->error;
    }

    if (cache->init) {
        struct am_cache *cache_data = (struct am_cache *) am_shm_alloc(cache, sizeof (struct am_cache));
        if (cache_data == NULL) {
            cache->user = NULL;
            return AM_ENOMEM;
        }
        am_shm_lock(cache);
        cache_data->count = 0;
        /* initialize head nodes */
        for (i = 0; i < AM_HASH_TABLE_SIZE; i++) {
            cache_data->table[i].next = cache_data->table[i].prev = 0;
        }
        cache->user = cache_data;
        /*store table offset (for other processes)*/
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

static unsigned int index_for(unsigned int tablelength, unsigned int hashvalue) {
    return (hashvalue % tablelength);
}

static unsigned int sdbm_hash(const void *s) {
    unsigned long hash = 0;
    int c;
    const unsigned char *str = (const unsigned char *) s;
    while ((c = *str++)) {
        hash = c + (hash << 6) + (hash << 16) - hash;
    }
    return (unsigned int) hash;
}

static unsigned int hash(const void *k) {
    unsigned int i = sdbm_hash(k);
    i += ~(i << 9);
    i ^= ((i >> 14) | (i << 18));
    i += (i << 4);
    i ^= ((i >> 10) | (i << 22));
    return i;
}

static struct am_cache_entry *get_cache_entry(const char *key, int *index) {
    struct am_cache_entry *element, *tmp, *head;
    unsigned int key_hash;
    int entry_index;
    struct am_cache *cache_data;

    if (cache == NULL || cache->user == NULL) {
        return NULL;
    }
    cache_data = (struct am_cache *) cache->user;
    key_hash = hash(key);
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
 * Delete a cache entry and return 0.
 */
static int delete_cache_entry(int entry_index, struct am_cache_entry *element) {

    struct am_cache_entry_data *i, *tmp, *head;
    struct am_cache *cache_data = (struct am_cache *) cache->user;

    if (element == NULL) {
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
    return 0;
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

    if (cache == NULL || cache->user == NULL) {
        return AM_ENOMEM;
    }
    if (ISINVALID(key)) {
        return AM_EINVAL;
    }
    am_shm_lock(cache);

    cache_data = cache->user;
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
            strftime(tsc, sizeof (tsc), AM_CACHE_TIMEFORMAT, &created);
            strftime(tsu, sizeof (tsu), AM_CACHE_TIMEFORMAT, &until);
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
                *data_sz = element->size[URL_LENGTH]; /*report url size only*/
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
    struct am_cache_entry_data *cache_entry_data;
    struct am_cache *cache_data;

    if (cache == NULL || cache->user == NULL) {
        return AM_ENOMEM;
    }
    if (ISINVALID(key) || ISINVALID(url) || ISINVALID(file) || ISINVALID(content_type)) {
        return AM_EINVAL;
    }
    if (strlen(key) >= AM_HASH_TABLE_SIZE) {
        return AM_E2BIG;
    }

    cache_data = (struct am_cache *) cache->user;

    url_length = strlen(url);
    file_length = strlen(file);
    content_type_length = strlen(content_type);

    key_hash = hash(key);
    entry_index = index_for(AM_HASH_TABLE_SIZE, key_hash);

    am_shm_lock(cache);

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

    cache_entry = am_shm_alloc(cache, sizeof (struct am_cache_entry));
    if (cache_entry == NULL) {
        AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes",
                thisfunc, sizeof (struct am_cache_entry));
        am_shm_unlock(cache);
        return AM_ENOMEM;
    }

    cache_entry->ts = time(NULL);
    cache_entry->valid = request->conf->pdp_cache_valid;
    cache_entry->instance_id = request->instance_id;
    strncpy(cache_entry->key, key, sizeof (cache_entry->key) - 1);

    cache_entry->data.next = cache_entry->data.prev = 0;
    cache_entry->lh.next = cache_entry->lh.prev = 0;
    AM_OFFSET_LIST_INSERT(cache->pool, cache_entry, &(cache_data->table[entry_index]), struct am_cache_entry);

    cache_entry_data = am_shm_alloc(cache, sizeof (struct am_cache_entry_data) +url_length + file_length + content_type_length + 3);
    if (cache_entry_data == NULL) {
        AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes",
                thisfunc, sizeof (struct am_cache_entry_data));
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

    AM_OFFSET_LIST_INSERT(cache->pool, cache_entry_data, &(cache_entry->data), struct am_cache_entry_data);

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

    if (cache == NULL || cache->user == NULL) {
        return AM_ENOMEM;
    }
    if (ISINVALID(key)) {
        return AM_EINVAL;
    }
    am_shm_lock(cache);

    cache_data = (struct am_cache *) cache->user;
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

    if (cache == NULL || cache->user == NULL) {
        return AM_ENOMEM;
    }
    if (ISINVALID(key)) {
        return AM_EINVAL;
    }

    cache_data = (struct am_cache *) cache->user;

    am_shm_lock(cache);

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
            strftime(tsc, sizeof (tsc), AM_CACHE_TIMEFORMAT, &created);
            strftime(tsu, sizeof (tsu), AM_CACHE_TIMEFORMAT, &until);
            AM_LOG_WARNING(request->instance_id, "%s data for a key (%s) is obsolete (created: %s, valid until: %s)",
                    thisfunc, key, tsc, tsu);

            /*if (!delete_cache_entry(entry_index, c)) {
                am_shm_free(cache, c);
                cache_data->count--;
            }
            am_shm_unlock(cache);
            return AM_ETIMEDOUT;*/

            *ets = cache_entry->ts;
        }
    }

    head = (struct am_cache_entry_data *) AM_GET_POINTER(cache->pool, cache_entry->data.prev);

    AM_OFFSET_LIST_FOR_EACH(cache->pool, head, a, tmp, struct am_cache_entry_data) {

        if (a->type == AM_CACHE_SESSION && a->size[0] > 0 && a->size[1] > 0) {
            struct am_namevalue *el = NULL;
            if (create_am_namevalue_node(a->value, a->size[0], a->value + a->size[0] + 1, a->size[1], &el) == 0) {
                AM_LIST_INSERT(sesion_attrs, el);
            }
        } else if ((a->type & AM_CACHE_POLICY) == AM_CACHE_POLICY) {

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

            if ((a->type & AM_CACHE_POLICY_RESPONSE_A) == AM_CACHE_POLICY_RESPONSE_A && a->size[0] > 0 && a->size[1] > 0) {
                struct am_namevalue *el = NULL;
                if (create_am_namevalue_node(a->value, a->size[0], a->value + a->size[0] + 1, a->size[1], &el) == 0) {
                    AM_LIST_INSERT(pol_curr->response_attributes, el);
                }
            }
            if ((a->type & AM_CACHE_POLICY_RESPONSE_D) == AM_CACHE_POLICY_RESPONSE_D && a->size[0] > 0 && a->size[1] > 0) {
                struct am_namevalue *el = NULL;
                if (create_am_namevalue_node(a->value, a->size[0], a->value + a->size[0] + 1, a->size[1], &el) == 0) {
                    AM_LIST_INSERT(pol_curr->response_decisions, el);
                }
            }
            if ((a->type & AM_CACHE_POLICY_ACTION) == AM_CACHE_POLICY_ACTION) {
                am_bool_t act;
                struct am_action_decision *el = NULL;
                act = TO_BOOL(a->type & AM_CACHE_POLICY_ALLOW);
                if (create_am_action_decision_node(act, a->method, a->ttl, &el) == 0) {
                    AM_LIST_INSERT(pol_curr->action_decisions, el);
                    action_curr = el;
                }
            }
            if ((a->type & AM_CACHE_POLICY_ADVICE) == AM_CACHE_POLICY_ADVICE && a->size[0] > 0 && a->size[1] > 0) {
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

    if (cache == NULL || cache->user == NULL) {
        return AM_ENOMEM;
    }
    if (ISINVALID(key) || (policy == NULL && session == NULL)) {
        return AM_EINVAL;
    }
    if (strlen(key) >= AM_HASH_TABLE_SIZE) {
        return AM_E2BIG;
    }

    cache_data = (struct am_cache *) cache->user;
    key_hash = hash(key);
    entry_index = index_for(AM_HASH_TABLE_SIZE, key_hash);

    am_shm_lock(cache);

    cache_entry = get_cache_entry(key, NULL);
    if (cache_entry != NULL) {
        if (!delete_cache_entry(entry_index, cache_entry)) {
            am_shm_free(cache, cache_entry);
            cache_data->count--;
            cache_entry = NULL;
        } else {
            AM_LOG_ERROR(request->instance_id, "%s failed to remove cache entry (%s)", thisfunc, key);
            am_shm_unlock(cache);
            return AM_ERROR;
        }
    }

    cache_entry = am_shm_alloc(cache, sizeof (struct am_cache_entry));
    if (cache_entry == NULL) {
        AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes", thisfunc, sizeof (struct am_cache_entry));
        am_shm_unlock(cache);
        return AM_ENOMEM;
    }

    /* maxcaching value is in minutes, timeleft in seconds */
    max_caching = get_ttl_value(session, "maxcaching", request->conf->token_cache_valid, AM_TRUE);
    time_left = get_ttl_value(session, "timeleft", request->conf->token_cache_valid, AM_FALSE);

    cache_entry->ts = time(NULL);
    cache_entry->valid = request->conf->token_cache_valid <= max_caching ?
            request->conf->token_cache_valid : (max_caching < time_left ? max_caching : time_left);
    cache_entry->instance_id = request->instance_id;
    strncpy(cache_entry->key, key, sizeof (cache_entry->key) - 1);

    cache_entry->data.next = cache_entry->data.prev = 0;
    cache_entry->lh.next = cache_entry->lh.prev = 0;

    AM_OFFSET_LIST_INSERT(cache->pool, cache_entry, &(cache_data->table[entry_index]), struct am_cache_entry);
    cache_data->count += 1;

    if (session != NULL) {
        struct am_namevalue *element, *tmp;

        AM_LIST_FOR_EACH(session, element, tmp) {
            struct am_cache_entry_data *mem = am_shm_alloc(cache,
                    sizeof (struct am_cache_entry_data)
                    +element->ns + element->vs + 2);
            if (mem == NULL) {
                AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes",
                        thisfunc, sizeof (struct am_cache_entry_data));
                am_shm_unlock(cache);
                return AM_ENOMEM;
            }
            mem->type = AM_CACHE_SESSION;
            mem->method = AM_REQUEST_UNKNOWN;
            mem->scope = mem->index = -1; /*not used in this context*/
            mem->ttl = cache_entry->ts + cache_entry->valid;

            mem->size[NAME_LENGTH] = element->ns;
            mem->size[VALUE_LENGTH] = element->vs;
            mem->size[NAME_VALUE_UNUSED] = 0;

            mem2cpy(mem->value, element->n, element->ns, element->v, element->vs);

            mem->lh.next = mem->lh.prev = 0;

            AM_OFFSET_LIST_INSERT(cache->pool, mem, &(cache_entry->data), struct am_cache_entry_data);
        }
    }

    if (policy != NULL) {
        struct am_policy_result *element, *tmp;

        struct am_namevalue *rae, *rat; // response attributes element, response attributes tmp
        struct am_namevalue *rde, *rdt; // response decisions element, responce decisions tmp
        struct am_action_decision *ae, *at; // action (decisions) element, action (decisions) tmp
        struct am_namevalue *aee, *att; // advices element?  advices tmp??

        AM_LIST_FOR_EACH(policy, element, tmp) {

            {
                /*add policy entry (per resource)*/
                size_t resource_len = strlen(element->resource);
                size_t mem_len = sizeof (struct am_cache_entry_data) +resource_len + 1;
                struct am_cache_entry_data *mem = am_shm_alloc(cache, mem_len);

                if (mem == NULL) {
                    AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes", thisfunc, mem_len);
                    am_shm_unlock(cache);
                    return AM_ENOMEM;
                }

                memset(mem, 0, mem_len);
                mem->type = AM_CACHE_POLICY;
                mem->method = AM_REQUEST_UNKNOWN;
                mem->scope = element->scope;
                mem->index = element->index;
                mem->ttl = cache_entry->ts + cache_entry->valid;

                mem->size[RESOURCE_LENGTH] = resource_len;

                strcpy(mem->value, element->resource);

                AM_OFFSET_LIST_INSERT(cache->pool, mem, &(cache_entry->data), struct am_cache_entry_data);
            }

            AM_LIST_FOR_EACH(element->response_attributes, rae, rat) {
                /*add response attributes*/

                size_t mem_len = sizeof (struct am_cache_entry_data) +rae->ns + rae->vs + 2;
                struct am_cache_entry_data *mem = am_shm_alloc(cache, mem_len);

                if (mem == NULL) {
                    AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes", thisfunc, mem_len);
                    am_shm_unlock(cache);
                    return AM_ENOMEM;
                }

                memset(mem, 0, mem_len);
                mem->type = AM_CACHE_POLICY | AM_CACHE_POLICY_RESPONSE_A;
                mem->method = AM_REQUEST_UNKNOWN;
                mem->scope = -1;
                mem->index = element->index;
                mem->ttl = cache_entry->ts + cache_entry->valid;

                mem->size[NAME_LENGTH] = rae->ns;
                mem->size[VALUE_LENGTH] = rae->vs;

                mem2cpy(mem->value, rae->n, rae->ns, rae->v, rae->vs);

                AM_OFFSET_LIST_INSERT(cache->pool, mem, &(cache_entry->data), struct am_cache_entry_data);
            }

            AM_LIST_FOR_EACH(element->action_decisions, ae, at) {

                {
                    /*add action decision*/
                    size_t mem_len = sizeof (struct am_cache_entry_data);
                    struct am_cache_entry_data *mem = am_shm_alloc(cache, mem_len);

                    if (mem == NULL) {
                        AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes", thisfunc, mem_len);
                        am_shm_unlock(cache);
                        return AM_ENOMEM;
                    }

                    memset(mem, 0, mem_len);
                    mem->type = AM_CACHE_POLICY | AM_CACHE_POLICY_ACTION;
                    if (ae->action) {
                        mem->type |= AM_CACHE_POLICY_ALLOW;
                    } else {
                        mem->type |= AM_CACHE_POLICY_DENY;
                    }
                    mem->method = ae->method;
                    mem->ttl = ae->ttl;
                    mem->scope = -1;
                    mem->index = element->index;

                    AM_OFFSET_LIST_INSERT(cache->pool, mem, &(cache_entry->data), struct am_cache_entry_data);
                }

                AM_LIST_FOR_EACH(ae->advices, aee, att) {
                    /*add advices*/
                    size_t mem_len = sizeof (struct am_cache_entry_data) +aee->ns + aee->vs + 2;
                    struct am_cache_entry_data *mem = am_shm_alloc(cache, mem_len);

                    if (mem == NULL) {
                        AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes", thisfunc, mem_len);
                        am_shm_unlock(cache);
                        return AM_ENOMEM;
                    }

                    memset(mem, 0, mem_len);
                    mem->type = AM_CACHE_POLICY | AM_CACHE_POLICY_ADVICE;
                    mem->method = AM_REQUEST_UNKNOWN;
                    mem->scope = -1;
                    mem->index = element->index;
                    mem->ttl = cache_entry->ts + cache_entry->valid;

                    mem->size[0] = aee->ns;
                    mem->size[1] = aee->vs;

                    mem2cpy(mem->value, aee->n, aee->ns, aee->v, aee->vs);

                    AM_OFFSET_LIST_INSERT(cache->pool, mem, &(cache_entry->data), struct am_cache_entry_data);
                }
            }

            AM_LIST_FOR_EACH(element->response_decisions, rde, rdt) {
                /*add response decisions (profile attributes)*/
                size_t mem_len = sizeof (struct am_cache_entry_data) +rde->ns + rde->vs + 2;
                struct am_cache_entry_data *mem = am_shm_alloc(cache, mem_len);

                if (mem == NULL) {
                    AM_LOG_ERROR(request->instance_id, "%s failed to allocate %ld bytes", thisfunc, mem_len);
                    am_shm_unlock(cache);
                    return AM_ENOMEM;
                }

                memset(mem, 0, mem_len);
                mem->type = AM_CACHE_POLICY | AM_CACHE_POLICY_RESPONSE_D;
                mem->method = AM_REQUEST_UNKNOWN;
                mem->scope = -1;
                mem->index = element->index;
                mem->ttl = cache_entry->ts + cache_entry->valid;

                mem->size[0] = rde->ns;
                mem->size[1] = rde->vs;

                mem2cpy(mem->value, rde->n, rde->ns, rde->v, rde->vs);

                AM_OFFSET_LIST_INSERT(cache->pool, mem, &(cache_entry->data), struct am_cache_entry_data);
            }
        }
    }

    am_shm_unlock(cache);
    return AM_SUCCESS;
}

/**
 * Fetch policy/resource cache entry (key: ResourceResult name).
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

    if (cache == NULL || cache->user == NULL) {
        return AM_ENOMEM;
    }
    if (ISINVALID(key)) {
        return AM_EINVAL;
    }
    am_shm_lock(cache);

    cache_data = (struct am_cache *) cache->user;
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
            localtime_r(&cache_entry->ts, &created);
            localtime_r(&ts, &until);
            strftime(tsc, sizeof (tsc), AM_CACHE_TIMEFORMAT, &created);
            strftime(tsu, sizeof (tsu), AM_CACHE_TIMEFORMAT, &until);
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

    if (reference > 0 && difftime(cache_entry->ts, reference) > 0) {
        localtime_r(&cache_entry->ts, &created);
        localtime_r(&reference, &until);
        strftime(tsc, sizeof (tsc), AM_CACHE_TIMEFORMAT, &created);
        strftime(tsu, sizeof (tsu), AM_CACHE_TIMEFORMAT, &until);
        AM_LOG_WARNING(request->instance_id, "%s data for a key (%s) is newer than reference data (created: %s, reference: %s)",
                thisfunc, key, tsc, tsu);
        am_shm_unlock(cache);
        return AM_ETIMEDOUT;
    }

    am_shm_unlock(cache);
    return AM_SUCCESS;
}

/**
 * Add policy/resource cache entry (key: ResourceResult name).
 * 
 * @return AM_SUCCESS if operation was successful
 */
int am_add_policy_cache_entry(am_request_t *r, const char *key, int valid) {
    static const char *thisfunc = "am_add_policy_cache_entry():";
    unsigned int key_hash;
    int entry_index = 0;
    struct am_cache_entry *cache_entry;
    struct am_cache *cache_data;

    if (cache == NULL || cache->user == NULL) {
        return AM_ENOMEM;
    }
    if (ISINVALID(key)) {
        return AM_EINVAL;
    }
    if (strlen(key) >= AM_HASH_TABLE_SIZE) {
        return AM_E2BIG;
    }

    cache_data = (struct am_cache *) cache->user;

    key_hash = hash(key);
    entry_index = index_for(AM_HASH_TABLE_SIZE, key_hash);

    am_shm_lock(cache);

    cache_entry = get_cache_entry(key, NULL);
    if (cache_entry != NULL) {
        if (!delete_cache_entry(entry_index, cache_entry)) {
            am_shm_free(cache, cache_entry);
            cache_data->count--;
            cache_entry = NULL;
        } else {
            AM_LOG_ERROR(r->instance_id, "%s failed to remove cache entry (%s)",
                    thisfunc, key);
            am_shm_unlock(cache);
            return 1;
        }
    }

    cache_entry = am_shm_alloc(cache, sizeof (struct am_cache_entry));
    if (cache_entry == NULL) {
        AM_LOG_ERROR(r->instance_id, "%s failed to allocate %ld bytes",
                thisfunc, sizeof (struct am_cache_entry));
        am_shm_unlock(cache);
        return AM_ENOMEM;
    }

    cache_entry->ts = time(NULL);
    cache_entry->valid = r->conf->policy_cache_valid > 0 &&
            r->conf->policy_cache_valid < valid ? r->conf->policy_cache_valid : valid;
    cache_entry->instance_id = r->instance_id;
    strncpy(cache_entry->key, key, sizeof (cache_entry->key) - 1);

    cache_entry->data.next = cache_entry->data.prev = 0;
    cache_entry->lh.next = cache_entry->lh.prev = 0;

    AM_OFFSET_LIST_INSERT(cache->pool, cache_entry, &(cache_data->table[entry_index]), struct am_cache_entry);
    cache_data->count++;

    am_shm_unlock(cache);
    return AM_SUCCESS;
}
