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
 * Copyright 2012 - 2015 ForgeRock AS.
 */

#include "platform.h"
#include "am.h"
#include "thread.h"
#include "utility.h"
#include "log.h"
#include "list.h"

#define MIN_URL_VALIDATOR_TICK 5 /* sec */

struct url_valid_table {
    unsigned long instance_id;
    int ok;
    int fail;
    int index;
    struct url_valid_table *next;
};

static am_timer_event_t *validator_timer = NULL;
static struct url_valid_table *table = NULL;
static am_mutex_t table_mutex;

int get_valid_url_all(struct url_validator_worker_data *list);
void set_valid_url_instance_running(unsigned long instance_id, int value);
void set_valid_url_index(unsigned long instance_id, int value);

static void delete_url_validation_table(struct url_valid_table **list) {
    struct url_valid_table *t = list != NULL ? *list : NULL;
    if (t != NULL) {
        delete_url_validation_table(&t->next);
        free(t);
        t = NULL;
    }
}

static void get_validation_table_entry(unsigned long instance_id,
        int index, int *ok, int *fail, int *default_ok) {
    struct url_valid_table *e, *t;

    AM_MUTEX_LOCK(&table_mutex);

    AM_LIST_FOR_EACH(table, e, t) {
        if (e->instance_id == instance_id && e->index == 0) {
            if (default_ok != NULL) *default_ok = e->ok;
        }
        if (e->instance_id == instance_id && e->index == index) {
            if (ok != NULL) *ok = e->ok;
            if (fail != NULL) *fail = e->fail;
            break;
        }
    }

    AM_MUTEX_UNLOCK(&table_mutex);
}

static void set_validation_table_entry(unsigned long instance_id, int index, int ok, int fail) {
    am_bool_t found = AM_FALSE;
    struct url_valid_table *e, *t;

    AM_MUTEX_LOCK(&table_mutex);

    AM_LIST_FOR_EACH(table, e, t) {
        if (e->instance_id == instance_id && e->index == index) {
            e->ok = ok;
            e->fail = fail;
            found = AM_TRUE;
            break;
        }
    }

    if (!found) {
        e = (struct url_valid_table *) malloc(sizeof (struct url_valid_table));
        if (e != NULL) {
            e->instance_id = instance_id;
            e->index = index;
            e->ok = ok;
            e->fail = fail;
            e->next = NULL;
            AM_LIST_INSERT(table, e);
        }
    }

    AM_MUTEX_UNLOCK(&table_mutex);
}

void url_validator_worker(
#ifdef _WIN32
        PTP_CALLBACK_INSTANCE
#else
        void *
#endif
        inst, void *arg) {
    static const char *thisfunc = "url_validator_worker():";
    struct url_validator_worker_data *w = (struct url_validator_worker_data *) arg;
    am_net_options_t net_options;
    int i, validate_status;
    am_config_t *conf = NULL;
    time_t current_ts;
    struct url_valid_table *e, *t;
    int current_index, current_ok, current_fail, default_ok, next_ok;
    char **url_list;
    int url_list_sz = 0;
    int ping_diff;

    set_valid_url_instance_running(w->instance_id, AM_TRUE);

    conf = am_get_config_file(w->instance_id, w->config_path);
    if (conf == NULL) {
        AM_LOG_WARNING(w->instance_id, "%s failed to get agent configuration (%s)",
                thisfunc, LOGEMPTY(w->config_path));
        set_valid_url_instance_running(w->instance_id, AM_FALSE);
        AM_FREE(w->config_path, w);
        return;
    }

    ping_diff = MAX(MIN_URL_VALIDATOR_TICK, conf->valid_ping);
    current_ts = time(NULL);
    /* this index corresponds to the naming.url multi-value index */
    current_index = w->url_index;

    if (conf->valid_level > 1 || conf->naming_url_sz < 2 || conf->naming_url_sz != conf->valid_default_url_sz ||
            (current_ts - w->last) < ping_diff) {
        /* a) validation is disabled; b) there is nothing to validate;
         * c) naming.url list and default.url list sizes do not match or
         * d) its not time yet to do any validation
         */
        am_config_free(&conf);
        set_valid_url_instance_running(w->instance_id, AM_FALSE);
        AM_FREE(w->config_path, w);
        return;
    }

    if (current_index < 0 || current_index >= conf->naming_url_sz) {
        AM_LOG_WARNING(w->instance_id,
                "%s invalid current index value, defaulting to %s", thisfunc, conf->naming_url[0]);
        set_valid_url_index(w->instance_id, 0);
        am_config_free(&conf);
        set_valid_url_instance_running(w->instance_id, AM_FALSE);
        AM_FREE(w->config_path, w);
        return;
    }

#define URL_LIST_FREE(l, s) do { \
        int k; \
        if (l == NULL) break; \
        for (k = 0; k < s; k++) { \
            am_free(l[k]); \
        }\
        free(l); \
    } while (0)

    url_list = (char **) calloc(1, conf->naming_url_sz * sizeof (char *));
    if (url_list == NULL) {
        AM_LOG_ERROR(w->instance_id, "%s memory allocation error", thisfunc);
        am_config_free(&conf);
        set_valid_url_instance_running(w->instance_id, AM_FALSE);
        AM_FREE(w->config_path, w);
        return;
    }
    url_list_sz = conf->naming_url_sz;

    for (i = 0; i < url_list_sz; i++) {
        /* default.url.set contains fail-over order;
         * will keep internal value list index-ordered 
         **/
        int j = conf->valid_default_url[i];
        url_list[i] = strdup(conf->naming_url[j]);
        if (url_list[i] == NULL) {
            URL_LIST_FREE(url_list, url_list_sz);
            am_config_free(&conf);
            set_valid_url_instance_running(w->instance_id, AM_FALSE);
            AM_FREE(w->config_path, w);
            return;
        }
    }

    am_net_options_create(conf, &net_options, NULL);
    net_options.keepalive = AM_FALSE;
    net_options.local = net_options.cert_trust = AM_TRUE;
    net_options.net_timeout = 2; /* fixed for url validator; in sec */

    /* do the actual url validation */

    for (i = 0; i < url_list_sz; i++) {
        const char *url = url_list[i];
        int ok = 0, fail = 0, httpcode = 0;

        get_validation_table_entry(w->instance_id, i, &ok, &fail, NULL);

        AM_LOG_DEBUG(w->instance_id, "%s validating %s", thisfunc, url);

        if (conf->valid_level == 1) {
            /* simple HEAD request */
            validate_status = am_url_validate(w->instance_id, url, &net_options, &httpcode);
        } else {
            /* full scale agent login-logout request */
            char *agent_token = NULL;
            validate_status = am_agent_login(w->instance_id, url, conf->user, conf->pass, conf->realm,
                    &net_options, &agent_token, NULL, NULL, NULL);
            if (agent_token != NULL) {
                am_agent_logout(0, url, agent_token, &net_options);
                free(agent_token);
                httpcode = 200;
            }
        }

        if (validate_status == AM_SUCCESS && httpcode != 0) {
            if (ok++ > conf->valid_ping_ok) {
                ok = conf->valid_ping_ok;
            }
            fail = 0;
        } else {
            if (fail++ > conf->valid_ping_miss) {
                fail = conf->valid_ping_miss;
            }
            ok = 0;
        }

        set_validation_table_entry(w->instance_id, i, ok, fail);
    }

    /* map stored index value to our ordered list index */
    for (i = 0; i < conf->valid_default_url_sz; i++) {
        if (current_index == conf->valid_default_url[i]) {
            current_index = i;
            break;
        }
    }

    default_ok = current_ok = current_fail = 0;
    /* fetch validation table entry for the current_index 
     * (which now corresponds to the default.url.set value/index) */
    get_validation_table_entry(w->instance_id, current_index, &current_ok, &current_fail, &default_ok);

    /* do the fail-over logic */
    do {
        if (current_ok > 0) {
            if (current_index > 0 && default_ok >= conf->valid_ping_ok) {
                set_valid_url_index(w->instance_id, conf->valid_default_url[0]);
                AM_LOG_INFO(w->instance_id, "%s fail-back to %s", thisfunc, url_list[0]);
            } else {
                set_valid_url_index(w->instance_id, conf->valid_default_url[current_index]);
                AM_LOG_INFO(w->instance_id, "%s continue with %s", thisfunc, url_list[current_index]);
            }
            break;
        }

        /* current index is not valid; check ping.miss.count */
        if (current_ok == 0 && current_fail <= conf->valid_ping_miss) {
            set_valid_url_index(w->instance_id, conf->valid_default_url[current_index]);
            AM_LOG_INFO(w->instance_id, "%s still staying with %s", thisfunc, url_list[current_index]);
            break;
        }

        /* find next valid index value to fail-over to */
        next_ok = 0;
        AM_MUTEX_LOCK(&table_mutex);

        AM_LIST_FOR_EACH(table, e, t) {
            if (e->instance_id == w->instance_id && e->index == 0) {
                default_ok = e->ok;
            }
            if (e->instance_id == w->instance_id && e->ok > 0) {
                next_ok = e->ok;
                i = e->index;
                break;
            }
        }

        AM_MUTEX_UNLOCK(&table_mutex);

        if (next_ok == 0) {
            AM_LOG_WARNING(w->instance_id,
                    "%s none of the values are valid, defaulting to %s", thisfunc, url_list[0]);
            set_valid_url_index(w->instance_id, conf->valid_default_url[0]);
            break;
        }

        if (current_index > 0 && default_ok >= conf->valid_ping_ok) {
            AM_LOG_INFO(w->instance_id, "%s fail-back to %s", thisfunc, url_list[0]);
            set_valid_url_index(w->instance_id, conf->valid_default_url[0]);
            break;
        }

        AM_LOG_INFO(w->instance_id, "%s fail-over to %s", thisfunc, url_list[i]);
        set_valid_url_index(w->instance_id, conf->valid_default_url[i]);

    } while (0);

    am_net_options_delete(&net_options);
    am_config_free(&conf);
    set_valid_url_instance_running(w->instance_id, AM_FALSE);
    AM_FREE(w->config_path, w);
    URL_LIST_FREE(url_list, url_list_sz);
}

static void am_url_validator_tick(void *arg) {
    static const char *thisfunc = "am_url_validator_tick():";
    int i;
    struct url_validator_worker_data *list;

    list = (struct url_validator_worker_data *) calloc(1,
            sizeof (struct url_validator_worker_data) * AM_MAX_INSTANCES);
    if (list == NULL || get_valid_url_all(list) != AM_SUCCESS) {
        am_free(list);
        return;
    }

    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        /* schedule a new url_validator_worker only when instance is registered and validator is not running already */
        if (list[i].instance_id > 0 && !list[i].running) {
            struct url_validator_worker_data *worker_data =
                    (struct url_validator_worker_data *) malloc(sizeof (struct url_validator_worker_data));
            if (worker_data != NULL) {
                worker_data->instance_id = list[i].instance_id;
                worker_data->url_index = list[i].url_index;
                worker_data->last = list[i].last;
                worker_data->config_path = strdup(list[i].config_path);
                if (am_worker_dispatch(url_validator_worker, worker_data) != AM_SUCCESS) {
                    AM_LOG_WARNING(list[i].instance_id, "%s failed to dispatch url validator worker", thisfunc);
                    AM_FREE(worker_data->config_path, worker_data);
                }
            } else {
                AM_LOG_ERROR(list[i].instance_id, "%s memory allocation error", thisfunc);
            }
        }
        am_free(list[i].config_path);
    }
    free(list);
}

int am_url_validator_init() {
    if (validator_timer != NULL) {
        return AM_SUCCESS;
    }

    AM_MUTEX_INIT(&table_mutex);

    validator_timer = am_create_timer_event(AM_TIMER_EVENT_RECURRING,
            MIN_URL_VALIDATOR_TICK, NULL, am_url_validator_tick);
    if (validator_timer == NULL) {
        return AM_ENOMEM;
    }

    if (validator_timer->error != 0) {
        return AM_ERROR;
    }

    am_start_timer_event(validator_timer);

    return AM_SUCCESS;
}

void am_url_validator_shutdown() {
    am_close_timer_event(validator_timer);
    AM_MUTEX_DESTROY(&table_mutex);
    delete_url_validation_table(&table);
    table = NULL;
    validator_timer = NULL;
}
