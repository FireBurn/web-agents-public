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
 * Copyright 2015 ForgeRock AS.
 */

#include "platform.h"
#include "am.h"
#include "utility.h"
#include "list.h"
#include "thread.h"
#include "net_client.h"

#define BATCH_SIZE 25
#define DEFAULT_RUN_INTERVAL 5 /* minutes */

#define AUDIT_ENTRY_LINKS(offset) (&((struct am_audit_entry *) AM_GET_POINTER(audit_shm->pool, (offset)))->lh)

#define OFFSET_LIST_APPEND(hdr, links, offset) do {\
    if ((hdr)->last) {\
        links((hdr)->last)->next = offset;\
        links(offset)->prev = (hdr)->last;\
    } else {\
        (hdr)->first = offset;\
    }\
    (hdr)->last = offset;\
} while (0)

#define OFFSET_LIST_UNLINK(hdr, links, offset) do {\
    if (links(offset)->next) {\
        links(links(offset)->next)->prev = links(offset)->prev;\
    } else {\
        (hdr)->last = links(offset)->prev;\
    }\
    if (links(offset)->prev) {\
        links(links(offset)->prev)->next = links(offset)->next;\
    } else {\
        (hdr)->first = links(offset)->next;\
    }\
} while (0)

#define AM_OFFSET_LIST_FOR_EACH_OFFSET(base, header, e, offset) \
    for (offset = (header)->first; (e = AM_GET_POINTER((base), offset), offset); \
        offset = e->lh.next)

struct offset_list_hdr {
    unsigned int first, last;
};

struct am_audit {
    struct am_audit_config {
        unsigned long instance_id;
        int interval;
        int last;
        struct offset_list_hdr list_hdr;
        char config_file[AM_PATH_SIZE];
        char openam[AM_URI_SIZE];
    } config[AM_MAX_INSTANCES];
};

struct am_audit_entry {
    unsigned long instance_id;
    struct offset_list lh;
    char server_id[12];
    char value[1];
};

struct am_audit_transfer {
    unsigned long instance_id;
    char *message;
    char *server_id;
    char *config_file;
};

static am_timer_event_t *audit_timer = NULL;
static am_shm_t *audit_shm = NULL;

static const char *AUDIT_REQ_MSG = "<Request><![CDATA[<logRecWrite reqid=\"%%d\"><log logName=\"%s\" sid=\"%s\">"
        "</log><logRecord><level>800</level><recMsg>%s</recMsg><logInfoMap><logInfo><infoKey>LoginIDSid</infoKey>"
        "<infoValue>%s</infoValue></logInfo></logInfoMap></logRecord></logRecWrite>]]></Request>%%s";

int am_audit_init(int id) {
    if (audit_shm != NULL) return AM_SUCCESS;

    audit_shm = am_shm_create(get_global_name(AM_AUDIT_SHM_NAME, id),
            sizeof (struct am_audit) + ((sizeof (struct am_audit_entry) + 800 /* an average logRecWrite entry size */) * 2048));
    if (audit_shm == NULL) {
        return AM_ERROR;
    }
    if (audit_shm->error != AM_SUCCESS) {
        return audit_shm->error;
    }

    if (audit_shm->init) {
        struct am_audit *audit_data = (struct am_audit *) am_shm_alloc(audit_shm, sizeof (struct am_audit));
        if (audit_data == NULL) {
            return AM_ENOMEM;
        }
        am_shm_lock(audit_shm);
        memset(audit_data->config, 0, sizeof (audit_data->config));
        /* store table offset (for other processes) */
        am_shm_set_user_offset(audit_shm, AM_GET_OFFSET(audit_shm->pool, audit_data));
        am_shm_unlock(audit_shm);
    }

    return AM_SUCCESS;
}

int am_audit_shutdown() {
    am_shm_shutdown(audit_shm);
    audit_shm = NULL;
    return AM_SUCCESS;
}

static struct am_audit *get_audit_data() {
    return (struct am_audit *) am_shm_get_user_pointer(audit_shm);
}

static struct am_audit_config *get_audit_config(unsigned long instance_id) {
    int i;
    struct am_audit *audit = get_audit_data();
    if (audit != NULL) {
        for (i = 0; i < AM_MAX_INSTANCES; i++) {
            if (audit->config[i].instance_id == instance_id)
                return &audit->config[i];
        }
    }
    return NULL;
}

static am_status_t add_audit_entry(struct am_audit_config *config, unsigned long instance_id,
        const char *server_id, const char *message, size_t size) {
    int offset;
    struct am_audit_entry *audit_entry;

    audit_entry = am_shm_alloc(audit_shm, sizeof (struct am_audit_entry) +size + 1);
    if (audit_entry == NULL) {
        return AM_ENOMEM;
    }

    if (ISVALID(server_id)) {
        strncpy(audit_entry->server_id, server_id, sizeof (audit_entry->server_id) - 1);
    } else {
        memset(audit_entry->server_id, 0, sizeof (audit_entry->server_id));
    }
    memcpy(audit_entry->value, message, size);
    audit_entry->value[size] = '\0';
    audit_entry->instance_id = instance_id;

    audit_entry->lh.next = audit_entry->lh.prev = 0;

    offset = AM_GET_OFFSET(audit_shm->pool, audit_entry);
    OFFSET_LIST_APPEND(&config->list_hdr, AUDIT_ENTRY_LINKS, offset);
    return AM_SUCCESS;
}

int am_add_remote_audit_entry(unsigned long instance_id, const char *agent_token,
        const char *agent_token_server_id, const char *file_name,
        const char *user_token, const char *format, ...) {
    va_list args;
    size_t size;
    int msg_size;
    am_status_t status;
    struct am_audit_config *config;
    char *tmp = NULL, *message = NULL, *message_b64 = NULL;

    if (!instance_id || ISINVALID(agent_token) || ISINVALID(user_token) ||
            ISINVALID(file_name) || ISINVALID(format)) {
        return AM_EINVAL;
    }

    va_start(args, format);
    msg_size = am_vasprintf(&tmp, format, args);
    va_end(args);

    if (msg_size <= 0 || tmp == NULL) {
        am_free(tmp);
        return AM_ENOMEM;
    }

    size = msg_size;
    message_b64 = base64_encode(tmp, &size);
    if (message_b64 == NULL) {
        am_free(tmp);
        return AM_ENOMEM;
    }

    msg_size = am_asprintf(&message, AUDIT_REQ_MSG, file_name, agent_token, message_b64, user_token);
    if (msg_size <= 0 || message == NULL) {
        AM_FREE(tmp, message, message_b64);
        return AM_ENOMEM;
    }
    size = msg_size;

    status = am_shm_lock(audit_shm);
    if (status != AM_SUCCESS) {
        AM_FREE(tmp, message, message_b64);
        return status;
    }

    config = get_audit_config(instance_id);
    if (config == NULL) {
        status = AM_EINVAL;
    } else {
        status = add_audit_entry(config, instance_id, agent_token_server_id, message, size);
    }
    am_shm_unlock(audit_shm);
    AM_FREE(tmp, message, message_b64);
    return status;
}

static am_status_t extract_audit_entries(unsigned long instance_id,
        am_status_t(*callback)(const char *openam, int count, struct am_audit_transfer *batch)) {
    static const char *thisfunc = "extract_audit_entries():";
    am_status_t status;
    struct am_audit_entry *e;
    int offset;
    struct am_audit_config *config;
    int i, c = 0;
    struct am_audit_transfer *batch;

    batch = malloc(BATCH_SIZE * sizeof (struct am_audit_transfer));
    if (batch == NULL) {
        return AM_ENOMEM;
    }

    status = am_shm_lock(audit_shm);
    if (status != AM_SUCCESS)
        AM_FREE(batch);
        return status;

    config = get_audit_config(instance_id);
    if (config == NULL) {
        AM_FREE(batch);
        am_shm_unlock(audit_shm);
        return AM_EINVAL;
    }

    AM_OFFSET_LIST_FOR_EACH_OFFSET(audit_shm->pool, &config->list_hdr, e, offset) {
        batch[c].message = strdup(e->value);
        batch[c].instance_id = e->instance_id;
        batch[c].server_id = strdup(e->server_id);
        batch[c].config_file = strdup(config->config_file);

        c++;

        if (c == BATCH_SIZE) {
            AM_LOG_DEBUG(instance_id, "%s sending %d audit log messages to %s", thisfunc, c, config->openam);
            callback(config->openam, c, batch);
            for (i = 0; i < c; i++) {
                AM_FREE(batch[i].message, batch[i].server_id, batch[i].config_file);
            }
            c = 0;
        }

        OFFSET_LIST_UNLINK(&config->list_hdr, AUDIT_ENTRY_LINKS, offset);
        am_shm_free(audit_shm, e);
    }

    if (c) {
        AM_LOG_DEBUG(instance_id, "%s sending %d audit log messages to %s", thisfunc, c, config->openam);
        callback(config->openam, c, batch);
        for (i = 0; i < c; i++) {
            AM_FREE(batch[i].message, batch[i].server_id, batch[i].config_file);
        }
    }

    am_shm_unlock(audit_shm);

    AM_FREE(batch);
    return status;
}

static am_status_t write_entries_to_server(const char *openam, int count, struct am_audit_transfer *batch) {
    static const char *thisfunc = "write_entries_to_server():";
    int i, msg_size;
    struct audit_worker_data *wd;
    char *server_id = NULL, *msg = NULL, *config_file = NULL;
    unsigned long instance_id;

    if (count == 0 || batch == NULL || ISINVALID(openam)) {
        return AM_EINVAL;
    }

    wd = malloc(sizeof (struct audit_worker_data));
    if (wd == NULL) {
        return AM_ENOMEM;
    }

    for (i = 0; i < count; i++) {
        if (msg == NULL) {
            server_id = batch[i].server_id;
            instance_id = batch[i].instance_id;
            config_file = batch[i].config_file;
            msg_size = am_asprintf(&msg, batch[i].message, i + 1, "");
        } else {
            msg_size = am_asprintf(&msg, batch[i].message, i + 1, msg);
        }
        if (msg_size <= 0 || msg == NULL) {
            AM_FREE(wd, msg);
            return AM_ENOMEM;
        }
    }

    wd->instance_id = instance_id;
    wd->openam = strdup(openam);
    wd->logdata = msg;
    wd->options = malloc(sizeof (am_net_options_t));
    if (wd->options != NULL) {
        am_config_t *conf = NULL;
        if (am_get_agent_config(instance_id, config_file, &conf) == AM_SUCCESS) {
            am_net_options_create(conf, wd->options, NULL);
        }
        wd->options->server_id = strdup(server_id);
        am_config_free(&conf);
    }

    if (am_worker_dispatch(remote_audit_worker, wd) != 0) {
        AM_LOG_WARNING(instance_id, "%s failed to dispatch remote audit_shm log worker", thisfunc);
        am_net_options_delete(wd->options);
        AM_FREE(wd->openam, wd->logdata, wd->options, wd);
        return AM_ERROR;
    }
    return AM_SUCCESS;
}

static void am_audit_tick(void *arg) {
    static const char *thisfunc = "am_audit_tick():";
    int i;
    struct am_audit *audit_data;
    int lock_status, status;

    lock_status = am_shm_lock(audit_shm);
    if (lock_status != AM_SUCCESS) {
        return;
    }

    audit_data = get_audit_data();
    if (audit_data == NULL) {
        am_shm_unlock(audit_shm);
        return;
    }

    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        if (audit_data->config[i].instance_id > 0 &&
                (audit_data->config[i].interval == 1 ||
                audit_data->config[i].interval == ++(audit_data->config[i].last))) {
            /* reset run-count for this instance */
            audit_data->config[i].last = 0;

            status = extract_audit_entries(audit_data->config[i].instance_id, write_entries_to_server);
            if (status != AM_SUCCESS) {
                AM_LOG_WARNING(audit_data->config[i].instance_id,
                        "%s failed to extract audit entries (%s)", thisfunc, am_strerror(status));
            }
        }
    }

    am_shm_unlock(audit_shm);
}

int am_audit_processor_init() {
    if (audit_timer != NULL) {
        return AM_SUCCESS;
    }
    audit_timer = am_create_timer_event(AM_TIMER_EVENT_RECURRING, 60, NULL, am_audit_tick);
    if (audit_timer == NULL) {
        return AM_ENOMEM;
    }
    if (audit_timer->error != 0) {
        return AM_ERROR;
    }
    am_start_timer_event(audit_timer);
    return AM_SUCCESS;
}

void am_audit_processor_shutdown() {
    am_close_timer_event(audit_timer);
    audit_timer = NULL;
}

int am_audit_register_instance(am_config_t *conf) {
    int i;
    struct am_audit *audit_data;
    int lock_status;
    am_request_t req;
    const char *openam;

    lock_status = am_shm_lock(audit_shm);
    if (lock_status != AM_SUCCESS) {
        return lock_status;
    }

    audit_data = get_audit_data();
    if (audit_data == NULL) {
        am_shm_unlock(audit_shm);
        return AM_ENOMEM;
    }

    memset(&req, 0, sizeof (am_request_t));
    req.instance_id = conf->instance_id;
    req.conf = conf;
    openam = get_valid_openam_url(&req);

    /* update existing instance configuration */
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        if (audit_data->config[i].instance_id == conf->instance_id) {
            audit_data->config[i].interval = conf->audit_remote_interval <= 0 ?
                    DEFAULT_RUN_INTERVAL : conf->audit_remote_interval;
            strncpy(audit_data->config[i].config_file, conf->config, sizeof (audit_data->config[i].config_file) - 1);
            strncpy(audit_data->config[i].openam, openam, sizeof (audit_data->config[i].openam) - 1);
            am_shm_unlock(audit_shm);
            return AM_SUCCESS;
        }
    }
    /* create instance configuration */
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        if (audit_data->config[i].instance_id == 0) {
            audit_data->config[i].instance_id = conf->instance_id;
            audit_data->config[i].interval = conf->audit_remote_interval <= 0 ?
                    DEFAULT_RUN_INTERVAL : conf->audit_remote_interval;
            audit_data->config[i].last = 0;
            strncpy(audit_data->config[i].config_file, conf->config, sizeof (audit_data->config[i].config_file) - 1);
            strncpy(audit_data->config[i].openam, openam, sizeof (audit_data->config[i].openam) - 1);
            break;
        }
    }

    am_shm_unlock(audit_shm);
    return AM_SUCCESS;
}
