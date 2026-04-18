// SPDX-License-Identifier: CDDL-1.0
//
// Copyright 2014-2016 ForgeRock AS.
// Copyright 2018-2026 Open Identity Platform Community.

#include "am.h"
#include "list.h"
#include "platform.h"
#include "utility.h"

void notification_worker(void *arg) {
    static const char *thisfunc = "notification_worker():";
    struct notification_worker_data *r = (struct notification_worker_data *)arg;
    struct am_namevalue *e, *t, *session_list;
    char *token = NULL, *agentid = NULL, *temp;
    am_bool_t destroyed = AM_FALSE, policy_change_run = AM_FALSE;
    size_t temp_sz = 0;

    if (r == NULL)
        return;
    if (r->post_data == NULL || r->post_data_sz == 0) {
        AM_LOG_WARNING(r->instance_id, "%s post data is not available", thisfunc);
        AM_FREE(r->post_data, r);
        return;
    }

    temp = load_file(r->post_data, &temp_sz);
    if (temp == NULL) {
        AM_LOG_WARNING(r->instance_id, "%s failed to load post data from %s", thisfunc, r->post_data);
        AM_FREE(r->post_data, r);
        return;
    }
    session_list = am_parse_session_xml(r->instance_id, temp, temp_sz);

    AM_LIST_FOR_EACH(session_list, e, t) {
        /* SessionNotification */
        if (strcmp(e->n, "sid") == 0) {
            token = e->v;
        }
        if (strcmp(e->n, "state") == 0 && (strcmp(e->v, "destroyed") == 0 || strcmp(e->v, "valid") == 0)) {
            /* state = destroyed:
             *  agent will remove token from its cache;
             * state = valid:
             *  agent will also remove token from its cache, but just to let
             *  it to be refreshed with the next call to SessionService
             */
            destroyed = AM_TRUE;
        }
        if (strcmp(e->n, "agentName") == 0) {
            agentid = e->v;
        }
        /* PolicyChangeNotification - ResourceName */
        if (!policy_change_run && strcmp(e->n, "ResourceName") == 0) {
            int rv;
            rv = am_set_policy_cache_epoch(time(0));
            AM_LOG_DEBUG(r->instance_id, "%s policy change cache update status: %s", thisfunc, am_strerror(rv));
            policy_change_run = AM_TRUE; /* one AM_POLICY_CHANGE_KEY update per PolicyChangeNotification is enough */
        }
    }

    if (ISVALID(token) && destroyed) {
        am_remove_cache_entry(r->instance_id, token);
    }

    if (ISVALID(agentid)) {
        AM_LOG_DEBUG(r->instance_id, "%s agent configuration entry removed (%s)", thisfunc, agentid);
        remove_agent_instance_byname(agentid);
    }

    delete_am_namevalue_list(&session_list);
    am_delete_file(r->post_data);
    AM_FREE(r->post_data, temp, r);
}

void session_logout_worker(void *arg) {
    struct logout_worker_data *r = (struct logout_worker_data *)arg;
    int status = am_agent_logout(r->instance_id, r->openam, r->token, r->options);
    if (status == AM_SUCCESS) {
        am_remove_cache_entry(r->instance_id, r->token);
    }
    am_net_options_delete(r->options);
    AM_FREE(r->openam, r->token, r->options, r);
}

void remote_audit_worker(void *arg) {
    struct audit_worker_data *r = (struct audit_worker_data *)arg;
    am_agent_audit_request(r->instance_id, r->openam, r->logdata, r->options);
    am_net_options_delete(r->options);
    AM_FREE(r->openam, r->logdata, r->options, r);
}
