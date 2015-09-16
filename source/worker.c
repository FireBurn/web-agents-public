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

void notification_worker(
#ifdef _WIN32
        PTP_CALLBACK_INSTANCE
#else
        void *
#endif
        inst, void *arg) {
    static const char *thisfunc = "notification_worker():";
    struct notification_worker_data *r = (struct notification_worker_data *) arg;
    struct am_namevalue *e, *t, *session_list;
    char *token = NULL, destroyed = 0;
    am_bool_t policy_change_run = AM_FALSE;
    char *agentid = NULL;

    if (r == NULL) return;
    if (r->post_data == NULL || r->post_data_sz == 0) {
        AM_LOG_WARNING(r->instance_id, "%s post data is not available", thisfunc);
        am_free(r->post_data);
        free(r);
        return;
    }

    session_list = am_parse_session_xml(r->instance_id, r->post_data, r->post_data_sz);

    AM_LIST_FOR_EACH(session_list, e, t) {
        /* SessionNotification */
        if (strcmp(e->n, "sid") == 0) {
            token = e->v;
        }
        if (strcmp(e->n, "state") == 0 && strcmp(e->v, "destroyed") == 0) {
            destroyed = 1;
        }
        if (strcmp(e->n, "agentName") == 0) {
            agentid = e->v;
        }
        /* PolicyChangeNotification - ResourceName */
        if (!policy_change_run && strcmp(e->n, "ResourceName") == 0) {
            am_request_t req;
            int rv;
            memset(&req, 0, sizeof (am_request_t));
            req.instance_id = r->instance_id;
            rv = am_add_policy_cache_entry(&req, AM_POLICY_CHANGE_KEY, 0);
            AM_LOG_DEBUG(r->instance_id, "%s policy change cache update status: %s",
                    thisfunc, am_strerror(rv));
            policy_change_run = AM_TRUE; /* one AM_POLICY_CHANGE_KEY update per PolicyChangeNotification is enough */
        }
    }

    if (ISVALID(token) && destroyed) {
        am_remove_cache_entry(r->instance_id, token);
    }

    if (ISVALID(agentid)) {
        AM_LOG_DEBUG(r->instance_id, "%s agent configuration entry removed (%s)",
                thisfunc, agentid);
        remove_agent_instance_byname(agentid);
    }

    delete_am_namevalue_list(&session_list);

    am_free(r->post_data);
    free(r);
}

void session_logout_worker(
#ifdef _WIN32
        PTP_CALLBACK_INSTANCE
#else
        void *
#endif
        inst, void *arg) {
    struct logout_worker_data *r = (struct logout_worker_data *) arg;
    int status = am_agent_logout(r->instance_id, r->openam, r->token, r->options);
    if (status == AM_SUCCESS) {
        am_remove_cache_entry(r->instance_id, r->token);
    }
    am_net_options_delete(r->options);
    AM_FREE(r->openam, r->token, r->options, r);
}

void remote_audit_worker(
#ifdef _WIN32
        PTP_CALLBACK_INSTANCE
#else
        void *
#endif
        inst, void *arg) {
    struct audit_worker_data *r = (struct audit_worker_data *) arg;
    am_agent_audit_request(r->instance_id, r->openam, r->logdata, r->options);
    am_net_options_delete(r->options);
    AM_FREE(r->openam, r->logdata, r->options, r);
}
