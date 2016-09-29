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
#include "net_client.h"
#include "utility.h"

/*
 * Initialising the agent:
 *
 * On Unix, where fork is used by the webserver to spawn a new child (worker) process, there is a
 * main-process-init and a child-process init. Whereas on windows there is no main process (fork is not
 * available) - all processes are equal and must be dealt with appropriately. Thus the difference in
 * init calls to get agent bootstrapped in different environments, i.e. for unix (and it's variants) we
 * call this function am_init.  For Windows, call am_init_worker.
 */
int am_init(int id) {
    int rv = AM_SUCCESS;
#ifndef _WIN32
    am_net_init();
    am_worker_pool_init_main();
    am_log_init(id);
    am_configuration_init(id);
    am_audit_init(id);
    am_audit_processor_init();
    am_url_validator_init();
    rv = am_cache_init(id);
    am_cache_worker_init();
#endif
    return rv;
}

int am_init_worker(int id) {
    int rv = AM_SUCCESS;
#ifdef _WIN32
    am_net_init();
    am_worker_pool_init();
    am_log_init(id);
    am_configuration_init(id);
    am_audit_init(id);
    rv = am_cache_init(id);
    am_cache_worker_init();
#else
    am_worker_pool_init();
#endif
    return rv;
}

int am_shutdown(int id) {
    am_url_validator_shutdown();
    am_audit_processor_shutdown();
    am_audit_shutdown();
#ifdef _WIN32
    am_worker_pool_shutdown();
#else
    am_worker_pool_shutdown_main();
#endif
    am_cache_worker_shutdown();
    am_cache_shutdown();
    am_configuration_shutdown();
    am_log_shutdown(id);
    am_net_shutdown();
    return 0;
}

void am_restart_workers() {
#ifdef _WIN32
    am_cache_worker_shutdown();
    am_audit_processor_init();
    am_url_validator_init();
#endif
}

int am_shutdown_worker() {
    am_worker_pool_shutdown();
    return 0;
}

/*
 * Remove all shared memory and semaphore resources that might be left open if the agent terminates
 * abnormally
 */
am_status_t am_remove_shm_and_locks(int id, void (*log_cb)(void *arg, char *name, int error), void *cb_arg) {
    int status;
    int errors = 0;

    if (am_cache_cleanup(id)) {
        errors++;
    }

    status = am_shm_delete(get_global_name(AM_AUDIT_SHM_NAME, id));
    if (status) {
        log_cb(cb_arg, AM_AUDIT_SHM_NAME, status);
        errors++;
    }

    status = am_shm_delete(get_global_name(AM_CONFIG_SHM_NAME, id));
    if (status) {
        log_cb(cb_arg, AM_CONFIG_SHM_NAME, status);
        errors++;
    }

    status = am_shm_delete(get_global_name(AM_LOG_SHM_NAME, id));
    if (status) {
        log_cb(cb_arg, AM_LOG_SHM_NAME, status);
        errors++;
    }

    return errors ? AM_ERROR : AM_SUCCESS;
}
