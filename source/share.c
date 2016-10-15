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
#include "error.h"
#include "share.h"

/*
 * map entire shared memory into virtual memory
 *
 * the callback (cb) is called when the block is first opened and it is for initialization of the block
 *
 */
int get_memory_segment(am_shm_t **p_addr, char *name, size_t sz,
        void (*cb)(void *cbdata, void *p), void *cbdata, int id) {
    static const char *thisfunc = "get_memory_segment():";
    uint64_t size_limit = 0;

    if (p_addr == NULL) {
        return AM_FAIL;
    }

    *p_addr = am_shm_create(get_global_name(name, id), (uint64_t) sz, AM_TRUE, &size_limit);
    if (*p_addr == NULL) {
        AM_LOG_ERROR(0, "%s shared memory error: %s\n", thisfunc, name);
        return AM_ERROR;
    }
    if ((*p_addr)->error != AM_SUCCESS) {
        AM_LOG_ERROR(0, "%s shared memory error %d: %s\n", thisfunc, (*p_addr)->error, name);
        return (*p_addr)->error;
    }
    if ((*p_addr)->init) {
        if (size_limit > 0) {
            AM_LOG_DEBUG(0, "%s shared memory '%s' segment size limited to %"PR_L64" bytes\n",
                    thisfunc, name, size_limit);
        }
        if (cbdata != NULL) {
            cluster_limit_t *limit = (cluster_limit_t *) cbdata;
            limit->size_limit = size_limit;
        }
        cb(cbdata, (*p_addr)->base_ptr);
    }

    return AM_SUCCESS;
}

/*
 * unmap and optionally unlink a shared memory segment
 *
 */
int remove_memory_segment(am_shm_t **p_addr, int destroy) {

    if (p_addr == NULL) {
        return AM_FAIL;
    }
    if (destroy)
        am_shm_destroy(*p_addr);
    else
        am_shm_shutdown(*p_addr);

    *p_addr = NULL;
    return AM_SUCCESS;
}

/*
 * delete memory segment
 *
 */
int delete_memory_segment(const char *name, int id) {
    static const char *thisfunc = "delete_memory_segment():";

    int status = am_shm_delete(get_global_name(name, id));

    if (status == AM_NOT_FOUND) {
        status = AM_SUCCESS;
    } else if (status) {
        AM_LOG_ERROR(0, "%s error deleting shared memory: %s\n", thisfunc, name);
    }

    return status;
}

