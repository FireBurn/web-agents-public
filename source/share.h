// SPDX-License-Identifier: CDDL-1.0
//
// Copyright 2014-2016 ForgeRock AS.
// Copyright 2018-2026 Open Identity Platform Community.

#ifndef SHM_INCLUDED
#define SHM_INCLUDED
#include "platform.h"
#include "utility.h"

typedef struct {
    uint64_t size_limit;
    uint32_t orig_size;
} cluster_limit_t;

int get_memory_segment(am_shm_t **p_addr, char *name, size_t sz, void (*cb)(void *cbdata, void *p), void *cbdata,
                       int id);
int remove_memory_segment(am_shm_t **p_addr, int destroy);
int delete_memory_segment(const char *name, int it);

#endif /*SHM_INCLUDED*/
