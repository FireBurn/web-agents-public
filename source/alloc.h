// SPDX-License-Identifier: CDDL-1.0
//
// Copyright 2014-2016 ForgeRock AS.
// Copyright 2018-2026 Open Identity Platform Community.

#ifndef AM_MEMORY_MANAGER
#define AM_MEMORY_MANAGER
#include "platform.h"

#define CTLFILE "ctl"
#define BLOCKFILE "blocks"
#define HEADERFILE "headers"

#define CLUSTERS 256u
#define MAX_CACHE_MEMORY_SZ 0x40000000
#define MAX_CLUSTER_SIZE 0x400000

typedef uint32_t offset;

uint32_t cache_memory_size();

offset agent_memory_offset(void *ptr);
void *agent_memory_ptr(offset ofs);

int agent_memory_initialise(uint32_t sz, int id);
void agent_memory_shutdown(int unlink);
int agent_memory_cleanup(int id);

int agent_memory_clusters(void);

void agent_memory_barrier(pid_t pid);

uint32_t agent_memory_seed();

void *agent_memory_alloc(pid_t pid, uint32_t seed, int32_t type, uint32_t size);

int agent_memory_free(pid_t pid, void *ptr);

int agent_memory_check(pid_t pid, int verbose, int cleanup);
void agent_memory_scan(pid_t pid, int (*checker)(void *cbdata, pid_t pid, int32_t type, void *p), void *cbdata);

void agent_memory_barrier(pid_t pid);
void agent_memory_validate(pid_t pid);

void agent_memory_reset(pid_t pid);

void agent_memory_error();

#endif /* AM_MEMORY_MANAGER */
