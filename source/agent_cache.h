// SPDX-License-Identifier: CDDL-1.0
//
// Copyright 2014-2016 ForgeRock AS.
// Copyright 2018-2026 Open Identity Platform Community.

#ifndef AGENT_CACHE_H
#define AGENT_CACHE_H
#include "platform.h"

int cache_initialise(int id);
int cache_shutdown(int destroy);
int cache_cleanup(int id);

int is_agent_cache_ready();
int is_agent_memory_ready();

int cache_add(uint32_t hash, void *data, size_t ln, int64_t expires, int (*identity)(void *, void *));

void cache_delete(uint32_t hash, void *data, int (*identity)(void *, void *));

int cache_get_readlocked_ptr(uint32_t hash, void **addr, uint32_t *ln, void *data, int64_t now,
                             int (*identity)(void *, void *));
void cache_release_readlocked_ptr(uint32_t hash);

void cache_purge_expired_entries(pid_t pid);

void cache_garbage_collect();

void cache_stats();

void cache_readlock_total_barrier(pid_t pid);

int cache_check_entries(pid_t pid);

#endif /* AGENT_CACHE_H */
