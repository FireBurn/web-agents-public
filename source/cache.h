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

#ifndef AGENT_CACHE_H
#define AGENT_CACHE_H

int cache_initialise(int id);
void cache_reinitialise();
int cache_shutdown();

int cache_add(uint32_t hash, void *data, size_t ln, int64_t expires, int (*identity)(void *, void *));

void cache_delete(uint32_t hash, void *data, int (*identity)(void *, void *));

int cache_get_readlocked_ptr(uint32_t hash, void **addr, uint32_t *ln, void *data, int64_t now, int (*identity)(void *, void *));
void cache_release_readlocked_ptr(uint32_t hash);

void cache_purge_expired_entries(pid_t pid);

void cache_garbage_collect();

void cache_stats();

void cache_readlock_total_barrier(pid_t pid);

int cache_check_entries(pid_t pid);

#endif /* AGENT_CACHE_H */

