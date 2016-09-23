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

#ifndef AM_MEMORY_MANAGER
#define AM_MEMORY_MANAGER

#define CTLFILE                                        "/ctl"
#define BLOCKFILE                                      "/blocks"
#define HEADERFILE                                     "/headers"

#define CLUSTERS                                       256u

typedef uint32_t                                       offset;

offset agent_memory_offset(void *ptr);
void *agent_memory_ptr(offset ofs);

void agent_memory_initialise(uint32_t sz, unsigned long id);
void agent_memory_destroy();

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

#endif  /* AM_MEMORY_MANAGER */

