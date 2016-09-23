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

#ifndef SHM_INCLUDED
#define SHM_INCLUDED

int get_memory_segment(am_shm_t **p_addr, char *name, size_t sz, void (*cb)(void *cbdata, void *p), void *cbdata, unsigned long id);
int remove_memory_segment(am_shm_t **p_addr);

#endif  /*SHM_INCLUDED*/
