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

#define THREAD_LIMIT                        20

struct readlock
{
    volatile int32_t                        readers;

    volatile pid_t                          barrier;

    volatile pid_t                          pids[THREAD_LIMIT];

};

extern const struct readlock                readlock_init;


int read_lock(struct readlock *lock, pid_t pid);

int read_lock_try(struct readlock *lock, pid_t pid, int tries);

int read_release(struct readlock *lock, pid_t pid);

int read_try_unique(struct readlock *lock, int tries);

int read_release_unique(struct readlock *lock);

int read_release_all(struct readlock *lock, pid_t pid);

int read_block(struct readlock *lock, pid_t pid);

int read_unblock(struct readlock *lock, pid_t pid);

int wait_for_barrier(struct readlock *lock, pid_t pid);

