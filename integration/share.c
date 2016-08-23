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

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/shm.h>

#include "share.h"


/*
 * map entire shared memory into virtual memory
 *
 * the callack (cb) is called when the block is first opened and it is for initialisaiton of the block
 *
 */
int get_memory_segment(void **p_addr, char *name, size_t sz, void (*cb)(void *cbdata, void *p), void *cbdata)
{
    int                                     fd;
    int                                     er = 0, creat;

    fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0666);

    if (0 <= fd)
    {
        if (ftruncate(fd, sz) < 0)
        {
            er = errno;
            perror("sizing new shared memory");
        }
        else
        {
            creat = 1;
        }
    }
    else if (errno == EEXIST)
    {
        if (( fd = shm_open(name, O_RDWR, 0666) ) < 0)
        {   
            er = errno;
            perror("opening existing shared memory");
        }   
        else
        {
            creat = 0;
        }
    }

//shm_unlink(name);

    if (er == 0)
    {
        void                               *p;

        p = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

        if (p == MAP_FAILED)
        {
            er = errno;
            perror("mapping memory");

            close(fd);
        }
        else
        {
            if (creat)
            {
                cb(cbdata, p);
            }
            *p_addr = p;
        }
    }
    return er;

}

/*
 * unmap and optionlly unlink a shared memory segment
 *
 */
int remove_memory_segment(void *addr, char *name, int unlink, size_t sz)
{
    int                                     er = 0;

    if (munmap(addr, sz) < 0)
    {
        er = errno;
        perror("unmapping shared memory");
    }

    if (unlink)
    {
        if (shm_unlink(name) < 0 && errno != ENOENT)
        {
            er = errno;
            perror("unlinking shared memory");
        }
    }

    return er;

}

static int get_attach_count_sysv(int shmid)
{
    struct shmid_ds                         ds;

    if (shmctl(shmid, IPC_STAT, &ds))
    {
        perror("getting ipc stat");

        return -1;
    }
    else
    {
        return ds.shm_nattch;
    }

}

int get_memory_segment_sysv(void **p_addr, char *name, size_t sz, void (*cb)(void *cbdata, void *p), void *cbdata)
{
    int                                     shmid;
    int                                     er = 0, creat;

    key_t                                   key = ftok(name, 1);
     
    if (key < 0)
    {
        er = errno;
        perror("getting key for shared memory");
    }
    else if (0 <= ( shmid = shmget(key, sz, IPC_CREAT | IPC_EXCL | IPC_R | IPC_W | IPC_M) ))
    {
        creat = 1;
    }
    else if (errno == EEXIST)
    {
        if (( shmid = shmget(key, sz, IPC_R|IPC_W) ) < 0)
        {
            er = errno;
            perror("opening existing shared memory");
        }
        else
        {
            creat = 0;
        }
    }
    else
    {
        er = errno;
        perror("opening new memory");
    }

    if (er == 0)
    {
        void                               *p;
        int                                 att_count = get_attach_count_sysv(shmid);

        printf("attach count -> %d\n", att_count);

        p = shmat(shmid, 0, 0);

        if (p == 0)
        {
            er = errno;
            perror("mapping memory");
        }
        else
        {
            if (creat)
            {
                cb(cbdata, p);
            }
            *p_addr = p;
        }
    }
    return er;

}

int remove_memory_segment_sysv(void *addr, char *name, int unlink, size_t sz)
{
    int                                     er = 0;

    if (shmdt(addr))
    {
        er = errno;
        perror("unmapping shared memory");
    }

    if (unlink)
    {
        int                                 shmid;
        key_t                               key = ftok(name, 1);

        if (key < 0)
        {
            er = errno;
            perror("getting shared memory key");
        }
        else if (( shmid = shmget(key, 0, IPC_R | IPC_W | IPC_M) ) < 0)
        {
            /* its gone already */
        }
        else if (shmctl(shmid, IPC_RMID, 0) < 0)
        {
            er = errno;
            perror("unlinking shared memory");
        }
    }
    return er;

}

int get_memory_attach_count_sysv(char *name, int *addr)
{
    int                                     er = 0;

    int                                     shmid;
    key_t                                   key = ftok(name, 1);

    if (key < 0)
    {
        er = errno;
        perror("getting shared memory key");
    }
    else if (( shmid = shmget(key, 0, IPC_R | IPC_W | IPC_M) ) < 0)
    {
        er = errno;
        perror("getting shared memory");
    }
    else
    {
        *addr = get_attach_count_sysv(shmid);
    }
    return er;

}

#include "sys/sem.h"

int get_semaphores_sysv(int *semid_addr, char *name, uint16_t sz, void (*cb)(void *cbdata, int semid), void *cbdata)
{
    int                                     er = 0;

    int                                     semid;
    key_t                                   key = ftok(name, 1);

    if (key < 0)
    {
        er = errno;
        perror("getting key for semaphore get");
    }
    else if (0 <= ( semid = semget(key, sz, IPC_CREAT | IPC_EXCL | SEM_R | SEM_A) ))
    {
        cb(cbdata, semid);
    }
    else if (errno == EEXIST)
    {
        if (( semid = semget(key, 0, SEM_R | SEM_A) ) < 0)
        {
            er = errno;
            perror("opening existing semaphores");
        }
        else
        {
            struct semid_ds                 ds;

            if (semctl(semid, 0, IPC_STAT, &ds))
	    {
                er = errno;
                perror("validating existing semaphore");
            }
            else if (ds.sem_nsems != sz)
            {
                er = EINVAL;
                printf("semaphore set size error (%d, expecting %d)\n", (int)ds.sem_nsems, (int)sz);
            }
        }
    }
    else
    {
        er = errno;
        perror("opening new semaphores");
    }

    if (er == 0)
    {
        *semid_addr = semid;
    }

    return er;

}

int remove_semaphores_sysv(int semid)
{
    int                                     er = 0;

    if (semctl(semid, 0, IPC_RMID) < 0)
    {
        er = errno;
        perror("unlinking semaphores");
    }
    return er;

}


