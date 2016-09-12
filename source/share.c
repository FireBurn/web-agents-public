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
//#include <stdint.h>

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
    int                                     er = 0, creat = 0;

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
    else
    {
        er = errno;
        perror("opening shared memory");
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

