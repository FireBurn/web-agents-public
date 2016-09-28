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

/**
 ** test utility for shared memory allocator, and a control process that uses malloc in the same way for
 ** comparison.
 **
 ** this will allocate memory in a way that is compatible with the cache tests, using a different value for
 ** the memory block type so that it won't be garbage collected
 **
 **/

#include "platform.h"
#include "thread.h"

#include "alloc.h"

#define THREADS                             5

#define TEST_CYCLES                         100000

#define TEST_ALLOCS                         1000

#define TEST_CHUNK_SIZE                     4096

#define TEST_DATA_TYPE                      3


int master_recovery_process(pid_t pid)
{
    printf("alloc test recovery process: TBD\n");

    return 0;

}

void *mem_test_thread(void * data)
{
    void                                   *ptrs[TEST_ALLOCS];
    
    const int32_t                           seed = agent_memory_seed();               /* use seed to separate clusters used by each thread */
    const pid_t                             pid = getpid();

    int                                     n;

    for (n = 0; n < TEST_CYCLES; n++)
    {
        int                                 c = 0;
        
        for (int i = 0; i < TEST_ALLOCS; i++)
        {
            int32_t                         size = 1 + rand() % TEST_CHUNK_SIZE;
            
            void                           *ptr = agent_memory_alloc(pid, seed, TEST_DATA_TYPE, size);

            if (ptr)
            {
                memset(ptr, 0, size);
                ptrs[c++] = ptr;
            }
            else
            {
                printf("fail\n");
            }
        }
        // non-sequential freeing...
        for (int i = 0; i < 7; i++)
            for (int j = i; j < c; j += 7)
                agent_memory_free(pid, ptrs[j]);
        
        *(long *)data += c;
        
        if (n % 10000 == 0)
            printf("%d done %d\n", seed, (int)n);
    }

    return data;
    
}

void *mem_control_thread(void * data)
{
    void                                   *ptrs[TEST_ALLOCS];
    
    int                                     n;

    const int32_t                           seed = agent_memory_seed();
        
    for (n = 0; n < TEST_CYCLES; n++)
    {
        int c = 0;
    
        for (int i = 0; i < TEST_ALLOCS; i++)
        {
            int32_t                         size = 1 + rand() % TEST_CHUNK_SIZE;
            void                           *ptr = malloc(size);
            
            if (ptr)
            {
                memset(ptr, 0, size);
                ptrs[c++] = ptr;
            }
        }
        // non-sequential freeing...
        for (int i = 0; i < 7; i++)
            for (int j = i; j < c; j += 7)
                free(ptrs[j]);
        
        *(long *)data += c;
        
        if (n % 10000 == 0)
            printf("%d done %d\n", seed, n);

    }

    return data;
    
}

int main(int argc, char *argv[])
{
    am_thread_t                             threads[THREADS];
    
    long                                    args[THREADS];
    
    long                                    t0;
    double                                  dt;

    agent_memory_initialise(CLUSTERS * 4096 * 1024, 0);
    
    if (argc == 2 && strcmp(argv[1], "--check") == 0)
    {
        agent_memory_check(getpid(), 0, 0);

        agent_memory_destroy(0);

        exit(0);
    }

    printf("waiting... "); getchar();
    printf("joining multithreaded tests with %d threads\n", THREADS);

    t0 = clock();
    
    for (int i = 0; i < THREADS; i++)
    {
        args [i] = 0;

        AM_THREAD_CREATE(threads[i],  mem_test_thread, args + i);
    }

    for (int i = 0; i < THREADS; i++)
    {
        AM_THREAD_JOIN(threads[i]);
    }
    
    dt = ((double) (clock() - t0)) / CLOCKS_PER_SEC;
    printf("finished after %lf secs\n", dt);
    
    agent_memory_check(getpid(), 0, 0);

    agent_memory_destroy(1);

    exit(0);
}

