/**
 ** test utility for shared memory allocator, and a control process that uses malloc in the same way for
 ** comparison.
 **
 ** this will allocate memory in a way that is compatible with the cache tests, using a different value for
 ** the memory block type so that it won't be garbage collected
 **
 **/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>

#include "alloc.h"

#define THREADS                             5

#define TEST_CYCLES                         100000

#define TEST_ALLOCS                         1000

#define TEST_CHUNK_SIZE                     4096

#define TEST_DATA_TYPE                      3

void *mem_test_thread(void * data)
{
    void                                   *ptrs[TEST_ALLOCS];
    
    // each thread tends to have an isolated cluster
    
    const int32_t                           seed = agent_memory_seed();
    const pid_t                             pid = getpid();

    int                                     n;

    for (n = 0; n < TEST_CYCLES; n++)
    {
        int                                 c = 0;
        
        for (int i = 0; i < TEST_ALLOCS; i++)
        {
            int32_t                         size = 1 + rand() % TEST_CHUNK_SIZE;
            
            void                           *ptr = agent_memory_alloc_seed(pid, seed, TEST_DATA_TYPE, size);

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

void *mem_transact_thread(void * data)
{
    void                                   *ptrs[TEST_ALLOCS];

    // each thread tends to have an isolated cluster

    //int32_t                                 seed = rand();
    const pid_t                             pid = getpid();

    int                                     n;

    for (n = 0; n < TEST_CYCLES; n++)
    {
        int                                 c = 0;

        const int32_t                       seed = agent_memory_seed();

        if (seed == ~ 0)
        {
            printf("unable to start transaction\n");
        }

        for (int i = 0; i < TEST_ALLOCS; i++)
        {
            int32_t                         size = 1 + rand() % TEST_CHUNK_SIZE;

            void                           *ptr = agent_memory_alloc_seed(pid, (seed + 3) % 32, TEST_DATA_TYPE, size);

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

    for (n = 0; n < TEST_CYCLES; n++)
    {
        int c = 0;
    
    const int32_t                           seed = agent_memory_seed();
        
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
    pthread_t                               threads[THREADS];
    
    long                                    args[THREADS];
    
    long                                    t0;
    double                                  dt;

    agent_memory_initialise(4096*1024);
    
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
        if (pthread_create(threads + i, NULL, mem_test_thread, args + i))
            perror("create thread");
    }

    for (int i = 0; i < THREADS; i++)
    {
        void                               *arg = 0;
        
        if (pthread_join(threads [i], &arg))
            perror("create thread");
    }
    
    dt = ((double) (clock() - t0)) / CLOCKS_PER_SEC;
    printf("finished after %lf secs\n", dt);
    
    agent_memory_check(getpid(), 0, 0);

    agent_memory_destroy(1);

    exit(0);
}

