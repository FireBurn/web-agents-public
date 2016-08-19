
#ifndef AM_MEMORY_MANAGER
#define AM_MEMORY_MANAGER

#define MEMPREFIX                                      "/tmp"

#define CTLFILE                                        MEMPREFIX"/ctl"
#define BLOCKFILE                                      MEMPREFIX"/blocks"
#define HEADERFILE                                     MEMPREFIX"/headers"

typedef uint32_t                                       offset;

void agent_memory_initialise(int32_t cluster_sz);
void agent_memory_destroy(int unlink);

int agent_memory_clusters(void);

void agent_memory_barrier(pid_t pid);

int32_t agent_memory_seed();

void *agent_memory_alloc(pid_t pid, int32_t seed, int32_t type, int32_t size);
void *agent_memory_alloc_seed(pid_t pid, int32_t seed, int32_t type, int32_t size);

int agent_memory_free(pid_t pid, void *ptr);

int agent_memory_check(pid_t pid, int verbose, int cleanup);
void agent_memory_scan(pid_t pid, int (*checker)(void *cbdata, pid_t pid, int32_t type, void *p), void *cbdata);

offset agent_memory_offset(void *ptr);
void *agent_memory_ptr(offset ofs);

void agent_memory_barrier(pid_t pid);
void agent_memory_validate(pid_t pid);

void agent_memory_reset(pid_t pid);

void agent_memory_error();

#endif  /* AM_MEMORY_MANAGER */

