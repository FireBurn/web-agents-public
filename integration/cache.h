
#ifndef AGENT_CACHE_H
#define AGENT_CACHE_H

int cache_initialise();
void cache_reinitialise();
int cache_shutdown();

int cache_add(uint32_t hash, void *data, size_t ln, int64_t expires, int (*identity)(void *, void *));

void cache_delete(uint32_t hash, void *data, int (*identity)(void *, void *));

int cache_get_readlocked_ptr(uint32_t hash, void **addr, void *data, int (*identity)(void *, void *));
void cache_readlock_release(uint32_t hash);

void cache_purge_expired_entries(pid_t pid, int64_t now);

void cache_garbage_collect();

void cache_stats();

void cache_readlock_total_barrier(pid_t pid);

#endif /* AGENT_CACHE_H */

