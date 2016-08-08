
#ifndef SHM_INCLUDED
#define SHM_INCLUDED

int get_memory_segment(void **p_addr, char *name, size_t sz, void (*cb)(void *cbdata, void *p), void *cbdata);
int remove_memory_segment(void *addr, char *name, int unlink, size_t sz);

int get_memory_attach_count(char *name, int *count_addr);

int get_semaphores_sysv(int *semid_addr, char *name, uint16_t sz, void (*cb)(void *cbdata, int sem_id), void *cbdata);
int remove_semaphores_sysv(int semid);

#endif  /*SHM_INCLUDED*/
