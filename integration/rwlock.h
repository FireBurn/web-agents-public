
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

int wait_for_barrier(struct readlock *lock, pid_t pid);

