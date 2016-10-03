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

#include "platform.h"
#include "thread.h"
#include "am.h"
#include "utility.h"
#include "version.h"
#ifndef _WIN32
#include <libgen.h>
#endif
#if defined(AIX)
#include <sys/ldr.h>

typedef struct {
    const char *dli_fname;
} Dl_info;

static int dladdr(void *s, Dl_info *i) {
#define DLADDR_BUFF_SZ      4096
    void *buf = malloc(DLADDR_BUFF_SZ);
    if (buf == NULL) {
        i->dli_fname = NULL;
        return 0;
    }
    
    char *pldi = (char *) buf;
    int r = loadquery(L_GETINFO, pldi, DLADDR_BUFF_SZ);
    if (r == -1) {
        i->dli_fname = NULL;
        free(buf);
        return 0;
    }

    struct ld_info *ldi = (struct ld_info *) pldi;
    while (ldi->ldinfo_next) {
        pldi += ldi->ldinfo_next;
        ldi = (struct ld_info *) pldi;
        char *begin = (char *) ldi->ldinfo_textorg;
        if (begin < s) {
            char *end = begin + ldi->ldinfo_textsize;
            if (end > s) {
                i->dli_fname = ldi->ldinfo_filename;
                free(buf);
                return 1;
            }
        }
    }
    i->dli_fname = NULL;
    free(buf);
    return 0;
}

#endif

#define DEFAULT_LOG_SIZE (1024 * 1024 * 5) /* 5MB */

#if defined(_WIN32)
#define AM_ATOMIC_ADD_32        InterlockedExchangeAdd
#define AM_ATOMIC_CAS_32        InterlockedCompareExchange
#define AM_ATOMIC_SWAP_32       InterlockedExchange
#elif defined(__sun)
#include <sys/atomic.h>
#define AM_ATOMIC_ADD_32        atomic_add_32_nv
#define AM_ATOMIC_CAS_32(t,o,n) atomic_cas_32(t,n,o)
#define AM_ATOMIC_SWAP_32       atomic_swap_32
#else
#define AM_ATOMIC_ADD_32        __sync_fetch_and_add
#define AM_ATOMIC_CAS_32(t,o,n) __sync_val_compare_and_swap(t,n,o)

static inline uint32_t AM_ATOMIC_SWAP_32(volatile uint32_t *target, uint32_t value) {
    __sync_synchronize();
    return __sync_lock_test_and_set(target, value);
}
#endif

#define LOG_WRITE_TIMEOUT 1000
#define LOG_READ_TIMEOUT 1000

enum {
    LOG_MUTEX = 0,
    LOG_URL_MUTEX,
    LOG_INIT_MUTEX
};

struct log_block {
    uint32_t prev;
    uint32_t next;
    volatile uint32_t done_read;
    volatile uint32_t done_write;
    unsigned long instance_id;
    int32_t level;
    uint64_t size;
    char data[AM_LOG_MESSAGE_SIZE];
};

struct log_buffer {
    struct log_block blocks[AM_LOG_QUEUE_SIZE];
    volatile uint32_t read_end; /* read and write cursors */
    volatile uint32_t read_start;
    volatile uint32_t write_end;
    volatile uint32_t write_start;

    volatile uint32_t owner; /* process id who owns the log_reader thread */
    volatile uint32_t stop; /* log_reader stop flag */

    volatile int32_t lock_owner[3];
    volatile uint32_t lock[3];

#ifndef _WIN32
    sem_t sem[2];
#endif

    struct log_files {
        int32_t used;
        unsigned long instance_id;
        char name_debug[AM_PATH_SIZE];
        char name_audit[AM_PATH_SIZE];
        int32_t max_size_debug;
        int32_t max_size_audit;
        int32_t level_debug;
        int32_t level_audit;
    } files[AM_MAX_INSTANCES];

    struct valid_url {
        unsigned long instance_id;
        uint64_t last;
        int32_t url_index;
        int32_t running;
        char config_path[AM_PATH_SIZE];
    } valid[AM_MAX_INSTANCES];

    struct instance_init {
        unsigned long instance_id;
        int32_t in_progress;
    } init[AM_MAX_INSTANCES];
};

struct log_mutex {
    int32_t pid;
    uint32_t count;
    am_mutex_t lock;
};

struct log_file {
    unsigned long instance_id;
    int32_t file_debug;
    int32_t file_audit;
    uint64_t created_debug;
    uint64_t created_audit;
};

static struct am_shared_log {
    am_event_t *log_buffer_available;
    am_event_t *log_buffer_filled;
#ifdef _WIN32
    HANDLE mapping;
#else
    int mapping;
#endif
    am_thread_t worker;
    struct log_buffer *area;
    uint64_t area_size;
    struct log_mutex *mutex[3];
} *log_handle = NULL;

static char default_log_path[AM_PATH_SIZE] = {0};

static void log_mutex_lock(int type) {
    struct log_mutex *mtx;
    if (log_handle == NULL || (mtx = log_handle->mutex[type]) == NULL)
        return;

    AM_MUTEX_LOCK(&mtx->lock);
    for (;;) {
        while (AM_ATOMIC_SWAP_32(&log_handle->area->lock[type], 1) != 0) {
#ifdef _WIN32
            Sleep(0);
#else
            sched_yield();
#endif
        }
        if (log_handle->area->lock_owner[type] == 0 || log_handle->area->lock_owner[type] == mtx->pid) {
            log_handle->area->lock_owner[type] = mtx->pid;
            AM_ATOMIC_SWAP_32(&log_handle->area->lock[type], 0);
            break;
        }
        AM_ATOMIC_SWAP_32(&log_handle->area->lock[type], 0);
#ifdef _WIN32
        Sleep(1);
#else

        nanosleep((const struct timespec[]) {
            {0, 1000000L}
        }, NULL);
#endif
    }
    ++(mtx->count);
}

static void log_mutex_unlock(int type) {
    struct log_mutex *mtx;
    if (log_handle == NULL || (mtx = log_handle->mutex[type]) == NULL)
        return;

    if (--(mtx->count) == 0) {
        while (AM_ATOMIC_SWAP_32(&log_handle->area->lock[type], 1) != 0) {
#ifdef _WIN32
            Sleep(0);
#else
            sched_yield();
#endif
        }
        log_handle->area->lock_owner[type] = 0;
        AM_ATOMIC_SWAP_32(&log_handle->area->lock[type], 0);
    }
    AM_MUTEX_UNLOCK(&mtx->lock);
}

static struct log_block *get_write_block() {
    for (;;) {
        if (log_handle == NULL || log_handle->area == NULL ||
                AM_ATOMIC_ADD_32(&log_handle->area->stop, 0) > 0)
            return NULL;
        /* check if there is a room to expand the cursor */
        uint32_t index = log_handle->area->write_start;
        struct log_block *block = log_handle->area->blocks + index;
        if (block->next == log_handle->area->read_end) {
            /* nope, wait till it becomes available */
            if (wait_for_event(log_handle->log_buffer_available, LOG_WRITE_TIMEOUT) == 0)
                continue;
            /* timeout */
            return NULL;
        }
        /* try to move write cursor forward */
        if (AM_ATOMIC_CAS_32(&log_handle->area->write_start, block->next, index) == index)
            return block;
        /* it didn't work out - someone has taken that slot already, retry */
    }
}

static struct log_block *get_read_block() {
    for (;;) {
        if (log_handle == NULL || log_handle->area == NULL ||
                AM_ATOMIC_ADD_32(&log_handle->area->stop, 0) > 0)
            return NULL;
        uint32_t index = log_handle->area->read_start;
        struct log_block *block = log_handle->area->blocks + index;
        if (index == log_handle->area->write_end) {
            if (wait_for_event(log_handle->log_buffer_filled, LOG_READ_TIMEOUT) == 0)
                continue;
            return NULL;
        }
        if (AM_ATOMIC_CAS_32(&log_handle->area->read_start, block->next, index) == index)
            return block;
    }
}

static am_bool_t should_rotate_time(uint64_t ct) {
    uint64_t ts = ct;
    ts += 86400; /* once in 24 hours */
    return difftime(time(NULL), ts) >= 0;
}


#ifdef _WIN32
#define fsync _commit
#define file_open(name) _open(name, _O_CREAT | _O_WRONLY | _O_APPEND | _O_BINARY, _S_IREAD | _S_IWRITE)
#define file_close _close
#define file_fstat _fstat64
#define file_stat_struct struct __stat64
#define file_access(name) _access(name, 0)
#else
#define file_open(name) open(name, O_CREAT | O_WRONLY | O_APPEND, S_IWUSR | S_IRUSR | S_IRGRP)
#define file_close close
#define file_fstat fstat
#define file_stat_struct struct stat
#define file_access(name) access(name, F_OK)
#endif

static void log_file_write(unsigned long instance_id, const char *data, unsigned int data_sz,
        struct log_files *f, struct log_file *file_cache, am_bool_t is_audit) {
    file_stat_struct st;
    uint64_t wr, file_created, fsize;
    int32_t file_handle, max_size;
    const char *file_name;
    int status;

    if (ISINVALID(data) || !data_sz || file_cache == NULL) {
        return;
    }

    if (f != NULL && instance_id > 0) {
        file_name = is_audit ? f->name_audit : f->name_debug;
        max_size = is_audit ? f->max_size_audit : f->max_size_debug;
        file_created = is_audit ? file_cache->created_audit : file_cache->created_debug;
        file_handle = is_audit ? file_cache->file_audit : file_cache->file_debug;
    } else if (instance_id == 0 && ISVALID(default_log_path)) {
        file_name = default_log_path;
        max_size = DEFAULT_LOG_SIZE;
        file_created = file_cache->created_debug;
        file_handle = file_cache->file_debug;
    } else {
        /* invalid arguments */
        return;
    }

    if (ISINVALID(file_name)) {
        fprintf(stderr, "log_file_write(): invalid file name\n");
        return;
    }

    if (file_handle == -1) {
        /* this is a new file - try to open/create one */
        file_handle = file_open(file_name);
#ifdef _WIN32
        if (file_handle != -1) {
            file_created = time(NULL);
        }
#endif
    }
    status = errno;
    if (file_handle == -1 || file_fstat(file_handle, &st) != 0) {
        fprintf(stderr, "log_file_write(): failed to open log file %s: (error: %d/%d)\n",
                file_name, status, errno);
        if (file_handle != -1) {
            file_close(file_handle);
        }
        if (is_audit) {
            file_cache->file_audit = -1;
        } else {
            file_cache->file_debug = -1;
        }
        return;
    }

    fsize = st.st_size;
#ifndef _WIN32
    file_created = st.st_ctime;
#endif
    /* store file ctime in local cache entry */
    if (is_audit) {
        file_cache->created_audit = file_created;
    } else {
        file_cache->created_debug = file_created;
    }

    wr = write(file_handle, data, data_sz);
    wr += write(file_handle,
#ifdef _WIN32
            "\r\n", 2
#else
            "\n", 1
#endif
            );
    fsync(file_handle);
    fsize += wr;

    /* rotate file if size exceeds max (configured) value or it is set to rotate once a day */
    if ((max_size > 0 && (fsize + 1024) > max_size) ||
            (max_size == -1 && should_rotate_time(file_created))) {
        unsigned int idx = 1;
        char *tmp = malloc(AM_PATH_SIZE + 1);
        if (tmp != NULL) {
            do {
                snprintf(tmp, AM_PATH_SIZE, "%s.%d", file_name, idx);
                idx++;
            } while (file_access(tmp) == 0);
#ifdef _WIN32
            if (CopyFileExA(file_name, tmp, NULL, NULL, FALSE, COPY_FILE_NO_BUFFERING)) {
                HANDLE fh = (HANDLE) _get_osfhandle(file_handle);
                SetFilePointer(fh, 0, NULL, FILE_BEGIN);
                SetEndOfFile(fh);
                if (is_audit) {
                    file_cache->created_audit = time(NULL);
                } else {
                    file_cache->created_debug = time(NULL);
                }
            } else {
                fprintf(stderr, "log_file_write(): could not rotate log file %s (error: %d)\n",
                        file_name, GetLastError());
            }
#else
            file_close(file_handle);
            file_handle = -1;
            if (rename(file_name, tmp) != 0) {
                fprintf(stderr, "log_file_write(): could not rotate log file %s (error: %d)\n",
                        file_name, errno);
            }
#endif
            free(tmp);
        }
    }
    /* preserve file descriptor in local cache entry */
    if (is_audit) {
        file_cache->file_audit = file_handle;
    } else {
        file_cache->file_debug = file_handle;
    }
}

static struct log_file *get_cached_file(struct log_file *fc, unsigned long instance_id) {
    int i;
    /* lookup local-cached entry */
    if (instance_id == 0)
        return &fc[AM_MAX_INSTANCES];
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        struct log_file *file = &fc[i];
        if (file->instance_id == instance_id)
            return file;
    }
    /* cache does not contain an entry yet, create one now */
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        struct log_file *file = &fc[i];
        if (file->instance_id == 0) {
            file->instance_id = instance_id;
            return file;
        }
    }
    return NULL;
}

static void log_buffer_read(struct log_file *fc) {
    int i;
    struct log_files *file = NULL;
    struct log_file *file_cache;
    /* get log block to read from */
    struct log_block *block = get_read_block();
    if (block == NULL)
        return;

    file_cache = get_cached_file(fc, block->instance_id);
    if (file_cache == NULL)
        return;

    /* lookup file data for an instance id */
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        file = &log_handle->area->files[i];
        if (file->used && file->instance_id == block->instance_id) {
            break;
        }
    }

    /* do the actual file write op */
    log_file_write(block->instance_id, block->data, (unsigned int) block->size, file, file_cache,
            (block->level & AM_LOG_LEVEL_AUDIT) != 0);

    /* set done flag for this block */
    block->done_read = 1;
    for (;;) {
        if (log_handle == NULL || log_handle->area == NULL ||
                AM_ATOMIC_ADD_32(&log_handle->area->stop, 0) > 0)
            break;
        /* try and get the right to move the cursor */
        uint32_t index = log_handle->area->read_end;
        block = log_handle->area->blocks + index;
        if (AM_ATOMIC_CAS_32(&block->done_read, 0, 1) != 1) {
            /* some other thread has already moved cursor for us or we have
             * reached as far as it possible for us to move the cursor
             */
            break;
        }
        /* move cursor forward */
        AM_ATOMIC_CAS_32(&log_handle->area->read_end, block->next, index);
        /* signal availability for more space */
        if (block->prev == log_handle->area->write_start)
            set_event(log_handle->log_buffer_available);
    }
}

static void log_file_cache_close(struct log_file *fc) {
    int i;
    for (i = 0; i < AM_MAX_INSTANCES + 1; i++) {
        struct log_file *file = &fc[i];
        if (file->file_audit != -1)
            file_close(file->file_audit);
        if (file->file_debug != -1)
            file_close(file->file_debug);
    }
}

static void *am_log_worker(void *arg) {
    int i;

    /* local open file descriptor cache; last entry reserved for instanceid 0 */
    struct log_file *fc = malloc(sizeof (struct log_file) * (AM_MAX_INSTANCES + 1));
    if (fc == NULL)
        return NULL;

    /* reset local open file descriptor cache */
    for (i = 0; i < AM_MAX_INSTANCES + 1; i++) {
        struct log_file *file = &fc[i];
        file->instance_id = 0;
        file->created_debug = file->created_audit = 0;
        file->file_debug = file->file_audit = -1;
    }
    /* log file writer loop */
    for (;;) {
        if (log_handle == NULL || log_handle->area == NULL) {
            log_file_cache_close(fc);
            free(fc);
            return NULL;
        }
        if (AM_ATOMIC_ADD_32(&log_handle->area->stop, 0) > 0)
            break;
        log_buffer_read(fc);
    }
    AM_ATOMIC_SWAP_32(&log_handle->area->owner, 0);
    log_file_cache_close(fc);
    free(fc);
    return NULL;
}

am_bool_t is_process_running(unsigned long pid) {
#ifdef _WIN32
    HANDLE proc;
    DWORD status, exitcode = 0;
    if (pid == 0)
        return AM_TRUE;
    if (pid < 0)
        return AM_FALSE;
    proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    status = GetLastError();
    if (status == ERROR_ACCESS_DENIED)
        return AM_TRUE;
    if (proc == NULL)
        return AM_FALSE;
    status = GetExitCodeProcess(proc, &exitcode);
    CloseHandle(proc);
    return exitcode == STILL_ACTIVE;
#else
    return AM_TRUE;
#endif
}

static void log_worker_register() {
    uint32_t pid = getpid();
    log_mutex_lock(LOG_MUTEX);
    if (log_handle->area->owner == 0 || (log_handle->area->owner != pid &&
            !is_process_running(log_handle->area->owner))) {

        /* register & start log-writer thread in this process */
        log_handle->area->stop = 0;
        log_handle->area->owner = pid;

        AM_THREAD_CREATE(log_handle->worker, am_log_worker, NULL);

        /* and all the rest of worker threads */
        am_restart_workers();
    }
    log_mutex_unlock(LOG_MUTEX);
}

static void log_mutex_init(am_mutex_t *mutex) {
#ifdef _WIN32
    InitializeCriticalSection(mutex);
#else
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(mutex, &attr);
    pthread_mutexattr_destroy(&attr);
#endif
}

void am_log_init(int id) {
    am_bool_t opened = AM_FALSE;

#define AM_LOG_EVENT_AVAILABLE      AM_GLOBAL_PREFIX AM_LOG_SHM_NAME "_avlb_ev"
#define AM_LOG_EVENT_FILL           AM_GLOBAL_PREFIX AM_LOG_SHM_NAME "_fill_ev"
#ifdef __sun
#define AM_LOG_SHM_NAME_INT         "/" AM_LOG_SHM_NAME "_s"
#else
#define AM_LOG_SHM_NAME_INT         AM_GLOBAL_PREFIX AM_LOG_SHM_NAME "_s"
#endif

    if (log_handle != NULL) return;

    memset(&default_log_path[0], 0, sizeof(default_log_path));

#ifdef _WIN32
    SECURITY_DESCRIPTOR sec_descr;
    SECURITY_ATTRIBUTES sec_attr, *sec = NULL;

    if (InitializeSecurityDescriptor(&sec_descr, SECURITY_DESCRIPTOR_REVISION) &&
            SetSecurityDescriptorDacl(&sec_descr, TRUE, (PACL) NULL, FALSE)) {
        sec_attr.nLength = sizeof (SECURITY_ATTRIBUTES);
        sec_attr.lpSecurityDescriptor = &sec_descr;
        sec_attr.bInheritHandle = TRUE;
        sec = &sec_attr;
    }
#endif

    log_handle = (struct am_shared_log *) calloc(1, sizeof (struct am_shared_log));
    if (log_handle == NULL) {
        return;
    }

#ifndef UNIT_TEST
#define DEFAULT_AGENT_LOG_FILE "agent.log"
#ifdef _WIN32
    HMODULE hm = NULL;
    void *caller = _ReturnAddress();
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR) caller, &hm) &&
            GetModuleFileNameA(hm, default_log_path, sizeof (default_log_path) - 1) > 0) {
        PathRemoveFileSpecA(default_log_path);
        strcat(default_log_path, "\\..\\log\\"DEFAULT_AGENT_LOG_FILE);
    }
#else
    Dl_info info;
    if (dladdr(
#ifdef AIX
            (void*) *((ulong *) & am_log_init)
#else
            (void *) &am_log_init
#endif
            , &info)) {
        snprintf(default_log_path, sizeof (default_log_path),
                "%s/../log/"DEFAULT_AGENT_LOG_FILE, dirname((char *) info.dli_fname));
    }
#endif
#endif

    log_handle->mutex[LOG_MUTEX] = (struct log_mutex *) calloc(1, sizeof (struct log_mutex));
    log_handle->mutex[LOG_URL_MUTEX] = (struct log_mutex *) calloc(1, sizeof (struct log_mutex));
    log_handle->mutex[LOG_INIT_MUTEX] = (struct log_mutex *) calloc(1, sizeof (struct log_mutex));
    if (log_handle->mutex[LOG_MUTEX] == NULL || log_handle->mutex[LOG_MUTEX] == NULL ||
            log_handle->mutex[LOG_MUTEX] == NULL) {
        AM_FREE(log_handle->mutex[LOG_MUTEX], log_handle->mutex[LOG_URL_MUTEX],
                log_handle->mutex[LOG_INIT_MUTEX], log_handle);
        log_handle = NULL;
        return;
    }

    log_handle->mutex[LOG_MUTEX]->pid = log_handle->mutex[LOG_URL_MUTEX]->pid =
            log_handle->mutex[LOG_INIT_MUTEX]->pid = getpid();

    log_mutex_init(&log_handle->mutex[LOG_MUTEX]->lock);
    log_mutex_init(&log_handle->mutex[LOG_URL_MUTEX]->lock);
    log_mutex_init(&log_handle->mutex[LOG_INIT_MUTEX]->lock);

    log_handle->area_size = page_size(sizeof (struct log_buffer));

#ifdef _WIN32

    log_handle->mapping = CreateFileMappingA(
            INVALID_HANDLE_VALUE, sec, PAGE_READWRITE,
            (DWORD) ((log_handle->area_size >> 32) & 0xFFFFFFFFul),
            (DWORD) (log_handle->area_size & 0xFFFFFFFFul), get_global_name(AM_LOG_SHM_NAME_INT, id));
    if (log_handle->mapping == NULL) {
        fprintf(stderr, "am_log_init() CreateFileMapping failed (%d)\n", GetLastError());
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_MUTEX]->lock);
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_URL_MUTEX]->lock);
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_INIT_MUTEX]->lock);
        AM_FREE(log_handle->mutex[LOG_MUTEX], log_handle->mutex[LOG_URL_MUTEX],
                log_handle->mutex[LOG_INIT_MUTEX], log_handle);
        log_handle = NULL;
        return;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        opened = AM_TRUE;
    }

    log_handle->area = (struct log_buffer *) MapViewOfFile(
            log_handle->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof (struct log_buffer));
    if (log_handle->area == NULL) {
        fprintf(stderr, "am_log_init() MapViewOfFile failed (%d)\n", GetLastError());
        CloseHandle(log_handle->mapping);
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_MUTEX]->lock);
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_URL_MUTEX]->lock);
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_INIT_MUTEX]->lock);
        AM_FREE(log_handle->mutex[LOG_MUTEX], log_handle->mutex[LOG_URL_MUTEX],
                log_handle->mutex[LOG_INIT_MUTEX], log_handle);
        log_handle = NULL;
        return;
    }

#else

    log_handle->mapping = shm_open(get_global_name(AM_LOG_SHM_NAME_INT, id),
            O_CREAT | O_EXCL | O_RDWR, 0666);
    if (log_handle->mapping == -1 && errno != EEXIST) {
        fprintf(stderr, "am_log_init() shm_open failed (%d)\n", errno);
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_MUTEX]->lock);
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_URL_MUTEX]->lock);
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_INIT_MUTEX]->lock);
        AM_FREE(log_handle->mutex[LOG_MUTEX], log_handle->mutex[LOG_URL_MUTEX],
                log_handle->mutex[LOG_INIT_MUTEX], log_handle);
        log_handle = NULL;
        return;
    }
    if (log_handle->mapping == -1) {
        log_handle->mapping = shm_open(get_global_name(AM_LOG_SHM_NAME_INT, id), O_RDWR, 0666);
        if (log_handle->mapping == -1) {
            fprintf(stderr, "am_log_init() shm_open failed (%d)\n", errno);
            AM_MUTEX_DESTROY(&log_handle->mutex[LOG_MUTEX]->lock);
            AM_MUTEX_DESTROY(&log_handle->mutex[LOG_URL_MUTEX]->lock);
            AM_MUTEX_DESTROY(&log_handle->mutex[LOG_INIT_MUTEX]->lock);
            AM_FREE(log_handle->mutex[LOG_MUTEX], log_handle->mutex[LOG_URL_MUTEX],
                    log_handle->mutex[LOG_INIT_MUTEX], log_handle);
            log_handle = NULL;
            return;
        }
        opened = AM_TRUE;
    } else if (ftruncate(log_handle->mapping, log_handle->area_size) == -1) {
        fprintf(stderr, "am_log_init() ftruncate failed (%d)\n", errno);
        close(log_handle->mapping);
        shm_unlink(get_global_name(AM_LOG_SHM_NAME_INT, id));
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_MUTEX]->lock);
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_URL_MUTEX]->lock);
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_INIT_MUTEX]->lock);
        AM_FREE(log_handle->mutex[LOG_MUTEX], log_handle->mutex[LOG_URL_MUTEX],
                log_handle->mutex[LOG_INIT_MUTEX], log_handle);
        log_handle = NULL;
        return;
    }

    log_handle->area = mmap(NULL, log_handle->area_size,
            PROT_READ | PROT_WRITE, MAP_SHARED, log_handle->mapping, 0);
    if (log_handle->area == MAP_FAILED) {
        fprintf(stderr, "am_log_init() mmap failed (%d)\n", errno);
        close(log_handle->mapping);
        shm_unlink(get_global_name(AM_LOG_SHM_NAME_INT, id));
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_MUTEX]->lock);
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_URL_MUTEX]->lock);
        AM_MUTEX_DESTROY(&log_handle->mutex[LOG_INIT_MUTEX]->lock);
        AM_FREE(log_handle->mutex[LOG_MUTEX], log_handle->mutex[LOG_URL_MUTEX],
                log_handle->mutex[LOG_INIT_MUTEX], log_handle);
        log_handle = NULL;
        return;
    }

#endif

#ifdef _WIN32
    log_handle->log_buffer_available = create_named_event(get_global_name(AM_LOG_EVENT_AVAILABLE, id),
            NULL);
    log_handle->log_buffer_filled = create_named_event(get_global_name(AM_LOG_EVENT_FILL, id),
            NULL);
#endif

    if (!opened) {
        memset(log_handle->area, 0, sizeof (struct log_buffer));

#ifndef _WIN32
        log_handle->log_buffer_available = create_named_event(NULL, &log_handle->area->sem[0]);
        log_handle->log_buffer_filled = create_named_event(NULL, &log_handle->area->sem[1]);
#endif

        /* create a double circular linked list */
        int i = 1;
        log_handle->area->blocks[0].next = 1;
        log_handle->area->blocks[0].prev = AM_LOG_QUEUE_SIZE - 1;
        for (; i < AM_LOG_QUEUE_SIZE - 1; i++) {
            /* add block into the available list */
            log_handle->area->blocks[i].next = i + 1;
            log_handle->area->blocks[i].prev = i - 1;
        }
        log_handle->area->blocks[i].next = 0;
        log_handle->area->blocks[i].prev = AM_LOG_QUEUE_SIZE - 2;

        /* initialize the cursors */
        log_handle->area->read_end = 0;
        log_handle->area->read_start = 0;
        log_handle->area->write_end = 1;
        log_handle->area->write_start = 1;

        for (i = 0; i < AM_MAX_INSTANCES; i++) {
            struct log_files *f = &log_handle->area->files[i];
            f->used = AM_FALSE;
            f->instance_id = 0;
            f->level_debug = f->level_audit = AM_LOG_LEVEL_NONE;
            f->max_size_debug = f->max_size_audit = 0;
        }
    }

    log_worker_register();
}

/**
 * This function simply returns true or false depending on whether "level" specifies we
 * need to log given the logger level settings for this instance.  Note that the function
 * should return an am_bool_t, but because of a circular dependency between am.h (which
 * defines that type) and log.h (which needs that type), I'm changing it to "int".
 */
int perform_logging(unsigned long instance_id, int level) {
    int i;
    int32_t log_level = AM_LOG_LEVEL_NONE;
    int32_t audit_level = AM_LOG_LEVEL_NONE;

    if (instance_id == 0) {
        return AM_TRUE;
    }

    /* We simply cannot log if the shared memory segment is not initialised */
    if (log_handle == NULL || log_handle->area == NULL) {
        return AM_FALSE;
    }

    log_mutex_lock(LOG_MUTEX);

    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        if (log_handle->area->files[i].instance_id == instance_id) {
            log_level = log_handle->area->files[i].level_debug;
            audit_level = log_handle->area->files[i].level_audit;
            break;
        }
    }

    log_mutex_unlock(LOG_MUTEX);

    /* Do not log in the following cases:
     *
     * requested log level is set to LEVEL_NONE
     *  or
     * selected (in a configuration) log level is LEVEL_NONE and requested log level is not LEVEL_AUDIT
     *  or
     * selected audit level is LEVE_NONE and requested log level is LEVEL_AUDIT
     */
    if (level == AM_LOG_LEVEL_NONE ||
            (log_level == AM_LOG_LEVEL_NONE && (level & AM_LOG_LEVEL_AUDIT) != AM_LOG_LEVEL_AUDIT) ||
            (audit_level == AM_LOG_LEVEL_NONE && (level & AM_LOG_LEVEL_AUDIT) == AM_LOG_LEVEL_AUDIT)) {
        return AM_FALSE;
    }

    /* In case requested log level is not LEVEL_AUDIT (as we must log audit message in case we
     * got past the previous check) and its not LEVEL_ALWAYS (which must be logged too)
     * and requested log level is "higher" than selected log level according to
     * "DEBUG > INFO > WARNING > ERROR" schema - do not log.
     */
    if ((level & AM_LOG_LEVEL_AUDIT) != AM_LOG_LEVEL_AUDIT &&
            (level & AM_LOG_LEVEL_ALWAYS) != AM_LOG_LEVEL_ALWAYS && level > log_level) {
        return AM_FALSE;
    }

    return AM_TRUE;
}

/**
 * This routine is primarily responsible for all logging within this application.
 *   instance_id: the instance that has something to log
 *   level: the level we want to log at, see constants AM_LOG_LEVEL_* in am.h
 *   header: a header consisting of various time information and the current logging level as a string
 *   header_sz: header string length
 *   format: the printf style format string telling us about the variadic arguments
 *   args: the variadic arguments themselves.
 *
 * Normally, this routine logs into a block of shared memory, which is subsequently written to a file.
 * However if we're running a unit test, this block of memory won't have been set up, even though we
 * would still like to log something somewhere.  If test cases ensure that instance_id is set to zero,
 * then logging messages are written to the standard error.
 *
 * Note that if you're calling this function from one of the macros in log.h, then the function
 * perform_logging will already have been called.  If you're not, then consider calling that function
 * first as it will save you a lot of work figuring out you didn't really want to log a message at
 * your current logging level.
 */
void am_log_write(unsigned long instance_id, int level, const char* header, int header_sz,
        const char *format, ...) {
    va_list args;
    struct log_block *block;

#ifdef UNIT_TEST
    /**
     * An instance id of zero indicates that we are running in unit test mode, shared memory is not
     * initialised and so our only option, if we want to log, is to write to the standard error.
     * Note that we ALWAYS log, no matter what the level.
     */
    if (instance_id == 0) {
        va_start(args, format);
        fprintf(stderr, "%s", header);
        vfprintf(stderr, format, args);
        fputs("\n", stderr);
        va_end(args);
        return;
    }
#endif

    if (log_handle == NULL || log_handle->area == NULL || header_sz <= 0) {
        return;
    }

    /* get the log block to write to */
    block = get_write_block();
    if (block == NULL)
        return;

    /* copy header into the bucket */
    if (strncpy(block->data, header, AM_LOG_MESSAGE_SIZE - 1) != NULL) {
        va_start(args, format);
        /* and the rest of the message */
        block->size = vsnprintf(block->data + header_sz,
                AM_LOG_MESSAGE_SIZE - header_sz, format, args) + header_sz;
        if (block->size >= AM_LOG_MESSAGE_SIZE) {
            block->size = AM_LOG_MESSAGE_SIZE - 1;
        }
        block->data[block->size] = '\0';
        va_end(args);
    }

    block->instance_id = instance_id;
    block->level = instance_id == 0 ? AM_LOG_LEVEL_ALWAYS : level;

    /* push the block back into the queue ready to be consumed */

    /* set done flag for this block */
    block->done_write = 1;
    for (;;) {
        if (log_handle == NULL || log_handle->area == NULL ||
                AM_ATOMIC_ADD_32(&log_handle->area->stop, 0) > 0)
            break;
        /* try and get the right to move the cursor */
        uint32_t index = log_handle->area->write_end;
        block = log_handle->area->blocks + index;
        if (AM_ATOMIC_CAS_32(&block->done_write, 0, 1) != 1) {
            /* some other thread has already moved cursor for us or we have
             * reached as far as it possible for us to move the cursor
             */
            break;
        }

        /* move cursor forward */
        AM_ATOMIC_CAS_32(&log_handle->area->write_end, block->next, index);

        /* signal availability of more data */
        if (block->prev == log_handle->area->read_start)
            set_event(log_handle->log_buffer_filled);
    }
}

void am_log_shutdown(int id) {
    if (log_handle == NULL || log_handle->area == NULL) {
        return;
    }

    if (AM_ATOMIC_ADD_32(&log_handle->area->owner, 0) == getpid()) {
        AM_ATOMIC_SWAP_32(&log_handle->area->stop, 1);
        AM_THREAD_JOIN(log_handle->worker);
#ifdef _WIN32
        CloseHandle(log_handle->worker);
#endif
        AM_ATOMIC_SWAP_32(&log_handle->area->owner, 0);
    }

    close_event(&log_handle->log_buffer_filled);
    close_event(&log_handle->log_buffer_available);

#ifdef _WIN32
    UnmapViewOfFile(log_handle->area);
    CloseHandle(log_handle->mapping);
#else
    munmap(log_handle->area, log_handle->area_size);
    close(log_handle->mapping);
    shm_unlink(get_global_name(AM_LOG_SHM_NAME_INT, id));
#endif

    AM_MUTEX_DESTROY(&log_handle->mutex[LOG_MUTEX]->lock);
    AM_MUTEX_DESTROY(&log_handle->mutex[LOG_URL_MUTEX]->lock);
    AM_MUTEX_DESTROY(&log_handle->mutex[LOG_INIT_MUTEX]->lock);
    AM_FREE(log_handle->mutex[LOG_MUTEX], log_handle->mutex[LOG_URL_MUTEX],
            log_handle->mutex[LOG_INIT_MUTEX], log_handle);
    log_handle = NULL;
}

int am_log_cleanup(int id) {
#ifdef _WIN32
    /* on windows, logger shared memory is mapped into the page file, and not deleted */
#else
    if (shm_unlink(get_global_name(AM_LOG_SHM_NAME_INT, id))) {
        if (errno == ENOENT)
            return AM_ERROR;
    }
#endif
    return AM_SUCCESS;
}

void am_log_register_instance(unsigned long instance_id, const char *debug_log, int log_level, int log_size,
        const char *audit_log, int audit_level, int audit_size, const char *config_file) {
    int i, exist = AM_NOT_FOUND;
    struct log_files *f;

    if (log_handle == NULL || log_handle->area == NULL ||
            instance_id == 0 || ISINVALID(debug_log) || ISINVALID(audit_log)) {
        return;
    }

#ifdef _WIN32
    log_worker_register();
#endif

    log_mutex_lock(LOG_MUTEX);

    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        f = &log_handle->area->files[i];
        if (f->instance_id == instance_id) {
            exist = AM_SUCCESS;
            break;
        }
    }
    if (exist == AM_NOT_FOUND) {
        for (i = 0; i < AM_MAX_INSTANCES; i++) {
            f = &log_handle->area->files[i];
            if (!f->used) {
                f->instance_id = instance_id;
                strncpy(f->name_debug, debug_log, sizeof (f->name_debug) - 1);
                strncpy(f->name_audit, audit_log, sizeof (f->name_audit) - 1);
                f->used = AM_TRUE;
                f->max_size_debug = log_size > 0 && log_size < DEFAULT_LOG_SIZE ? DEFAULT_LOG_SIZE : log_size;
                f->max_size_audit = audit_size > 0 && audit_size < DEFAULT_LOG_SIZE ? DEFAULT_LOG_SIZE : audit_size;
                f->level_debug = log_level;
                f->level_audit = audit_level;
                exist = AM_DONE;
                break;
            }
        }

        /* register instance in valid-url-index table */
        if (ISVALID(config_file)) {
            for (i = 0; i < AM_MAX_INSTANCES; i++) {
                struct valid_url *vf = &log_handle->area->valid[i];
                if (vf->instance_id == 0) {
                    vf->instance_id = instance_id;
                    vf->url_index = 0;
                    vf->running = 0;
                    vf->last = time(NULL);
                    strncpy(vf->config_path, config_file, sizeof (vf->config_path) - 1);
                    break;
                }
            }
        }
    } else {
        /* update instance logging level configuration */
        f->max_size_debug = log_size > 0 && log_size < DEFAULT_LOG_SIZE ? DEFAULT_LOG_SIZE : log_size;
        f->max_size_audit = audit_size > 0 && audit_size < DEFAULT_LOG_SIZE ? DEFAULT_LOG_SIZE : audit_size;
        f->level_debug = log_level;
        f->level_audit = audit_level;
    }

    log_mutex_unlock(LOG_MUTEX);

    if (exist == AM_DONE) {
#define AM_LOG_HEADER "\r\n\r\n\t######################################################\r\n\t# %-51s#\r\n\t# Version: %-42s#\r\n\t# %-51s#\r\n\t# Container: %-40s#\r\n\t# Build date: %s %-27s#\r\n\t######################################################\r\n"

        AM_LOG_ALWAYS(instance_id, AM_LOG_HEADER, DESCRIPTION, VERSION,
                VERSION_VCS, CONTAINER, __DATE__, __TIME__);

        log_mutex_lock(LOG_INIT_MUTEX);
        am_agent_init_set_value(instance_id, AM_UNKNOWN);
        log_mutex_unlock(LOG_INIT_MUTEX);
    }
}

/***************************************************************************/

int get_valid_url_index(unsigned long instance_id) {
    int i, value = 0;
    if (log_handle == NULL || log_handle->area == NULL) {
        return value;
    }

    log_mutex_lock(LOG_URL_MUTEX);
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        if (log_handle->area->valid[i].instance_id == instance_id) {
            value = log_handle->area->valid[i].url_index;
            break;
        }
    }
    log_mutex_unlock(LOG_URL_MUTEX);
    return value;
}

int get_valid_url_all(struct url_validator_worker_data *list) {
    int i, j = 0;
    if (log_handle == NULL || log_handle->area == NULL || list == NULL) {
        return AM_EINVAL;
    }

    log_mutex_lock(LOG_URL_MUTEX);
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        struct valid_url *vf = &log_handle->area->valid[i];
        if (vf->instance_id > 0 && ISVALID(vf->config_path)) {
            list[j].instance_id = vf->instance_id;
            list[j].url_index = vf->url_index;
            list[j].last = vf->last;
            list[j].running = vf->running;
            list[j].config_path = strdup(vf->config_path);
            j++;
        }
    }
    log_mutex_unlock(LOG_URL_MUTEX);
    return j > 0 ? AM_SUCCESS : AM_NOT_FOUND;
}

/***************************************************************************/

void set_valid_url_index(unsigned long instance_id, int value) {
    int i;
    if (log_handle == NULL || log_handle->area == NULL) {
        return;
    }

    log_mutex_lock(LOG_URL_MUTEX);
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        struct valid_url *vf = &log_handle->area->valid[i];
        if (vf->instance_id == instance_id) {
            vf->url_index = value;
            vf->last = time(NULL);
            break;
        }
    }
    log_mutex_unlock(LOG_URL_MUTEX);
}

void set_valid_url_instance_running(unsigned long instance_id, int value) {
    int i;
    if (log_handle == NULL || log_handle->area == NULL) {
        return;
    }

    log_mutex_lock(LOG_URL_MUTEX);
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        struct valid_url *vf = &log_handle->area->valid[i];
        if (vf->instance_id == instance_id) {
            vf->running = value;
            break;
        }
    }
    log_mutex_unlock(LOG_URL_MUTEX);
}

void am_agent_init_set_value(unsigned long instance_id, int val) {
    int i;
    if (log_handle == NULL || log_handle->area == NULL) {
        return;
    }
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        if (val == AM_UNKNOWN) {
            /* find the first empty slot */
            if (log_handle->area->init[i].instance_id == 0) {
                log_handle->area->init[i].in_progress = 0;
                log_handle->area->init[i].instance_id = instance_id;
                break;
            }
        } else {
            /* set/reset status value */
            if (log_handle->area->init[i].instance_id == instance_id) {
                log_handle->area->init[i].in_progress = val;
                break;
            }
        }
    }
}

int am_agent_init_get_value(unsigned long instance_id) {
    int i, status = AM_FALSE;
    if (log_handle == NULL || log_handle->area == NULL) {
        return status;
    }
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        /* get status value */
        if (log_handle->area->init[i].instance_id == instance_id) {
            status = log_handle->area->init[i].in_progress;
            break;
        }
    }
    return status;
}

void am_agent_instance_init_lock() {
    log_mutex_lock(LOG_INIT_MUTEX);
}

void am_agent_instance_init_unlock() {
    log_mutex_unlock(LOG_INIT_MUTEX);
}

#ifdef _WIN32

static int gettimeofday(struct timeval *tv, void *tz) {
    FILETIME ft;
    ULARGE_INTEGER tmp;

    if (tv == NULL) return -1;

    GetSystemTimeAsFileTime(&ft);

    /* GetSystemTimeAsFileTime returns the number of 100 nanosecond 
     * intervals since Jan 1, 1601 (UTC) 
     */
    tmp.LowPart = ft.dwLowDateTime;
    tmp.HighPart = ft.dwHighDateTime;

    /* convert to microseconds */
    tmp.QuadPart /= 10ULL;

    /* the UNIX epoch starts on Jan 1 1970 - need to subtract the difference 
     * in seconds from Jan 1 1601
     */
    tmp.QuadPart -= 11644473600000000ULL;

    /* finally change microseconds to seconds and place in the seconds value, 
     * the modulus picks up the microseconds
     */
    tv->tv_usec = (long) (tmp.QuadPart % 1000000LL);
    tv->tv_sec = (long) (tmp.QuadPart / 1000000LL);
    return 0;
}

#endif

char *log_header(int log_level, int *header_sz, const char *file, int line) {
    static AM_THREAD_LOCAL char header[160];
    char tz[6];
    size_t time_string_sz;
    struct tm now;
    struct timeval tv;
    const char *level;
    time_t rawtime;

    gettimeofday(&tv, NULL);
    rawtime = (time_t) tv.tv_sec;
    localtime_r(&rawtime, &now);

    switch (log_level) {
        case AM_LOG_LEVEL_AUDIT:
            level = "AUDIT";
            break;
        case AM_LOG_LEVEL_DEBUG:
            level = "DEBUG";
            break;
        case AM_LOG_LEVEL_ERROR:
            level = "ERROR";
            break;
        case AM_LOG_LEVEL_WARNING:
            level = "WARNING";
            break;
        default:
            level = "INFO";
            break;
    }
    /* format time */
    time_string_sz = strftime(header, sizeof (header), "%Y-%m-%d %H:%M:%S", &now);

    /* and time zone */
#ifdef _WIN32
#define LOG_HEADER_THREAD_ID "%d"
    TIME_ZONE_INFORMATION tz_info;
    GetTimeZoneInformation(&tz_info);
    snprintf(tz, sizeof (tz), "%03d%02d", -(tz_info.Bias) / 60, abs(-(tz_info.Bias) % 60));
    if (tz[0] == '0') {
        tz[0] = '+';
    }
#else
#define LOG_HEADER_THREAD_ID "%p"
    strftime(tz, sizeof (tz), "%z", &now);
#endif

    /* set all the data for the final log header */
    if (log_level == AM_LOG_LEVEL_DEBUG) {
        *header_sz = snprintf(header + time_string_sz, sizeof (header) - time_string_sz,
                ".%03ld %s %7.7s ["LOG_HEADER_THREAD_ID":%d][%s:%d] ",
                tv.tv_usec / 1000L, tz, level,
#ifdef _WIN32
                GetCurrentThreadId(),
#else
                (void *) (uintptr_t) pthread_self(),
#endif
                getpid(), NOTNULL(file), line);
    } else {
        *header_sz = snprintf(header + time_string_sz, sizeof (header) - time_string_sz,
                ".%03ld %s %7.7s ["LOG_HEADER_THREAD_ID":%d] ",
                tv.tv_usec / 1000L, tz, level,
#ifdef _WIN32
                GetCurrentThreadId(),
#else
                (void *) (uintptr_t) pthread_self(),
#endif
                getpid());
    }
    *header_sz += (int) time_string_sz;
    return header;
}
