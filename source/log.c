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
 * Copyright 2014 - 2015 ForgeRock AS.
 */

#include "platform.h"
#include "am.h"
#include "utility.h"
#include "version.h"

#define AM_LOG_BUFFER_MASK(index, size) ((index) & ((size) - 1))

#if defined(_WIN32)
static HANDLE ic_sem = NULL;
#elif defined(__APPLE__)
static semaphore_t ic_sem;
#else
static sem_t *ic_sem = NULL;
#endif


/**
 * This flag says we want debugging messages when the instance id is zero
 */
static am_bool_t zero_instance_logging_is_wanted = AM_FALSE;

struct am_shared_log {
    void *area;
    size_t area_size;
    char area_file_name[AM_PATH_SIZE];
#ifdef _WIN32
    HANDLE area_file_id;
    int reader_pid;
    HANDLE reader_thr;
#else
    int area_file_id;
    pid_t reader_pid;
    pthread_t reader_thr;
#endif
};

static struct am_shared_log *am_log_handle = NULL;

#define AM_LOG() (am_log_handle != NULL ? (struct am_log *) am_log_handle->area : NULL)

#ifdef _WIN32

struct am_shared_log_lock_s {
    HANDLE exit;
    HANDLE lock;
    HANDLE new_data_cond;
    HANDLE new_space_cond;
};

static struct am_shared_log_lock_s am_log_lck = {NULL, NULL, NULL, NULL};

#endif

struct am_log {
    volatile unsigned int in;
    volatile unsigned int out;
    volatile unsigned int read_count;
    volatile unsigned int write_count;
    unsigned int bucket_count;
    unsigned int bucket_size;
#ifndef _WIN32
    pthread_mutex_t lock;
    pthread_mutex_t exit;
    pthread_cond_t new_data_cond;
    pthread_cond_t new_space_cond;
#endif

    struct log_bucket {
        char data[AM_LOG_MESSAGE_SIZE];
        size_t size;
        unsigned long instance_id;
        int level;
        volatile char ready_to_read;
    } bucket[AM_LOG_QUEUE_SIZE];

    struct log_files {
        int used;
        unsigned long instance_id;
        char name_debug[AM_PATH_SIZE];
        char name_audit[AM_PATH_SIZE];
        int owner;
        int fd_debug;
        int fd_audit;
        int max_size_debug;
        int max_size_audit;
        int level_debug;
        int level_audit;
        time_t created_debug;
        time_t created_audit;
#ifndef _WIN32
        ino_t node_debug;
        ino_t node_audit;
#endif
    } files[AM_MAX_INSTANCES];

    int owner; /* current log reader process id */

    struct valid_url {
        unsigned long instance_id;
        time_t last;
        int url_index;
        int running;
        char config_path[AM_PATH_SIZE];
    } valid[AM_MAX_INSTANCES];

    struct instance_init {
        unsigned long instance_id;
        int in_progress;
    } init[AM_MAX_INSTANCES];
};

#ifndef _WIN32

/*****************************************************************************************/

static am_bool_t should_exit(pthread_mutex_t *mtx) {
    switch (pthread_mutex_trylock(mtx)) {
        case 0:
            pthread_mutex_unlock(mtx);
            return AM_TRUE;
        case EBUSY:
            return AM_FALSE;
    }
    return AM_TRUE;
}

/*****************************************************************************************/

static void rename_file(const char *file_name) {
    unsigned int idx = 1;
    static char tmp[AM_PATH_SIZE];
    do {
        snprintf(tmp, sizeof (tmp), "%s.%d", file_name, idx);
        idx++;
    } while (access(tmp, F_OK) == 0);
    if (rename(file_name, tmp) != 0) {
        fprintf(stderr, "could not rotate log file %s (error: %d)\n", file_name, errno);
    }
}

#endif /* _WIN32 */

/*****************************************************************************************/

static am_bool_t should_rotate_time(time_t ct) {
    time_t ts = ct;
    ts += 86400; /* once in 24 hours */
    if (difftime(time(NULL), ts) >= 0) {
        return AM_TRUE;
    }
    return AM_FALSE;
}

/*****************************************************************************************/

static void *am_log_worker(void *arg) {
    struct am_log *log = AM_LOG();
    int i, level, is_audit;
    unsigned int index;
    char *data;
    size_t data_sz;
    unsigned long instance_id;
    struct stat st;
    struct log_files *f;

    if (log == NULL) {
        return NULL;
    }

#ifdef _WIN32
    WaitForSingleObject(am_log_lck.lock, INFINITE);
#else
    pthread_mutex_lock(&log->lock);
#endif

    for (;;) {
        index = log->out;

#ifdef _WIN32
        while (log->read_count == 0 || !log->bucket[index].ready_to_read) {
            ReleaseMutex(am_log_lck.lock);
            if (WaitForSingleObject(am_log_lck.new_data_cond, 1000) == WAIT_TIMEOUT) {
                if (WaitForSingleObject(am_log_lck.exit, 0) == WAIT_OBJECT_0) {
                    return NULL;
                }
            }
            WaitForSingleObject(am_log_lck.lock, INFINITE);
        }
#else
        while (log->read_count == 0 || !log->bucket[index].ready_to_read) {
            struct timeval now = {0, 0};
            struct timespec ts = {0, 0};
            gettimeofday(&now, NULL);
            ts.tv_sec = now.tv_sec + 1;
            ts.tv_nsec = now.tv_usec * 1000;
            if (pthread_cond_timedwait(&log->new_data_cond, &log->lock, &ts) == ETIMEDOUT) {
                if (should_exit(&log->exit)) {
                    pthread_mutex_unlock(&log->lock);
                    return NULL;
                }
            }
        }
#endif  /* _WIN32 */

        log->bucket[index].ready_to_read = AM_FALSE;
#ifdef _WIN32
        ReleaseMutex(am_log_lck.lock);
#else
        pthread_mutex_unlock(&log->lock);
#endif  /* _WIN32 */

        data = log->bucket[index].data;
        data_sz = log->bucket[index].size;
        level = log->bucket[index].level;
        is_audit = (level & AM_LOG_LEVEL_AUDIT) != 0;
        instance_id = log->bucket[index].instance_id;

        f = NULL;

        for (i = 0; i < AM_MAX_INSTANCES; i++) {
            f = &log->files[i];
            if (f->used && f->instance_id == instance_id) {
                break;
            }
        }

        if (f != NULL) {

            if (ISINVALID(f->name_debug)) {
                fprintf(stderr, "am_log_worker(): the debug file name is invalid (i.e. empty or null)\n");
                f->fd_debug = -1;
                f->fd_audit = -1;
                return NULL;
            }

            if (ISINVALID(f->name_audit)) {
                fprintf(stderr, "am_log_worker(): the audit file name is invalid (i.e. empty or null)\n");
                f->fd_debug = -1;
                f->fd_audit = -1;
                return NULL;
            }

            /* log files are not opened yet, do it now */
            if (f->fd_audit == -1 && f->fd_debug == -1) {
#ifdef _WIN32

                f->fd_debug = _open(f->name_debug, _O_CREAT | _O_WRONLY | _O_APPEND | _O_BINARY,
                        _S_IREAD | _S_IWRITE);
                f->fd_audit = _open(f->name_audit, _O_CREAT | _O_WRONLY | _O_APPEND | _O_BINARY,
                        _S_IREAD | _S_IWRITE);
                if (f->fd_debug != -1 && stat(f->name_debug, &st) == 0) {
                    f->created_debug = st.st_ctime;
                    f->owner = getpid();
                }
                if (f->fd_audit != -1 && stat(f->name_audit, &st) == 0) {
                    f->created_audit = st.st_ctime;
                    f->owner = getpid();
                }

#else
                f->fd_debug = open(f->name_debug, O_CREAT | O_WRONLY | O_APPEND, S_IWUSR | S_IRUSR);
                f->fd_audit = open(f->name_audit, O_CREAT | O_WRONLY | O_APPEND, S_IWUSR | S_IRUSR);
                if (f->fd_debug != -1 && stat(f->name_debug, &st) == 0) {
                    f->node_debug = st.st_ino;
                    f->created_debug = st.st_ctime;
                    f->owner = getpid();
                }
                if (f->fd_audit != -1 && stat(f->name_audit, &st) == 0) {
                    f->node_audit = st.st_ino;
                    f->created_audit = st.st_ctime;
                    f->owner = getpid();
                }
#endif
            }

            if (f->fd_debug == -1) {
                fprintf(stderr, "am_log_worker() failed to open log file %s: error: %d", f->name_debug, errno);
                f->fd_debug = f->fd_audit = -1;
            } else if (f->fd_audit == -1) {
                fprintf(stderr, "am_log_worker() failed to open audit file %s: error: %d", f->name_audit, errno);
                f->fd_debug = f->fd_audit = -1;
            } else {
                int file_handle = is_audit ? f->fd_audit : f->fd_debug;
                char *file_name = is_audit ? f->name_audit : f->name_debug;
                int max_size = is_audit ? f->max_size_audit : f->max_size_debug;
                time_t file_created = is_audit ? f->created_audit : f->created_debug;
#ifdef _WIN32
                int wrote;
#else 
                ssize_t wrote;
                ino_t file_inode = is_audit ? f->node_audit : f->node_debug;
#endif
                wrote = write(file_handle, data, (unsigned int) data_sz);
#ifdef _WIN32
                wrote = write(file_handle, "\r\n", 2);
                _commit(file_handle);

                /* check file timestamp; rotate by date if set so */
                if (max_size == -1 && should_rotate_time(file_created)) {
                    HANDLE fh = (HANDLE) _get_osfhandle(file_handle);
                    unsigned int idx = 1;
                    static char tmp[AM_PATH_SIZE];

                    do {
                        snprintf(tmp, sizeof (tmp), "%s.%d", file_name, idx);
                        idx++;
                    } while (_access(tmp, 0) == 0);

                    if (CopyFileExA(file_name, tmp, NULL, NULL, FALSE, COPY_FILE_NO_BUFFERING)) {
                        SetFilePointer(fh, 0, NULL, FILE_BEGIN);
                        SetEndOfFile(fh);
                        if (is_audit) {
                            f->created_audit = time(NULL);
                        } else {
                            f->created_debug = time(NULL);
                        }
                    } else {
                        fprintf(stderr, "could not rotate log file %s (error: %d)\n",
                                file_name, GetLastError());
                    }
                }

                /* check file size; rotate by size if set so */
                if (max_size > 0) {
                    BY_HANDLE_FILE_INFORMATION info;
                    uint64_t fsz = 0;
                    HANDLE fh = (HANDLE) _get_osfhandle(file_handle);
                    if (GetFileInformationByHandle(fh, &info)) {
                        fsz = ((DWORDLONG) (((DWORD) (info.nFileSizeLow)) |
                                (((DWORDLONG) ((DWORD) (info.nFileSizeHigh))) << 32)));
                    }
                    if ((fsz + 1024) > max_size) {
                        unsigned int idx = 1;
                        static char tmp[AM_PATH_SIZE];

                        do {
                            snprintf(tmp, sizeof (tmp), "%s.%d", file_name, idx);
                            idx++;
                        } while (_access(tmp, 0) == 0);

                        if (CopyFileExA(file_name, tmp, NULL, NULL, FALSE, COPY_FILE_NO_BUFFERING)) {
                            SetFilePointer(fh, 0, NULL, FILE_BEGIN);
                            SetEndOfFile(fh);
                            if (is_audit) {
                                f->created_audit = time(NULL);
                            } else {
                                f->created_debug = time(NULL);
                            }
                        } else {
                            fprintf(stderr, "could not rotate log file %s (error: %d)\n",
                                    file_name, GetLastError());
                        }
                    }
                }

                _close(file_handle);
                if (is_audit) {
                    f->fd_audit = -1;
                } else {
                    f->fd_debug = -1;
                }
#else
                wrote = write(file_handle, "\n", 1);
                fsync(file_handle);

                /* check file timestamp; rotate by date if set so */
                if (max_size == -1 && should_rotate_time(file_created)) {
                    rename_file(file_name);
                }

                /* check file size; rotate by size if set so */
                if (max_size > 0 && stat(file_name, &st) == 0 && (st.st_size + 1024) > max_size) {
                    rename_file(file_name);
                }

                /* reset file inode number (in case it has changed as a result of rename_file) */
                if (stat(file_name, &st) != 0 || st.st_ino != file_inode) {
                    close(file_handle);
                    if (is_audit) {
                        f->fd_audit = open(f->name_audit, O_CREAT | O_WRONLY | O_APPEND, S_IWUSR | S_IRUSR);
                        f->node_audit = st.st_ino;
                        f->created_audit = st.st_ctime;
                        f->owner = getpid();
                    } else {
                        f->fd_debug = open(f->name_debug, O_CREAT | O_WRONLY | O_APPEND, S_IWUSR | S_IRUSR);
                        f->node_debug = st.st_ino;
                        f->created_debug = st.st_ctime;
                        f->owner = getpid();
                    }
                    if (f->fd_debug == -1 || f->fd_audit == -1) {
                        fprintf(stderr, "am_log_worker() log file re-open failed with error: %d", errno);
                        f->fd_debug = f->fd_audit = -1;
                    }
                }
#endif                            
            }
        }

        log->out = AM_LOG_BUFFER_MASK(log->out + 1, log->bucket_count);
#ifdef _WIN32
        WaitForSingleObject(am_log_lck.lock, INFINITE);
#else
        pthread_mutex_lock(&log->lock);
#endif
        log->read_count--;
#ifdef _WIN32
        SetEvent(am_log_lck.new_space_cond);
#else
        pthread_cond_broadcast(&log->new_space_cond);
#endif
    }
    return NULL;
}

/*****************************************************************************************/

void am_log_re_init(int status) {
#ifdef _WIN32
    struct am_log *log = AM_LOG();
    if (log != NULL && status == AM_RETRY_ERROR) {
        WaitForSingleObject(am_log_lck.lock, INFINITE);
        log->owner = getpid();
        am_log_handle->reader_thr = CreateThread(NULL, 0,
                (LPTHREAD_START_ROUTINE) am_log_worker, NULL, 0, NULL);
        ReleaseMutex(am_log_lck.lock);
    }
#endif
}

/*****************************************************************************************/

void am_log_init(int id, int status) {
    int i;
    char opened = 0;
#ifdef _WIN32
    SECURITY_DESCRIPTOR sec_descr;
    SECURITY_ATTRIBUTES sec_attr, *sec = NULL;
#endif

    if (am_agent_instance_init_init(id) != AM_SUCCESS) {
        return;
    }

    if (am_log_handle == NULL) {
        am_log_handle = (struct am_shared_log *) malloc(sizeof (struct am_shared_log));
        if (am_log_handle == NULL) {
            return;
        }
    }
#ifndef _WIN32
    else if (am_log_handle->reader_pid == getpid()) {
        return;
    }

    am_log_handle->reader_pid = getpid();
#endif

    snprintf(am_log_handle->area_file_name, sizeof (am_log_handle->area_file_name),
#ifdef __sun
            "/am_log_%d"
#else
            AM_GLOBAL_PREFIX"am_log_%d"
#endif
            , id);
    am_log_handle->area_size = page_size(sizeof (struct am_log));

#ifdef _WIN32
    if (InitializeSecurityDescriptor(&sec_descr, SECURITY_DESCRIPTOR_REVISION) &&
            SetSecurityDescriptorDacl(&sec_descr, TRUE, (PACL) NULL, FALSE)) {
        sec_attr.nLength = sizeof (SECURITY_ATTRIBUTES);
        sec_attr.lpSecurityDescriptor = &sec_descr;
        sec_attr.bInheritHandle = TRUE;
        sec = &sec_attr;
    }

    am_log_handle->area_file_id = CreateFileMappingA(INVALID_HANDLE_VALUE, sec, PAGE_READWRITE,
            0, (DWORD) am_log_handle->area_size, am_log_handle->area_file_name);

    if (am_log_handle->area_file_id == NULL) {
        return;
    }

    if (am_log_handle->area_file_id != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
        opened = 1;
    }

    if (am_log_handle->area_file_id != NULL) {
        am_log_handle->area = MapViewOfFile(am_log_handle->area_file_id, FILE_MAP_ALL_ACCESS,
                0, 0, am_log_handle->area_size);
    }

    if (am_log_handle->area != NULL) {

        am_log_lck.exit = CreateEventA(sec, FALSE, FALSE,
                get_global_name(AM_GLOBAL_PREFIX"am_log_exit", id));
        if (am_log_lck.exit == NULL && GetLastError() == ERROR_ACCESS_DENIED) {
            am_log_lck.exit = OpenEventA(SYNCHRONIZE, TRUE,
                    get_global_name(AM_GLOBAL_PREFIX"am_log_exit", id));
        }
        am_log_lck.lock = CreateMutexA(sec, FALSE,
                get_global_name(AM_GLOBAL_PREFIX"am_log_lock", id));
        if (am_log_lck.lock == NULL && GetLastError() == ERROR_ACCESS_DENIED) {
            am_log_lck.lock = OpenMutexA(SYNCHRONIZE, TRUE,
                    get_global_name(AM_GLOBAL_PREFIX"am_log_lock", id));
        }
        am_log_lck.new_data_cond = CreateEventA(sec, FALSE, FALSE,
                get_global_name(AM_GLOBAL_PREFIX"am_log_queue_empty", id));
        if (am_log_lck.new_data_cond == NULL && GetLastError() == ERROR_ACCESS_DENIED) {
            am_log_lck.new_data_cond = OpenEventA(SYNCHRONIZE, TRUE,
                    get_global_name(AM_GLOBAL_PREFIX"am_log_queue_empty", id));
        }
        am_log_lck.new_space_cond = CreateEventA(sec, FALSE, FALSE,
                get_global_name(AM_GLOBAL_PREFIX"am_log_queue_overflow", id));
        if (am_log_lck.new_space_cond == NULL && GetLastError() == ERROR_ACCESS_DENIED) {
            am_log_lck.new_space_cond = OpenEventA(SYNCHRONIZE, TRUE,
                    get_global_name(AM_GLOBAL_PREFIX"am_log_queue_overflow", id));
        }

        if (status == AM_SUCCESS || status == AM_EAGAIN) {
            struct am_log *log = (struct am_log *) am_log_handle->area;

            memset(log, 0, am_log_handle->area_size);
            log->bucket_count = AM_LOG_QUEUE_SIZE;
            log->bucket_size = AM_LOG_MESSAGE_SIZE;
            log->in = log->out = log->read_count = log->write_count = 0;

            for (i = 0; i < AM_MAX_INSTANCES; i++) {
                struct log_files *f = &log->files[i];
                f->fd_audit = f->fd_debug = -1;
                f->used = AM_FALSE;
                f->instance_id = 0;
                f->level_debug = f->level_audit = AM_LOG_LEVEL_NONE;
                f->max_size_debug = f->max_size_audit = 0;
            }

            log->owner = getpid();
            am_log_handle->reader_thr = CreateThread(NULL, 0,
                    (LPTHREAD_START_ROUTINE) am_log_worker, NULL, 0, NULL);
        }
    }

#else
    am_log_handle->area_file_id = shm_open(am_log_handle->area_file_name, O_CREAT | O_EXCL | O_RDWR, 0666);
    if (am_log_handle->area_file_id == -1 && EEXIST != errno) {
        return;
    }
    if (am_log_handle->area_file_id == -1) {
        /* already there, open without O_EXCL and go; if
         * something goes wrong, close and cleanup */
        am_log_handle->area_file_id = shm_open(am_log_handle->area_file_name, O_RDWR, 0666);
        if (am_log_handle->area_file_id == -1) {
            fprintf(stderr, "am_log_init() shm_open failed (%d)\n", errno);
            free(am_log_handle);
            am_log_handle = NULL;
            return;
        } else {
            opened = 1;
        }
    } else {
        /* we just created the shm area, must setup; if
         * something goes wrong, delete the shm area and
         * cleanup
         */
        if (ftruncate(am_log_handle->area_file_id, am_log_handle->area_size) == -1) {
            fprintf(stderr, "am_log_init() ftruncate failed\n");
            return;
        }
    }
    if (am_log_handle->area_file_id != -1) {
        am_log_handle->area = mmap(NULL, am_log_handle->area_size,
                PROT_READ | PROT_WRITE, MAP_SHARED, am_log_handle->area_file_id, 0);
        if (am_log_handle->area == MAP_FAILED) {
            fprintf(stderr, "am_log_init() mmap failed (%d)\n", errno);
            free(am_log_handle);
            am_log_handle = NULL;
        } else {
            pthread_mutexattr_t exit_attr, lock_attr;
            pthread_condattr_t new_data_attr, new_space_attr;

            struct am_log *log = (struct am_log *) am_log_handle->area;

            pthread_mutexattr_init(&exit_attr);
            pthread_mutexattr_init(&lock_attr);
            pthread_condattr_init(&new_data_attr);
            pthread_condattr_init(&new_space_attr);
            pthread_mutexattr_setpshared(&exit_attr, PTHREAD_PROCESS_SHARED);
            pthread_mutexattr_setpshared(&lock_attr, PTHREAD_PROCESS_SHARED);
            pthread_condattr_setpshared(&new_data_attr, PTHREAD_PROCESS_SHARED);
            pthread_condattr_setpshared(&new_space_attr, PTHREAD_PROCESS_SHARED);

            if (status == AM_SUCCESS || status == AM_EAGAIN) {

                memset(log, 0, am_log_handle->area_size);

                log->bucket_count = AM_LOG_QUEUE_SIZE;
                log->bucket_size = AM_LOG_MESSAGE_SIZE;
                log->in = log->out = log->read_count = log->write_count = 0;

                for (i = 0; i < AM_MAX_INSTANCES; i++) {
                    struct log_files *f = &log->files[i];
                    f->fd_audit = f->fd_debug = -1;
                    f->used = AM_FALSE;
                    f->instance_id = 0;
                    f->level_debug = f->level_audit = AM_LOG_LEVEL_NONE;
                    f->max_size_debug = f->max_size_audit = 0;
                }

                pthread_mutex_init(&log->exit, &exit_attr);
                pthread_mutex_init(&log->lock, &lock_attr);
                pthread_cond_init(&log->new_data_cond, &new_data_attr);
                pthread_cond_init(&log->new_space_cond, &new_space_attr);

                pthread_mutex_lock(&log->exit);
                pthread_create(&am_log_handle->reader_thr, NULL, am_log_worker, NULL);
                log->owner = getpid();
            }

            pthread_mutexattr_destroy(&exit_attr);
            pthread_mutexattr_destroy(&lock_attr);
            pthread_condattr_destroy(&new_data_attr);
            pthread_condattr_destroy(&new_space_attr);
        }
    }

#endif
}

/*****************************************************************************************/

void am_log_init_worker(int id, int status) {
#ifdef _WIN32
    am_log_init(id, status);
#endif
}

/**
 * This function simply returns true or false depending on whether "level" specifies we
 * need to log given the logger level settings for this instance.  Note that the function
 * should return an am_bool_t, but because of a circular dependency between am.h (which
 * defines that type) and log.h (which needs that type), I'm changing it to "int".
 */
int perform_logging(unsigned long instance_id, int level) {
    int i;
    struct am_log *log = AM_LOG();
    int log_level = AM_LOG_LEVEL_NONE;
    int audit_level = AM_LOG_LEVEL_NONE;

    /* If the instance id is zero, we are either running a test case, or installing something */
    if (instance_id == 0) {
        return zero_instance_logging_is_wanted;
    }

    /* We simply cannot log if the shared memory segment is not initialised */
    if (log == NULL) {
        return AM_FALSE;
    }

#ifdef _WIN32
    WaitForSingleObject(am_log_lck.lock, INFINITE);
#else
    pthread_mutex_lock(&log->lock);
#endif

    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        if (log->files[i].instance_id == instance_id) {
            log_level = log->files[i].level_debug;
            audit_level = log->files[i].level_audit;
            break;
        }
    }

#ifdef _WIN32
    ReleaseMutex(am_log_lck.lock);
#else
    pthread_mutex_unlock(&log->lock);
#endif

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
void am_log_write(unsigned long instance_id, int level, const char* header, int header_sz, const char *format, ...) {
    struct am_log *log = AM_LOG();
    va_list args;
    unsigned int index;

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

    if (log == NULL || header_sz <= 0) {
        return;
    }

#ifdef _WIN32
    WaitForSingleObject(am_log_lck.lock, INFINITE);
    while (log->read_count + log->write_count >= log->bucket_count) {
        ReleaseMutex(am_log_lck.lock);
        WaitForSingleObject(am_log_lck.new_space_cond, INFINITE);
        WaitForSingleObject(am_log_lck.lock, INFINITE);
    }
#else
    pthread_mutex_lock(&log->lock);
    while (log->read_count + log->write_count >= log->bucket_count) {
        pthread_cond_wait(&log->new_space_cond, &log->lock);
    }
#endif

    index = log->in;
    log->in = AM_LOG_BUFFER_MASK(log->in + 1, log->bucket_count);
    log->write_count++;

#ifdef _WIN32
    ReleaseMutex(am_log_lck.lock);
#else
    pthread_mutex_unlock(&log->lock);
#endif

    /* copy header into the bucket */
    if (strncpy(log->bucket[index].data, header, log->bucket_size - 1) != NULL) {
        va_start(args, format);
        /* and the rest of the message */
        log->bucket[index].size = vsnprintf(log->bucket[index].data + header_sz,
                log->bucket_size - header_sz, format, args) + header_sz;
        log->bucket[index].data[log->bucket[index].size] = '\0';
        va_end(args);
    }

    log->bucket[index].instance_id = instance_id;
    log->bucket[index].level = level;

#ifdef _WIN32
    WaitForSingleObject(am_log_lck.lock, INFINITE);
#else
    pthread_mutex_lock(&log->lock);
#endif

    log->read_count++;
    log->write_count--;
    log->bucket[index].ready_to_read = AM_TRUE;

#ifdef _WIN32
    SetEvent(am_log_lck.new_data_cond);
    ReleaseMutex(am_log_lck.lock);
#else
    pthread_cond_signal(&log->new_data_cond);
    pthread_mutex_unlock(&log->lock);
#endif
}

void am_log_shutdown(int id) {
    static const char *thisfunc = "am_log_shutdown():";
    int i;
    int pid = getpid();
    struct am_log *log = AM_LOG();

    if (log == NULL) {
        return;
    }

    /* notify the logger exit */
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        struct log_files *f = &log->files[i];
        if (f->instance_id > 0 && f->owner == pid) {
            AM_LOG_ALWAYS(f->instance_id, "%s exiting", thisfunc);
        }
    }

#ifdef _WIN32
    if (log->owner == pid) {
        SetEvent(am_log_lck.exit);
        WaitForSingleObject(am_log_handle->reader_thr, INFINITE);
        log->owner = 0;
    }
    CloseHandle(am_log_lck.exit);
    CloseHandle(am_log_lck.new_data_cond);
    CloseHandle(am_log_lck.new_space_cond);
    CloseHandle(am_log_handle->reader_thr);

    WaitForSingleObject(am_log_lck.lock, INFINITE);
    /* close log file(s) */
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        struct log_files *f = &log->files[i];
        if (f->owner == pid) {
            if (f->fd_debug != -1) {
                _close(f->fd_debug);
                f->fd_debug = -1;
            }
            if (f->fd_audit != -1) {
                _close(f->fd_audit);
                f->fd_audit = -1;
            }
            f->used = AM_FALSE;
            f->instance_id = 0;
            f->owner = 0;
            f->level_debug = f->level_audit = AM_LOG_LEVEL_NONE;
            f->max_size_debug = f->max_size_audit = 0;
            break;
        }
    }
    ReleaseMutex(am_log_lck.lock);
    CloseHandle(am_log_lck.lock);
    UnmapViewOfFile(am_log_handle->area);
    CloseHandle(am_log_handle->area_file_id);
    am_log_lck.lock = NULL;
    am_log_lck.exit = NULL;
    am_log_lck.new_data_cond = NULL;
    am_log_lck.new_space_cond = NULL;
#else
    pthread_mutex_unlock(&log->exit);
    pthread_join(am_log_handle->reader_thr, NULL);
    pthread_mutex_destroy(&log->exit);
    pthread_mutex_destroy(&log->lock);
    pthread_cond_destroy(&log->new_data_cond);
    pthread_cond_destroy(&log->new_space_cond);
    /* close log file(s) */
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        struct log_files *f = &log->files[i];
        if (f->fd_debug != -1) {
            close(f->fd_debug);
            f->fd_debug = -1;
        }
        if (f->fd_audit != -1) {
            close(f->fd_audit);
            f->fd_audit = -1;
        }
        f->used = AM_FALSE;
        f->instance_id = 0;
        f->level_debug = f->level_audit = AM_LOG_LEVEL_NONE;
        f->max_size_debug = f->max_size_audit = 0;
    }
    if (munmap((char *) am_log_handle->area, am_log_handle->area_size) == -1) {
        fprintf(stderr, "am_log_shutdown() munmap failed (%d)\n", errno);
    }
    close(am_log_handle->area_file_id);
    if (shm_unlink(am_log_handle->area_file_name) == -1) {
        fprintf(stderr, "am_log_shutdown() shm_unlink failed (%d)\n", errno);
    }
#endif

    am_agent_instance_init_release(id, AM_TRUE);

    free(am_log_handle);
    am_log_handle = NULL;
}

int am_log_get_current_owner() {
    int rv = 0;
    struct am_log *log = AM_LOG();

    if (log == NULL) {
        return rv;
    }

#ifdef _WIN32
    WaitForSingleObject(am_log_lck.lock, INFINITE);
#else
    pthread_mutex_lock(&log->lock);
#endif
    rv = log->owner;
#ifdef _WIN32
    ReleaseMutex(am_log_lck.lock);
#else
    pthread_mutex_unlock(&log->lock);
#endif
    return rv;
}

/***************************************************************************/

void am_log_register_instance(unsigned long instance_id, const char *debug_log, int log_level, int log_size,
        const char *audit_log, int audit_level, int audit_size, const char *config_file) {
    int i, exist = AM_NOT_FOUND;
    struct am_log *log = AM_LOG();
    struct log_files *f = NULL;

    if (log == NULL || instance_id == 0 || ISINVALID(debug_log) || ISINVALID(audit_log)) {
        return;
    }

#ifdef _WIN32
    if (log->owner != getpid()) {
        am_re_init_worker();
    }
    WaitForSingleObject(am_log_lck.lock, INFINITE);
#else
    pthread_mutex_lock(&log->lock);
#endif
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        f = &log->files[i];
        if (f->instance_id == instance_id) {
            exist = AM_SUCCESS;
            break;
        }
    }
    if (exist == AM_NOT_FOUND) {
        for (i = 0; i < AM_MAX_INSTANCES; i++) {
            f = &log->files[i];
            if (!f->used) {
                f->instance_id = instance_id;
                strncpy(f->name_debug, debug_log, sizeof (f->name_debug) - 1);
                strncpy(f->name_audit, audit_log, sizeof (f->name_audit) - 1);
                f->used = AM_TRUE;

#define DEFAULT_LOG_SIZE (1024 * 1024 * 5) /* 5MB */

                f->max_size_debug = log_size > 0 && log_size < DEFAULT_LOG_SIZE ? DEFAULT_LOG_SIZE : log_size;
                f->max_size_audit = audit_size > 0 && audit_size < DEFAULT_LOG_SIZE ? DEFAULT_LOG_SIZE : audit_size;
                f->level_debug = log_level;
                f->level_audit = audit_level;
                f->created_debug = f->created_audit = 0;
                f->owner = 0;
                exist = AM_DONE;
                break;
            }
        }

        /* register instance in valid-url-index table */
        if (ISVALID(config_file)) {
            for (i = 0; i < AM_MAX_INSTANCES; i++) {
                struct valid_url *vf = &log->valid[i];
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
#ifdef _WIN32
    ReleaseMutex(am_log_lck.lock);
#else
    pthread_mutex_unlock(&log->lock);
#endif
    if (exist == AM_DONE) {
#define AM_LOG_HEADER "\r\n\r\n\t######################################################\r\n\t# %-51s#\r\n\t# Version: %-42s#\r\n\t# %-51s#\r\n\t# Build date: %s %-27s#\r\n\t######################################################\r\n"

        AM_LOG_ALWAYS(instance_id, AM_LOG_HEADER, DESCRIPTION, VERSION,
                VERSION_VCS, __DATE__, __TIME__);

        am_agent_init_set_value(instance_id, AM_TRUE, AM_UNKNOWN);
    }
}

/***************************************************************************/

int get_valid_url_index(unsigned long instance_id) {
    int i, value = 0;
    struct am_log *log = AM_LOG();

    if (log == NULL) {
        return value;
    }

#ifdef _WIN32
    WaitForSingleObject(am_log_lck.lock, INFINITE);
#else
    pthread_mutex_lock(&log->lock);
#endif
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        if (log->valid[i].instance_id == instance_id) {
            value = log->valid[i].url_index;
            break;
        }
    }
#ifdef _WIN32
    ReleaseMutex(am_log_lck.lock);
#else
    pthread_mutex_unlock(&log->lock);
#endif
    return value;
}

int get_valid_url_all(struct url_validator_worker_data *list) {
    int i, j = 0;
    struct am_log *log = AM_LOG();

    if (log == NULL || list == NULL) {
        return AM_EINVAL;
    }

#ifdef _WIN32
    WaitForSingleObject(am_log_lck.lock, INFINITE);
#else
    pthread_mutex_lock(&log->lock);
#endif
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        if (log->valid[i].instance_id > 0 && ISVALID(log->valid[i].config_path)) {
            list[j].instance_id = log->valid[i].instance_id;
            list[j].url_index = log->valid[i].url_index;
            list[j].last = log->valid[i].last;
            list[j].running = log->valid[i].running;
            list[j].config_path = strdup(log->valid[i].config_path);
            j++;
        }
    }
#ifdef _WIN32
    ReleaseMutex(am_log_lck.lock);
#else
    pthread_mutex_unlock(&log->lock);
#endif
    return j > 0 ? AM_SUCCESS : AM_NOT_FOUND;
}

/***************************************************************************/

void set_valid_url_index(unsigned long instance_id, int value) {
    int i;
    struct am_log *log = AM_LOG();

    if (log == NULL) {
        return;
    }

#ifdef _WIN32
    WaitForSingleObject(am_log_lck.lock, INFINITE);
#else
    pthread_mutex_lock(&log->lock);
#endif
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        struct valid_url *vf = &log->valid[i];
        if (vf->instance_id == instance_id) {
            vf->url_index = value;
            vf->last = time(NULL);
            break;
        }
    }
#ifdef _WIN32
    ReleaseMutex(am_log_lck.lock);
#else
    pthread_mutex_unlock(&log->lock);
#endif
}

void set_valid_url_instance_running(unsigned long instance_id, int value) {
    int i;
    struct am_log *log = AM_LOG();

    if (log == NULL) {
        return;
    }

#ifdef _WIN32
    WaitForSingleObject(am_log_lck.lock, INFINITE);
#else
    pthread_mutex_lock(&log->lock);
#endif
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        struct valid_url *vf = &log->valid[i];
        if (vf->instance_id == instance_id) {
            vf->running = value;
            break;
        }
    }
#ifdef _WIN32
    ReleaseMutex(am_log_lck.lock);
#else
    pthread_mutex_unlock(&log->lock);
#endif
}

int am_agent_instance_init_init(int id) {
    int status = AM_ERROR;
#if defined(_WIN32)
    SECURITY_DESCRIPTOR sec_descr;
    SECURITY_ATTRIBUTES sec_attr, *sec = NULL;

    if (InitializeSecurityDescriptor(&sec_descr, SECURITY_DESCRIPTOR_REVISION) &&
            SetSecurityDescriptorDacl(&sec_descr, TRUE, (PACL) NULL, FALSE)) {
        sec_attr.nLength = sizeof (SECURITY_ATTRIBUTES);
        sec_attr.lpSecurityDescriptor = &sec_descr;
        sec_attr.bInheritHandle = TRUE;
        sec = &sec_attr;
    }

    ic_sem = CreateSemaphoreA(sec, 1, 1, get_global_name("Global\\"AM_CONFIG_INIT_NAME, id));
    if (ic_sem != NULL) {
        status = AM_SUCCESS;
    }
#elif defined(__APPLE__)
    kern_return_t rv = semaphore_create(mach_task_self(), &ic_sem, SYNC_POLICY_FIFO, 1);
    if (rv == KERN_SUCCESS) {
        status = AM_SUCCESS;
    }
#else
    ic_sem = sem_open(get_global_name(
#ifdef __sun
            "/"AM_CONFIG_INIT_NAME
#else
            AM_CONFIG_INIT_NAME
#endif
            , id), O_CREAT, 0600, 1);
    if (ic_sem != SEM_FAILED) {
        status = AM_SUCCESS;
    }
#endif
    return status;
}

void am_agent_instance_init_lock() {
#if defined(_WIN32)
    WaitForSingleObject(ic_sem, INFINITE);
#elif defined(__APPLE__)
    semaphore_wait(ic_sem);
#else
    sem_wait(ic_sem);
#endif 
}

void am_agent_instance_init_unlock() {
#if defined(_WIN32)
    ReleaseSemaphore(ic_sem, 1, NULL);
#elif defined(__APPLE__)
    semaphore_signal_all(ic_sem);
#else
    sem_post(ic_sem);
#endif 
}

void am_agent_instance_init_release(int id, char unlink) {
#if defined(_WIN32)
    CloseHandle(ic_sem);
#elif defined(__APPLE__)
    semaphore_destroy(mach_task_self(), ic_sem);
#else
    sem_close(ic_sem);
    if (unlink) {
        sem_unlink(get_global_name(
#ifdef __sun
                "/"AM_CONFIG_INIT_NAME
#else
                AM_CONFIG_INIT_NAME
#endif
                , id));
    }
#endif
}

void am_agent_init_set_value(unsigned long instance_id, char lock, int val) {
    int i;
    struct am_log *log = AM_LOG();

    if (log == NULL) {
        return;
    }

    if (lock) {
        am_agent_instance_init_lock();
    }
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        if (val == AM_UNKNOWN) {
            /* find first empty slot */
            if (log->init[i].instance_id == 0) {
                log->init[i].in_progress = 0;
                log->init[i].instance_id = instance_id;
                break;
            }
        } else {
            /* set/reset status value */
            if (log->init[i].instance_id == instance_id) {
                log->init[i].in_progress = val;
                break;
            }
        }
    }
    if (lock) {
        am_agent_instance_init_unlock();
    }
}

int am_agent_init_get_value(unsigned long instance_id, char lock) {
    int i, status = AM_FALSE;
    struct am_log *log = AM_LOG();

    if (log == NULL) {
        return status;
    }

    if (lock) {
        am_agent_instance_init_lock();
    }
    for (i = 0; i < AM_MAX_INSTANCES; i++) {
        /* get status value */
        if (log->init[i].instance_id == instance_id) {
            status = log->init[i].in_progress;
            break;
        }
    }
    if (lock) {
        am_agent_instance_init_unlock();
    }
    return status;
}

/**
 * This function gives controlled access to the flag which says whether to log or not when
 * there is no instance id.  This happens when we are running test cases and/or when we are
 * running the installation code.
 *
 * @param wanted true to enable zero instance id logging, false to disable
 * @return the previous value of the flag.
 */
am_bool_t zero_instance_logging_wanted(am_bool_t wanted) {
    am_bool_t result = zero_instance_logging_is_wanted;
    zero_instance_logging_is_wanted = wanted;
    return result;
}

