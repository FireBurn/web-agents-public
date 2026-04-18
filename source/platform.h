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

#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <iphlpapi.h>
#include <malloc.h>
#include <math.h>
#include <process.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <time.h>
#include <wincrypt.h>
#include <windns.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>

#if (_MSC_VER < 1900)
#define snprintf am_snprintf
#define vsnprintf am_vsnprintf
#endif
#define mkdir(a, b) _mkdir(a)
#define getpid GetCurrentProcessId
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define unlink _unlink
#define sleep(x) SleepEx(x * 1000, FALSE)
#define localtime_r(a, b) localtime_s(b, a)
#define strtok_r strtok_s
#define sockpoll WSAPoll
#define SOCKLEN_T int
#define pid_t int
typedef SSIZE_T ssize_t;
typedef long uid_t;
typedef long gid_t;
#define INETPTON InetPton
#define INETNTOP InetNtop

#if (_MSC_VER < 1800)
#define va_copy(dst, src) ((void)((dst) = (src)))
#endif
#ifndef S_ISDIR
#define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)
#endif
#define FILE_PATH_SEP "\\"
#define AM_GLOBAL_PREFIX "Global\\"

#define PR_L64 "I64d"

#else /* _WIN32 */

#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#if defined(__sun) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#include <sys/mman.h>
#include <sys/shm.h>
#undef _POSIX_C_SOURCE
#else
#include <sys/mman.h>
#include <sys/shm.h>
#endif /* __sun, etc. */

#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <ftw.h>
#include <grp.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <semaphore.h>
#include <signal.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/poll.h>
#include <sys/sem.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/time.h>

#ifdef __APPLE__
#include <copyfile.h>
#include <mach-o/dyld.h>
#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/semaphore.h>
#include <mach/task.h>
#include <sys/event.h>
#include <sys/uio.h>
#else
#ifndef AIX
#include <sys/sendfile.h>
#endif
#endif /* __APPLE */

#define sockpoll poll
#define SOCKLEN_T socklen_t
#define INETPTON inet_pton
#define INETNTOP inet_ntop
#define FILE_PATH_SEP "/"
#define AM_GLOBAL_PREFIX ""

#define PR_L64 PRId64

#endif /* _WIN32 */

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#endif /* PLATFORM_H */
