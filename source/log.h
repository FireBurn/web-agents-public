// SPDX-License-Identifier: CDDL-1.0
//
// Copyright 2014-2015 ForgeRock AS.
// Copyright 2018-2026 Open Identity Platform Community.

#ifndef LOG_H
#define LOG_H

#ifndef INTEGRATION_TEST

int perform_logging(unsigned long instance_id, int level);
void am_log_write(unsigned long instance_id, int level, const char *header, int header_sz, const char *format, ...);
char *log_header(int log_level, int *header_sz, const char *file, int line);

#define AM_LOG_ALWAYS(instance, format, ...)                                                                           \
    do {                                                                                                               \
        if (format != NULL) {                                                                                          \
            int header_sz;                                                                                             \
            char *header = log_header(AM_LOG_LEVEL_ALWAYS, &header_sz, __FILE__, __LINE__);                            \
            am_log_write(instance, AM_LOG_LEVEL_ALWAYS, header, header_sz, format, ##__VA_ARGS__);                     \
        }                                                                                                              \
    } while (0)

#define AM_LOG_INFO(instance, format, ...)                                                                             \
    do {                                                                                                               \
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_INFO)) {                                          \
            int header_sz;                                                                                             \
            char *header = log_header(AM_LOG_LEVEL_INFO, &header_sz, __FILE__, __LINE__);                              \
            am_log_write(instance, AM_LOG_LEVEL_INFO, header, header_sz, format, ##__VA_ARGS__);                       \
        }                                                                                                              \
    } while (0)

#define AM_LOG_WARNING(instance, format, ...)                                                                          \
    do {                                                                                                               \
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_WARNING)) {                                       \
            int header_sz;                                                                                             \
            char *header = log_header(AM_LOG_LEVEL_WARNING, &header_sz, __FILE__, __LINE__);                           \
            am_log_write(instance, AM_LOG_LEVEL_WARNING, header, header_sz, format, ##__VA_ARGS__);                    \
        }                                                                                                              \
    } while (0)

#define AM_LOG_ERROR(instance, format, ...)                                                                            \
    do {                                                                                                               \
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_ERROR)) {                                         \
            int header_sz;                                                                                             \
            char *header = log_header(AM_LOG_LEVEL_ERROR, &header_sz, __FILE__, __LINE__);                             \
            am_log_write(instance, AM_LOG_LEVEL_ERROR, header, header_sz, format, ##__VA_ARGS__);                      \
        }                                                                                                              \
    } while (0)

#define AM_LOG_DEBUG(instance, format, ...)                                                                            \
    do {                                                                                                               \
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_DEBUG)) {                                         \
            int header_sz;                                                                                             \
            char *header = log_header(AM_LOG_LEVEL_DEBUG, &header_sz, __FILE__, __LINE__);                             \
            am_log_write(instance, AM_LOG_LEVEL_DEBUG, header, header_sz, format, ##__VA_ARGS__);                      \
        }                                                                                                              \
    } while (0)

#define AM_LOG_AUDIT(instance, format, ...)                                                                            \
    do {                                                                                                               \
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_AUDIT)) {                                         \
            int header_sz;                                                                                             \
            char *header = log_header(AM_LOG_LEVEL_AUDIT, &header_sz, __FILE__, __LINE__);                             \
            am_log_write(instance, AM_LOG_LEVEL_AUDIT, header, header_sz, format, ##__VA_ARGS__);                      \
        }                                                                                                              \
    } while (0)

#else /* INTEGRATION_TEST */
#include <stdio.h>

#define AM_LOG_DEBUG(instance, format, ...)                                                                            \
    do {                                                                                                               \
        printf(format "\n", ##__VA_ARGS__);                                                                            \
    } while (0)

#define AM_LOG_ERROR(instance, format, ...)                                                                            \
    do {                                                                                                               \
        printf(format "\n", ##__VA_ARGS__);                                                                            \
    } while (0)

#endif /* INTEGRATION_TEST */

#endif /* LOG_H */
