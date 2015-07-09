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

#ifndef LOG_H
#define LOG_H

int perform_logging(unsigned long instance_id, int level);
void am_log_write(unsigned long instance_id, int level, const char* header, int header_sz, const char *format, ...);
am_bool_t zero_instance_logging_wanted(am_bool_t wanted);

#ifdef _WIN32
#define AM_LOG_ALWAYS(instance, format, ...)\
    do {\
        if (format != NULL) {\
            char header[128];\
            char time_string[25];\
            char tze[6];\
            int header_sz, minutes;\
            TIME_ZONE_INFORMATION tz;\
            SYSTEMTIME st;\
            GetLocalTime(&st);\
            GetTimeZoneInformation(&tz);\
            GetTimeFormatA(LOCALE_USER_DEFAULT, TIME_NOTIMEMARKER | TIME_FORCE24HOURFORMAT, &st,\
                   "HH':'mm':'ss", time_string, sizeof(time_string));\
            minutes = -(tz.Bias);\
            sprintf_s(tze, sizeof(tze), "%03d%02d", minutes / 60, abs(minutes % 60));\
            if (*tze == '0') {\
                *tze = '+';\
            }\
            header_sz = sprintf_s(header, sizeof(header), "%04d-%02d-%02d %s.%03d %s INFO [%d:%d] ",\
                      st.wYear, st.wMonth, st.wDay, time_string, st.wMilliseconds, tze,\
                      GetCurrentThreadId(), _getpid());\
            am_log_write(instance, AM_LOG_LEVEL_ALWAYS, header, header_sz, format, ##__VA_ARGS__);\
        }\
    } while (0)
#else
#define AM_LOG_ALWAYS(instance, format, ...)\
    do {\
        if (format != NULL) {\
            char header[128];\
            char time_string[25];\
            char tz[8];\
            int header_sz;\
            struct tm now;\
            struct timeval tv;\
            gettimeofday(&tv, NULL);\
            localtime_r(&tv.tv_sec, &now);\
            strftime(time_string, sizeof (time_string) - 1, "%Y-%m-%d %H:%M:%S", &now);\
            strftime(tz, sizeof (tz) - 1, "%z", &now);\
            header_sz = snprintf(header, sizeof(header), "%s.%03ld %s INFO [%p:%d] ", \
                time_string, tv.tv_usec / 1000L, tz, (void *)(uintptr_t)pthread_self(), \
                getpid());\
            am_log_write(instance, AM_LOG_LEVEL_ALWAYS, header, header_sz, format, ##__VA_ARGS__);\
        }\
    } while (0)
#endif

#ifdef _WIN32
#define AM_LOG_INFO(instance, format, ...) \
    do {\
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_INFO)) {\
            char header[128];\
            char time_string[25];\
            char tze[6];\
            int header_sz, minutes;\
            TIME_ZONE_INFORMATION tz;\
            SYSTEMTIME st;\
            GetLocalTime(&st);\
            GetTimeZoneInformation(&tz);\
            GetTimeFormatA(LOCALE_USER_DEFAULT, TIME_NOTIMEMARKER | TIME_FORCE24HOURFORMAT, &st,\
                "HH':'mm':'ss", time_string, sizeof (time_string));\
            minutes = -(tz.Bias);\
            sprintf_s(tze, sizeof (tze), "%03d%02d", minutes / 60, abs(minutes % 60));\
            if (*tze == '0') {\
                *tze = '+';\
            }\
            header_sz = sprintf_s(header, sizeof(header), "%04d-%02d-%02d %s.%03d %s INFO [%d:%d] ",\
                              st.wYear, st.wMonth, st.wDay, time_string, st.wMilliseconds, tze, \
                              GetCurrentThreadId(), _getpid());\
            am_log_write(instance, AM_LOG_LEVEL_INFO, header, header_sz, format, ##__VA_ARGS__);\
        }\
    } while (0)
#else
#define AM_LOG_INFO(instance, format, ...) \
    do {\
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_INFO)) {\
            char header[128];\
            char time_string[25];\
            char tz[8];\
            int header_sz;\
            struct tm now;\
            struct timeval tv;\
            gettimeofday(&tv, NULL);\
            localtime_r(&tv.tv_sec, &now);\
            strftime(time_string, sizeof(time_string) - 1, "%Y-%m-%d %H:%M:%S", &now);\
            strftime(tz, sizeof(tz) - 1, "%z", &now);\
            header_sz = snprintf(header, sizeof(header), "%s.%03ld %s INFO [%p:%d] ", \
                time_string, tv.tv_usec / 1000L, tz, (void *)(uintptr_t)pthread_self(), \
                getpid());\
            am_log_write(instance, AM_LOG_LEVEL_INFO, header, header_sz, format, ##__VA_ARGS__);\
        }\
    } while (0)
#endif

#ifdef _WIN32
#define AM_LOG_WARNING(instance, format, ...) \
    do {\
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_WARNING)) {\
            char header[128];\
            char time_string[25];\
            char tze[6];\
            int header_sz, minutes;\
            TIME_ZONE_INFORMATION tz;\
            SYSTEMTIME st;\
            GetLocalTime(&st);\
            GetTimeZoneInformation(&tz);\
            GetTimeFormatA(LOCALE_USER_DEFAULT, TIME_NOTIMEMARKER | TIME_FORCE24HOURFORMAT, &st,\
                "HH':'mm':'ss", time_string, sizeof (time_string));\
            minutes = -(tz.Bias);\
            sprintf_s(tze, sizeof (tze), "%03d%02d", minutes / 60, abs(minutes % 60));\
            if (*tze == '0') {\
                *tze = '+';\
            }\
            header_sz = sprintf_s(header, sizeof(header), "%04d-%02d-%02d %s.%03d %s WARNING [%d:%d] ",\
                st.wYear, st.wMonth, st.wDay, time_string, st.wMilliseconds, tze, \
                GetCurrentThreadId(), _getpid());\
            am_log_write(instance, AM_LOG_LEVEL_WARNING, header, header_sz, format, ##__VA_ARGS__);\
        }\
    } while (0)
#else
#define AM_LOG_WARNING(instance, format, ...) \
    do {\
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_WARNING)) {\
            char header[128];\
            char time_string[25];\
            char tz[8];\
            int header_sz;\
            struct tm now;\
            struct timeval tv;\
            gettimeofday(&tv, NULL);\
            localtime_r(&tv.tv_sec, &now);\
            strftime(time_string, sizeof (time_string) - 1, "%Y-%m-%d %H:%M:%S", &now);\
            strftime(tz, sizeof (tz) - 1, "%z", &now);\
            header_sz = snprintf(header, sizeof(header), "%s.%03ld %s WARNING [%p:%d] ", \
                time_string, tv.tv_usec / 1000L, tz, (void *)(uintptr_t)pthread_self(), \
                getpid());\
            am_log_write(instance, AM_LOG_LEVEL_WARNING, header, header_sz, format, ##__VA_ARGS__);\
         }\
     } while (0)
#endif

#ifdef _WIN32
#define AM_LOG_ERROR(instance, format, ...) \
    do {\
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_ERROR)) {\
            char header[128];\
            char time_string[25];\
            char tze[6];\
            int header_sz, minutes;\
            TIME_ZONE_INFORMATION tz;\
            SYSTEMTIME st;\
            GetLocalTime(&st);\
            GetTimeZoneInformation(&tz);\
            GetTimeFormatA(LOCALE_USER_DEFAULT, TIME_NOTIMEMARKER | TIME_FORCE24HOURFORMAT, &st,\
                "HH':'mm':'ss", time_string, sizeof (time_string));\
            minutes = -(tz.Bias);\
            sprintf_s(tze, sizeof (tze), "%03d%02d", minutes / 60, abs(minutes % 60));\
            if (*tze == '0') {\
                *tze = '+';\
            }\
            header_sz = sprintf_s(header, sizeof(header), "%04d-%02d-%02d %s.%03d %s ERROR [%d:%d] ",\
                st.wYear, st.wMonth, st.wDay, time_string, st.wMilliseconds, tze, \
                GetCurrentThreadId(), _getpid());\
            am_log_write(instance, AM_LOG_LEVEL_ERROR, header, header_sz, format, ##__VA_ARGS__);\
        }\
    } while (0)
#else
#define AM_LOG_ERROR(instance, format, ...) \
    do {\
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_ERROR)) {\
            char header[128];\
            char time_string[25];\
            char tz[8];\
            int header_sz;\
            struct tm now;\
            struct timeval tv;\
            gettimeofday(&tv, NULL);\
            localtime_r(&tv.tv_sec, &now);\
            strftime(time_string, sizeof (time_string) - 1, "%Y-%m-%d %H:%M:%S", &now);\
            strftime(tz, sizeof (tz) - 1, "%z", &now);\
            header_sz = snprintf(header, sizeof(header), "%s.%03ld %s ERROR [%p:%d] ", \
                time_string, tv.tv_usec / 1000L, tz, (void *)(uintptr_t)pthread_self(), \
                getpid());\
            am_log_write(instance, AM_LOG_LEVEL_ERROR, header, header_sz, format, ##__VA_ARGS__);\
         }\
    }while (0)
#endif

#ifdef _WIN32
#define AM_LOG_DEBUG(instance, format, ...) \
    do {\
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_DEBUG)) {\
            char header[128];\
            char time_string[25];\
            char tze[6];\
            int header_sz, minutes;\
            TIME_ZONE_INFORMATION tz;\
            SYSTEMTIME st;\
            GetLocalTime(&st);\
            GetTimeZoneInformation(&tz);\
            GetTimeFormatA(LOCALE_USER_DEFAULT, TIME_NOTIMEMARKER | TIME_FORCE24HOURFORMAT, &st,\
                "HH':'mm':'ss", time_string, sizeof (time_string));\
            minutes = -(tz.Bias);\
            sprintf_s(tze, sizeof (tze), "%03d%02d", minutes / 60, abs(minutes % 60));\
            if (*tze == '0') {\
                *tze = '+';\
            }\
            header_sz = sprintf_s(header, sizeof(header), "%04d-%02d-%02d %s.%03d %s DEBUG [%d:%d][%s:%d] ",\
                              st.wYear, st.wMonth, st.wDay, time_string, st.wMilliseconds, tze, \
                              GetCurrentThreadId(), _getpid(), __FILE__, __LINE__);\
            am_log_write(instance, AM_LOG_LEVEL_DEBUG, header, header_sz, format, ##__VA_ARGS__);\
        }\
    } while (0)
#else
#define AM_LOG_DEBUG(instance, format, ...) \
    do {\
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_DEBUG)) {\
            char header[128];\
            char time_string[25];\
            char tz[8];\
            struct tm now;\
            int header_sz;\
            struct timeval tv;\
            gettimeofday(&tv, NULL);\
            localtime_r(&tv.tv_sec, &now);\
            strftime(time_string, sizeof (time_string) - 1, "%Y-%m-%d %H:%M:%S", &now);\
            strftime(tz, sizeof (tz) - 1, "%z", &now);\
            header_sz = snprintf(header, sizeof(header), "%s.%03ld %s DEBUG [%p:%d][%s:%d] ", \
                time_string, tv.tv_usec / 1000L, tz, (void *)(uintptr_t)pthread_self(), \
                getpid(), __FILE__, __LINE__);\
            am_log_write(instance, AM_LOG_LEVEL_DEBUG, header, header_sz, format, ##__VA_ARGS__);\
        }\
    } while (0)
#endif

#ifdef _WIN32
#define AM_LOG_AUDIT(instance, format, ...) \
    do {\
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_AUDIT)) {\
            char header[128];\
            char time_string[25];\
            char tze[6];\
            int header_sz, minutes;\
            TIME_ZONE_INFORMATION tz;\
            SYSTEMTIME st;\
            GetLocalTime(&st);\
            GetTimeZoneInformation(&tz);\
            GetTimeFormatA(LOCALE_USER_DEFAULT, TIME_NOTIMEMARKER | TIME_FORCE24HOURFORMAT, &st,\
                "HH':'mm':'ss", time_string, sizeof (time_string));\
            minutes = -(tz.Bias);\
            sprintf_s(tze, sizeof (tze), "%03d%02d", minutes / 60, abs(minutes % 60));\
            if (*tze == '0') {\
                *tze = '+';\
            }\
            header_sz = sprintf_s(header, sizeof(header), "%04d-%02d-%02d %s.%03d %s AUDIT [%d:%d] ",\
                st.wYear, st.wMonth, st.wDay, time_string, st.wMilliseconds, tze, \
                GetCurrentThreadId(), _getpid());\
            am_log_write(instance, AM_LOG_LEVEL_AUDIT, header, header_sz, format, ##__VA_ARGS__);\
        }\
    } while (0)
#else
#define AM_LOG_AUDIT(instance, format, ...) \
    do {\
        if (format != NULL && perform_logging(instance, AM_LOG_LEVEL_AUDIT)) {\
            char header[128];\
            char time_string[25];\
            char tz[8];\
            int header_sz;\
            struct tm now;\
            struct timeval tv;\
            gettimeofday(&tv, NULL);\
            localtime_r(&tv.tv_sec, &now);\
            strftime(time_string, sizeof (time_string) - 1, "%Y-%m-%d %H:%M:%S", &now);\
            strftime(tz, sizeof (tz) - 1, "%z", &now);\
            header_sz = snprintf(header, sizeof(header), "%s.%03ld %s AUDIT [%p:%d] ", \
                time_string, tv.tv_usec / 1000L, tz, (void *)(uintptr_t)pthread_self(), \
                getpid());\
            am_log_write(instance, AM_LOG_LEVEL_AUDIT, header, header_sz, format, ##__VA_ARGS__);\
        }\
    } while (0)
#endif

#endif
