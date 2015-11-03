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
 * Copyright 2015 ForgeRock AS.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <setjmp.h>

#include "platform.h"
#include "am.h"
#include "log.h"
#include "cmocka.h"

void am_worker_pool_init_reset();
void am_net_init_ssl_reset();

/**
 * This is the simplest of tests to check we can log things without crashing.
 *
 * In fact, because of the way logging works (differently) in test mode than it does in "agent mode"
 * all we're really doing here is to test that logging in test mode isn't broken.  This may or may not
 * bear any relation to whether logging works for the rest of the time.
 */
void test_logging_in_unit_test_mode(void** state) {
    
    static const char* text1 = "Now is the winter of our discontent,";
    static const char* text2 = "Made glorious summer by this son of York";
        
    AM_LOG_INFO(0, "instance id is zero and no args");
    AM_LOG_INFO(0, "instance id is zero and incorrect args", text1);
    AM_LOG_INFO(0, "instance id is zero and more incorrect args", text1, text2);

    /* we're testing this will not crash */
    AM_LOG_INFO(0, NULL, text1, text2);

    /* this will not appear, since the instance is greater than zero, but it should not crash either */
    AM_LOG_ERROR(10, "%s %s", text1, text2);

    AM_LOG_INFO(0, "%s %s", text1, text2);
    AM_LOG_WARNING(0, "%s %s", text1, text2);
    AM_LOG_ERROR(0, "%s %s", text1, text2);
    AM_LOG_DEBUG(0, "%s %s", text1, text2);
    AM_LOG_AUDIT(0, "%s %s", text1, text2);

    AM_LOG_ALWAYS(0, "%s %s", text1, text2);
    AM_LOG_ALWAYS(0, "Now %s the %s of our %s, %s summ%s of York",
                  "is",
                  "winter",
                  "discontent",
                  "Made glorious",
                  "er by this son");

    /* attempt to overflow the buffer, although this will be ultimately unsuccessful because the
     * logging works differently in unit test mode than it does in "real life" mode.
     */
    AM_LOG_ALWAYS(0, "\n"
                     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
                     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
                     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
                     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
                     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
                     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
                     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
                     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
                     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
                     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
                     "ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ");
}

/*************************************************************************************/

char log_file_name[20];
char audit_file_name[20];

#define ONE_K   1024
#define ONE_MB  1024 * 1024
#define TEN_MB  ONE_MB * 10

/**
 * Set up everything (shared memory, etc.) so we can log, just as we would if we were
 * really running (as opposed to running in test harness mode).
 */
void logging_setup(int logging_level) {
    
    // destroy the cache, if it exists
    am_cache_destroy();
    
    assert_int_equal(am_init(AM_DEFAULT_AGENT_ID, NULL), AM_SUCCESS);

    am_init_worker(AM_DEFAULT_AGENT_ID);
    
    sprintf(log_file_name, "log%d", rand() % 1000000);
    
    // Note that we need a valid audit file name, even though we never audit
    sprintf(audit_file_name, "aud%d", rand() % 1000000);
    
    am_log_register_instance(getpid(),
                             log_file_name, logging_level, TEN_MB,
                             audit_file_name, AM_LOG_LEVEL_AUDIT, ONE_MB, NULL);
    am_init_worker(AM_DEFAULT_AGENT_ID);
}

/**
 * Tear down everything after doing some logging.
 */
void logging_teardown() {
    am_log_shutdown(AM_DEFAULT_AGENT_ID);
    am_shutdown_worker();
    am_cache_destroy();
    am_worker_pool_init_reset();
    am_net_init_ssl_reset();
    unlink(log_file_name);
    unlink(audit_file_name);
}

/**
 * Validate that the specified file contains the specified string.  Very limited.  The
 * string searched for must occur entirely on a line and not span lines (if it does, it
 * won't be matched).
 *
 * @param log_file_name The log file name
 * @param text The text string to search for
 * @return 1 if present, 0 if not present
 */
int validate_contains(const char* file_name, const char* text) {
    FILE* fp;
    int result = 0;
    char line[10 * ONE_K];
    
    if ((fp = fopen(file_name, "r")) != NULL) {
        while (fgets(line, sizeof(line), fp) != NULL && result == 0) {
            result = strstr(line, text) != NULL;
        }
        fclose(fp);
    } else {
        fprintf(stderr, "Warning, failed to open log file %s\n", file_name);
    }
    return result;
}

/*************************************************************************************/

/**
 * Ensure that an impractically high log level we DO actually log text via AM_LOG_DEBUG.
 */
void test_log_debug_at_debug_level(void** state) {
    int result;
    const char* message = "Message written at DEBUG level.";

    srand(time(NULL));
    logging_setup(AM_LOG_LEVEL_AUDIT_DENY);
    AM_LOG_DEBUG(getpid(), message);
    sleep(5);
    result = validate_contains(log_file_name, message);
    logging_teardown();
    assert_int_equal(result, 1);
}

/**
 * Ensure that at warning log level we do NOT log something via AM_LOG_DEBUG.
 */
void test_log_debug_not_at_warning_level(void** state) {
    int result;
    const char* message = "Message written at DEBUG level.";

    logging_setup(AM_LOG_LEVEL_WARNING);
    AM_LOG_DEBUG(getpid(), message);
    sleep(5);
    result = validate_contains(log_file_name, message);
    logging_teardown();
    assert_int_equal(result, 0);
}

/**
 * Ensure that at warning log level we DO log something via AM_LOG_WARNING.
 */
void test_log_warning_at_warning_level(void** state) {
    int result;
    const char* message = "Message written at WARNING level.";

    logging_setup(AM_LOG_LEVEL_WARNING);
    AM_LOG_WARNING(getpid(), message);
    sleep(5);
    result = validate_contains(log_file_name, message);
    logging_teardown();
    assert_int_equal(result, 1);
}

