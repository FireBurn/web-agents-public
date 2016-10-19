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
 * Copyright 2016 ForgeRock AS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include "platform.h"
#include "am.h"
#include "utility.h"
#include "list.h"
#include "thread.h"
#include "cmocka.h"

struct am_audit_transfer {
    unsigned long instance_id;
    char *message;
    char *server_id;
    char *config_file;
};

#define INSTANCE_ID 1
#define NUM_ENTRIES 4500 /* this value will require one shared memory resize op */
#define MESSAGE_TEMPLATE "user %d - got access ticket"

static int proc = 0;

am_status_t extract_audit_entries(unsigned long instance_id,
        am_status_t(*callback)(const char *openam, int count, struct am_audit_transfer *batch));

static am_status_t write_entries_to_server(const char *openam, int count, struct am_audit_transfer *batch) {
    int msg_size, i;
    unsigned long instance_id;
    char *server_id = NULL, *msg = NULL, *config_file = NULL;

    for (i = 0; i < count; i++) {
        if (msg == NULL) {
            server_id = batch[i].server_id;
            instance_id = batch[i].instance_id;
            config_file = batch[i].config_file;
            msg_size = am_asprintf(&msg, batch[i].message, i + 1, "");
        } else {
            msg_size = am_asprintf(&msg, batch[i].message, i + 1, msg);
        }
    }
    AM_FREE(msg);

    proc += count;

#define WRITE_TEST_SLEEP 1000 /* msec */
#ifdef _WIN32
    SleepEx(WRITE_TEST_SLEEP, FALSE)
#else
    usleep(WRITE_TEST_SLEEP * 1000);
#endif
    return AM_SUCCESS;
}

void test_audit_shm(void **state) {
    int i;
    am_config_t conf;
    char *am[] = {"http://localhost/am"};
    memset(&conf, 0, sizeof (am_config_t));
    conf.instance_id = INSTANCE_ID;
    conf.config = "agent.conf";
    conf.naming_url_sz = 1;
    conf.naming_url = am;

    assert_int_equal(am_audit_init(AM_DEFAULT_AGENT_ID), AM_SUCCESS);
    assert_int_equal(am_audit_register_instance(&conf), AM_SUCCESS);

    printf("adding %d entries\n", NUM_ENTRIES);

    for (i = 0; i < NUM_ENTRIES; i++) {
        assert_int_equal(am_add_remote_audit_entry(INSTANCE_ID, "AGENT_TOKEN", "01", "remote-file.log",
                "USER_TOKEN", MESSAGE_TEMPLATE, i), AM_SUCCESS);
    }

    extract_audit_entries(INSTANCE_ID, write_entries_to_server);
    printf("extracted %d entries\n", proc);

    assert_int_equal(proc, NUM_ENTRIES);

    am_audit_shutdown();
}
