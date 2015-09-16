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
#include <setjmp.h>

#include "platform.h"
#include "am.h"
#include "utility.h"
#include "net_client.h"
#include "thread.h"
#include "cmocka.h"

void am_net_init_ssl_reset();

static void install_log(const char *format, ...) {
    char ts[64];
    struct tm now;
#ifdef _WIN32
    FILE *f = fopen("c:\\windows\\temp\\test.log", "a+");
    time_t tv;
    time(&tv);
    localtime_s(&now, &tv);
#else
    FILE *f = fopen("/tmp/test.log", "a+");
    struct timeval tv;
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &now);
#endif
    strftime(ts, sizeof (ts) - 1, "%Y-%m-%d %H:%M:%S", &now);
    if (f != NULL) {
        va_list args;
        fprintf(f, "%s  ", ts);
        va_start(args, format);
        vfprintf(f, format, args);
        va_end(args);
        fprintf(f, "\n");
        fclose(f);
    }
}

void test_single_request(void **state) {
    int rv;
    const char *openam_url = "https://am.example.com:443/am";
    int httpcode = 0;
    am_net_options_t net_options;

    memset(&net_options, 0, sizeof (am_net_options_t));
    net_options.keepalive = net_options.local = net_options.cert_trust = AM_TRUE;
    net_options.log = install_log;

    am_net_init();

    rv = am_url_validate(0, openam_url, &net_options, &httpcode);

    am_net_options_delete(&net_options);

    assert_int_equal(rv, AM_SUCCESS);

    am_net_shutdown();
    am_net_init_ssl_reset();

    fprintf(stderr, "STATUS: %s\n", am_strerror(rv));
    fprintf(stderr, "HTTP STATUS: %d\n", httpcode);
}

void test_multiple_requests(void **state) {
    int rv;
    const char *openam_url = "https://am.example.com:443/am";
    const char *agent_user = "agent";
    const char *agent_password = "password";
    const char *agent_realm = "/";
    char *agent_token = NULL;
    am_net_options_t net_options;

    memset(&net_options, 0, sizeof (am_net_options_t));
    net_options.keepalive = net_options.local = net_options.cert_trust = AM_TRUE;
    net_options.log = install_log;

    am_net_init();

    rv = am_agent_login(0, openam_url, agent_user, agent_password, agent_realm, &net_options,
            &agent_token, NULL, NULL, NULL);

    fprintf(stderr, "LOGIN STATUS: %s\n", am_strerror(rv));
    assert_int_equal(rv, AM_SUCCESS);

    if (agent_token != NULL) {
        rv = am_agent_logout(0, openam_url, agent_token, &net_options);

        fprintf(stderr, "LOGOUT STATUS: %s\n", am_strerror(rv));
        assert_int_equal(rv, AM_SUCCESS);
    }
    am_net_options_delete(&net_options);

    am_net_shutdown();
    am_net_init_ssl_reset();

    fprintf(stderr, "TOKEN: %s\n", LOGEMPTY(agent_token));
    am_free(agent_token);
}
