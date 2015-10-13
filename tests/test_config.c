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
#include <stdint.h>
#include <setjmp.h>

#include "am.h"
#include "platform.h"
#include "utility.h"
#include "log.h"
#include "cmocka.h"

void test_config_url_maps(void **state) {
    int i;
    am_config_t * conf;
    char *value;
    
    char buffer [] = "config-tests-XXXXXXX";
    char *path = mktemp(buffer);
    
    char *configs =
    "com.sun.identity.agents.config.repository.location = local\n"
    
    "com.sun.identity.agents.config.notenforced.regex.enable = false\n"
    "com.sun.identity.agents.config.notenforced.url[0] = http://a.b.c/path\n"
    "com.sun.identity.agents.config.notenforced.url[1] = https://a.b.c:1234/path\n"
    
    "org.forgerock.agents.config.notenforced.ext.regex.enable = false\n"
    "org.forgerock.agents.config.notenforced.ipurl[0] = http://a.b.c/path\n"
    "org.forgerock.agents.config.notenforced.ipurl[1] = https://a.b.c/path\n"
    
    "org.forgerock.agents.config.logout.regex.enable = false\n"
    "com.sun.identity.agents.config.agent.logout.url[0]= http://a.b.c/path\n"
    "com.sun.identity.agents.config.agent.logout.url[1]= https://a.b.c/path\n"
    
    "org.forgerock.agents.config.json.url[0] = http://a.b.c/path\n"
    "org.forgerock.agents.config.json.url[1] = https://a.b.c/path\n"
    "";
    
    write_file(path, configs, strlen(configs));
    conf = am_get_config_file(1, path);
    
    assert_int_equal(!conf->not_enforced_regex_enable, AM_TRUE);
    assert_int_equal(conf->not_enforced_map_sz, 2);
    assert_string_equal(conf->not_enforced_map[0].value, "http://a.b.c:80/path");
    assert_string_equal(conf->not_enforced_map[1].value, "https://a.b.c:1234/path");
    
    assert_int_equal(!conf->not_enforced_ext_regex_enable, AM_TRUE);
    assert_int_equal(conf->not_enforced_ext_map_sz, 2);
    assert_string_equal(conf->not_enforced_ext_map[0].value, "http://a.b.c:80/path");
    assert_string_equal(conf->not_enforced_ext_map[1].value, "https://a.b.c:443/path");
    
    assert_int_equal(!conf->logout_regex_enable, AM_TRUE);
    assert_int_equal(conf->logout_map_sz, 2);
    assert_string_equal(conf->logout_map[0].value, "http://a.b.c:80/path");
    assert_string_equal(conf->logout_map[1].value, "https://a.b.c:443/path");
    
    assert_int_equal(conf->json_url_map_sz, 2);
    assert_string_equal(conf->json_url_map[0].value, "http://a.b.c:80/path");
    assert_string_equal(conf->json_url_map[1].value, "https://a.b.c:443/path");

    unlink(path);
}

void test_config_map_value_reorder(void **state) {
    am_config_t conf;
#define MAP_SIZE 3
    am_config_map_t *map = calloc(MAP_SIZE, sizeof (am_config_map_t));
    
    assert_non_null(map);
    
    memset(&conf, 0, sizeof (am_config_t));
    conf.login_url = map;
    conf.login_url_sz = MAP_SIZE;

    map[0].name = strdup("2");
    map[0].value = strdup("test 2");
    map[1].name = strdup("10");
    map[1].value = strdup("test 10");
    map[2].name = strdup("0");
    map[2].value = strdup("test 0");

    update_agent_configuration_reorder_map_values(&conf);

    assert_string_equal(map[2].name, "10");
    assert_string_equal(map[2].value, "test 10");

    free(map[0].name);
    free(map[0].value);
    free(map[1].name);
    free(map[1].value);
    free(map[2].name);
    free(map[2].value);
    free(map);
}
