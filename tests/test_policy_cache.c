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

void* am_parse_policy_xml(unsigned long instance_id, const char* xml, size_t xml_sz, int scope);
void am_worker_pool_init_reset();
void am_net_init_ssl_reset();

char* policy_xml = "<PolicyService version='1.0' revisionNumber='60'>"
    "<PolicyResponse requestId='4' issueInstant='1424783306343' >"
    " <ResourceResult name='http://vb2.local.com:80/testwebsite'>"
    "  <PolicyDecision>"
    "   <ResponseAttributes> <!-- these can have multiple (0..n) value elements -->"
    "    <AttributeValuePair>"
    "     <Attribute name='Attributes,key:0,0'/> <Value>Attributes,value:0,0,0</Value> <Value>Attributes,value:0,0,1</Value>"
    "     </AttributeValuePair>"
    "    <AttributeValuePair>"
    "     <Attribute name='Attributes,key:0,1'/> <Value>Attributes,value:0,1,0</Value>"
    "    </AttributeValuePair>"
    "   </ResponseAttributes>"

    "   <ActionDecision timeToLive='1234'> <!-- these can have no value elements, which defaults to ? -->"
    "    <AttributeValuePair>"
    "     <Attribute name='PUT'/> <Value>deny</Value>"
    "    </AttributeValuePair>"
    "    <Advices>"
    "     <AttributeValuePair>"
    "      <Attribute name='Advices,key:0,0'/> <Value>Advices,value:0,0,0</Value>"
    "     </AttributeValuePair>"
    "     <AttributeValuePair>"
    "      <Attribute name='Advices,key:0,1'/> <Value>Advices,value:0,1,0</Value>"
    "     </AttributeValuePair>"
    "    </Advices>"
    "   </ActionDecision>"

    "   <ActionDecision timeToLive='5678'>"
    "    <AttributeValuePair>"
    "     <Attribute name='GET'/> <Value>allow</Value>"
    "    </AttributeValuePair>"
    "    <Advices>"
    "     <AttributeValuePair>"
    "      <Attribute name='Advices,key:0,0'/> <Value>Advices,value:0,0,0</Value>"
    "     </AttributeValuePair>"
    "     <AttributeValuePair>"
    "      <Attribute name='Advices,key:0,1'/> <Value>Advices,value:0,1,0</Value>"
    "     </AttributeValuePair>"
    "    </Advices>"
    "    </ActionDecision>"

    "    <ActionDecision timeToLive='9012'>"
    "     <AttributeValuePair>"
    "      <Attribute name='POST'/> <Value>allow</Value>"
    "     </AttributeValuePair>"
    "     <Advices>"
    "      <AttributeValuePair>"
    "       <Attribute name='Advices,key:0,0'/> <Value>Advices,value:0,0,0</Value>"
    "      </AttributeValuePair>"
    "      <AttributeValuePair>"
    "       <Attribute name='Advices,key:0,1'/> <Value>Advices,value:0,1,0</Value>"
    "      </AttributeValuePair>"
    "      <AttributeValuePair>"
    "       <Attribute name='Advices,key:0,2'/> <Value>Advices,value:0,2,0</Value>"
    "      </AttributeValuePair>"
    "     </Advices>"
    "    </ActionDecision>"

    "    <ResponseDecisions>"
    "     <AttributeValuePair>"
    "      <Attribute name='Decision,key:0,0'/> <Value>Decision,value:0,0,0</Value>"
    "     </AttributeValuePair>"
    "     <AttributeValuePair>"
    "      <Attribute name='Decision,key:0,1'/> <Value>Decision,value:0,1,0</Value>"
    "     </AttributeValuePair>"
    "     <AttributeValuePair>"
    "      <Attribute name='Decision,key:0,2'/> <Value>Decision,value:0,2,0</Value>"
    "     </AttributeValuePair>"
    "    </ResponseDecisions>"
    "   </PolicyDecision>"
    " </ResourceResult>"
    "</PolicyResponse>"
    "</PolicyService>";


char* pll = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
    "<ResponseSet vers='1.0' svcid='poicy' reqid='48'>"
    "  <Response><![CDATA[%s]]></Response>"
    "</ResponseSet>";


static void test_namevalue_pair(const char* prefix, struct am_namevalue* nvp)
{
    int key_policy_seq, key_attr_seq;
    int value_policy_seq, value_attr_seq, value_value_seq;
    
    char* key_format = NULL;
    char* value_format = NULL;

    am_asprintf(&key_format, "%s%s", prefix, ",key:%d,%d");
    am_asprintf(&value_format, "%s%s", prefix, ",value:%d,%d,%d");
    
    assert_int_equal(sscanf(nvp->n, key_format, &key_policy_seq, &key_attr_seq), 2);
    assert_int_equal(sscanf(nvp->v, value_format, &value_policy_seq, &value_attr_seq, &value_value_seq), 3);
    assert_int_equal(key_policy_seq, value_policy_seq);
    assert_int_equal(key_attr_seq, value_attr_seq);
    
    free(key_format);
    free(value_format);
}

static int test_attributes(const char * prefix, struct am_namevalue * head)
{
    struct am_namevalue * nvp;
    int count = 0;
    for (nvp = head; nvp; nvp = nvp->next) {
        test_namevalue_pair(prefix, nvp);
        count++;
    }
    return count;
}

static void test_policy_structure(struct am_policy_result * result)
{
    struct am_policy_result* r = result;
    struct am_action_decision* ad = r != NULL ? r->action_decisions : NULL;
    
    assert_non_null(r);

    assert_string_equal(r->resource, "http://vb2.local.com:80/testwebsite");
    assert_int_equal(test_attributes("Attributes", r->response_attributes), 3);
    assert_int_equal(test_attributes("Decision", r->response_decisions), 3);
    
    assert_non_null(ad);
    
    assert_string_equal(am_method_num_to_str(ad->method), "PUT");
    assert_string_equal(ad->action ? "allow" : "deny", "deny");
    assert_int_equal(ad->ttl, 1234);
    assert_int_equal(test_attributes("Advices", ad->advices), 2);

    ad = ad->next;
    
    assert_non_null(ad);

    assert_string_equal(am_method_num_to_str(ad->method), "GET");
    assert_string_equal(ad->action ? "allow" : "deny", "allow");
    assert_int_equal(ad->ttl, 5678);
    
    assert_int_equal(test_attributes("Advices", ad->advices), 2);

    ad = ad->next;

    assert_non_null(ad);

    assert_string_equal(am_method_num_to_str(ad->method), "POST");
    assert_string_equal(ad->action ? "allow" : "deny", "allow");
    assert_int_equal(ad->ttl, 9012);
    assert_int_equal(test_attributes("Advices", ad->advices), 3);

    delete_am_policy_result_list(&result);
}

/***************************************************************************************************/

void test_policy_result_reader(void **state) {

    size_t size;
    char* buffer = NULL;
    struct am_policy_result* result;

    am_asprintf(&buffer, pll, policy_xml);
    size = strlen(pll);
    result = am_parse_policy_xml(0l, buffer, size, 0);

    free(buffer);

    test_policy_structure(result);
}


void test_policy_cache_simple(void **state) {
    
    am_config_t config;
    am_request_t request;
    char* buffer = NULL;
    struct am_policy_result * result;
    time_t ets;
    struct am_policy_result * r = NULL;
    struct am_namevalue * session = NULL;
    
    memset(&config, 0, sizeof(am_config_t));
    memset(&request, 0, sizeof(am_request_t));
    request.conf = &config;
    
    am_asprintf(&buffer, pll, policy_xml);
    result = am_parse_policy_xml(0l, buffer, strlen(buffer), 0);
    
    free(buffer);
    
    assert_int_equal(am_init(), AM_SUCCESS);
    am_init_worker();
        
    am_add_session_policy_cache_entry(&request, "Policy-key", result, NULL);
    am_get_session_policy_cache_entry(&request, "Policy-key", &r, &session, &ets);
    
    am_shutdown_worker();
    am_shutdown();
    am_worker_pool_init_reset();
    am_net_init_ssl_reset();
    
    test_policy_structure(r);
}


const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*";


void create_random_cache_key(char * buffer, size_t size)
{
    int i;
    size_t count = size - 1;
    size_t len = sizeof(alphabet) - 1;
    
    for (i = 0; i < count; i++) {
        buffer[i] = alphabet[rand() % len];
    }
    buffer[count] = 0;
}

static void test_cache(int test_size, am_request_t * request, struct am_policy_result * result)
{
    int i;
    char key[64];
    
    /* create initial entries */
    srand(543542);
    for(i = 0; i < test_size; i++) {
        create_random_cache_key(key, sizeof(key));
        assert_int_equal(am_add_session_policy_cache_entry(request, key, result, NULL), AM_SUCCESS);
    }
    
    /* should refresh the whole lot */
    srand(543542);
    for(i = 0; i < test_size; i++) {
        create_random_cache_key(key, sizeof(key));
        assert_int_equal(am_add_session_policy_cache_entry(request, key, result, NULL), AM_SUCCESS);
    }
    
    /* read them all back */
    srand(543542);
    for(i = 0; i < test_size; i++) {
        time_t ets;
        struct am_policy_result * r = NULL;
        struct am_namevalue * session = NULL;
        
        create_random_cache_key(key, sizeof(key));
        assert_int_equal(am_get_session_policy_cache_entry(request, key, &r, &session, &ets), AM_SUCCESS);
        test_policy_structure(r);
    }
}

static void test_cache_keys(int test_size, char** keys, am_request_t* request, struct am_policy_result* result)
{
    int i;

    /* create initial entries */
    for(i = 0; i < test_size; i++) {
        assert_int_equal(am_add_session_policy_cache_entry(request, keys [i], result, NULL), AM_SUCCESS);
    }
    
    /* should refresh the whole lot */
    for(i = 0; i < test_size; i++) {
        assert_int_equal(am_add_session_policy_cache_entry(request, keys [i], result, NULL), AM_SUCCESS);
    }
    
    /* read them all back */
    for(i = 0; i < test_size; i++) {
        time_t ets;
        struct am_policy_result * r = NULL;
        struct am_namevalue * session = NULL;
        
        assert_int_equal(am_get_session_policy_cache_entry(request, keys [i], &r, &session, &ets), AM_SUCCESS);
        test_policy_structure(r);
    }
}



void test_policy_cache_many_entries(void **state) {

    const int test_size = 198;
    char* buffer = NULL;
    struct am_policy_result * result;
    
    am_config_t config;
    am_request_t request;
    
    memset(&config, 0, sizeof(am_config_t));
    memset(&request, 0, sizeof(am_request_t));
    request.conf = &config;
    
    am_asprintf(&buffer, pll, policy_xml);
    result = am_parse_policy_xml(0l, buffer, strlen(buffer), 0);
    
    free(buffer);
    
    assert_int_equal(am_init(), AM_SUCCESS);
    am_init_worker();
        
    test_cache(test_size, &request, result);
    
    delete_am_policy_result_list(&result);
    
    am_shutdown_worker();
    am_shutdown();
    am_worker_pool_init_reset();
    am_net_init_ssl_reset();
}


struct test_cache_params {
    int test_size;
    char** keys;
    int iterations;
    am_request_t * request;
    struct am_policy_result * result;
};

static void* test_cache_procedure(void * params)
{
    int i;
    struct test_cache_params * p = params;

    for (i = 0; i < p->iterations; i++) {
        test_cache_keys(p->test_size, p->keys, p->request, p->result);
    }
    
    return 0;
}

void test_policy_cache_multithread() {
    
    am_config_t config;
    am_request_t request;
    char* buffer = NULL;
    struct am_policy_result* result;
    /* this must be slightly less than the maximum because re-use of shm chunks might use more space */
#define TEST_SIZE  195
    char* keys [TEST_SIZE];
    char key_buffer[64];
    int i;

    memset(&config, 0, sizeof (am_config_t));
    memset(&request, 0, sizeof (am_request_t));
    request.conf = &config;

    am_asprintf(&buffer, pll, policy_xml);
    result = am_parse_policy_xml(0l, buffer, strlen(buffer), 0);

    free(buffer);
    
    assert_non_null(result);
    
    if (result != NULL) {
        struct test_cache_params params = {
            .test_size = TEST_SIZE,
            .keys = keys,

            .iterations = 32,

            .request = &request,
            .result = result,
        };

        long t0 = clock();
#define NTHREADS 2
        am_thread_t threads [NTHREADS];
        double dt;
        
        for (i = 0; i < TEST_SIZE; i++) {
            create_random_cache_key(key_buffer, sizeof (key_buffer));
            keys[i] = strdup(key_buffer);
        }

        assert_int_equal(am_cache_init(), AM_SUCCESS);

        fprintf(stdout, "info: started multithreaded cache tests.. ");
        fflush(stdout);

        for (i = 0; i < NTHREADS; i++) {
            AM_THREAD_CREATE(threads[i], test_cache_procedure, &params);
        }

        for (i = 0; i < NTHREADS; i++) {
            AM_THREAD_JOIN(threads[i]);
        }

        dt = ((double) (clock() - t0)) / CLOCKS_PER_SEC;
        fprintf(stdout, "finished after %lf secs\n", dt);

        assert_int_equal(am_cache_shutdown(), AM_SUCCESS);

        delete_am_policy_result_list(&result);

        for (i = 0; i < TEST_SIZE; i++) {
            free(keys[i]);
        }
    }
}


/**
 * This is an internal test of the mechanism for replaying a given number of randomly generated strings
 */
void test_key_creation(void **state) {

#define TEST_SIZE_1 10
    char* keys[TEST_SIZE_1];
    char key[64];
    int i;
    
    srand(543542);
    for(i = 0; i < TEST_SIZE_1; i++) {
        create_random_cache_key(key, sizeof(key));
        keys[i] = strdup(key);
    }
    
    srand(543542);
    for(i = 0; i < TEST_SIZE_1; i++) {
        create_random_cache_key(key, sizeof(key));
        assert_string_equal(key, keys[i]);
    }
}
