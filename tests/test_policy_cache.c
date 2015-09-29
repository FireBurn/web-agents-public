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
int am_purge_caches(time_t expiry_time);

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


char* policy_for_url =
    "<PolicyService version=\"1.0\" revisionNumber=\"60\">"
    "    <PolicyResponse requestId=\"4\" issueInstant=\"9999999999999\" >"
    "        <ResourceResult name=\"%s\">"
    "            <PolicyDecision>"
    "                <ResponseAttributes>"
    "                </ResponseAttributes>"
    "                <ActionDecision timeToLive=\"9999999999999999999\">"
    "                    <AttributeValuePair>"
    "                        <Attribute name=\"POST\"/>"
    "                        <Value>allow</Value>"
    "                    </AttributeValuePair>"
    "                    <Advices>"
    "                    </Advices>"
    "                </ActionDecision>"
    "                <ActionDecision timeToLive=\"9999999999999999999\">"
    "                    <AttributeValuePair>"
    "                        <Attribute name=\"PATCH\"/>"
    "                        <Value>allow</Value>"
    "                    </AttributeValuePair>"
    "                    <Advices>"
    "                    </Advices>"
    "                </ActionDecision>"
    "                <ActionDecision timeToLive=\"9999999999999999999\">"
    "                    <AttributeValuePair>"
    "                        <Attribute name=\"GET\"/>"
    "                        <Value>allow</Value>"
    "                    </AttributeValuePair>"
    "                    <Advices>"
    "                    </Advices>"
    "                </ActionDecision>"
    "                <ActionDecision timeToLive=\"9999999999999999999\">"
    "                    <AttributeValuePair>"
    "                        <Attribute name=\"DELETE\"/>"
    "                        <Value>allow</Value>"
    "                    </AttributeValuePair>"
    "                    <Advices>"
    "                    </Advices>"
    "                </ActionDecision>"
    "                <ActionDecision timeToLive=\"9999999999999999999\">"
    "                    <AttributeValuePair>"
    "                        <Attribute name=\"OPTIONS\"/>"
    "                        <Value>allow</Value>"
    "                    </AttributeValuePair>"
    "                    <Advices>"
    "                    </Advices>"
    "                </ActionDecision>"
    "                <ActionDecision timeToLive=\"9999999999999999999\">"
    "                    <AttributeValuePair>"
    "                        <Attribute name=\"HEAD\"/>"
    "                        <Value>allow</Value>"
    "                    </AttributeValuePair>"
    "                    <Advices>"
    "                    </Advices>"
    "                </ActionDecision>"
    "                <ActionDecision timeToLive=\"9999999999999999999\">"
    "                    <AttributeValuePair>"
    "                        <Attribute name=\"PUT\"/>"
    "                        <Value>allow</Value>"
    "                    </AttributeValuePair>"
    "                    <Advices>"
    "                    </Advices>"
    "                </ActionDecision>"
    "            </PolicyDecision>"
    "        </ResourceResult>"
    "   </PolicyResponse>"
    "</PolicyService>";


char* pll = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
    "<ResponseSet vers='1.0' svcid='poicy' reqid='48'>"
    "  <Response><![CDATA[%s]]></Response>"
    "</ResponseSet>";


/**
 * Substitute our chosen URL into the "policy for url" string above.  That way we can pretend
 * we're getting different responses for different URLs. All the values are "allow" anyway.
 */
static char* get_policy_for_url(const char* url) {
    char* buff1 = NULL;
    char* result = NULL;
    
    am_asprintf(&buff1, policy_for_url, url);
    if (buff1 == NULL) {
        return NULL;
    }
    
    am_asprintf(&result, pll, buff1);
    am_free(buff1);
    
    return result;
}

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
    
    // destroy the cache, if it exists
    am_cache_destroy();
    assert_int_equal(am_init(AM_DEFAULT_AGENT_ID), AM_SUCCESS);
    am_init_worker(AM_DEFAULT_AGENT_ID);
        
    am_add_session_policy_cache_entry(&request, "Policy-key", result, NULL);
    am_get_session_policy_cache_entry(&request, "Policy-key", &r, &session, &ets);
    
    am_shutdown_worker();
    am_cache_destroy();
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

static int test_cache_with_seed(int seed, int test_size, am_request_t * request, struct am_policy_result * result)
{
    int i;
    char key[4093*5];
    int capacity = test_size;
    
    /* create initial entries */
    srand(seed);
    for(i = 0; i < test_size; i++) {
        create_random_cache_key(key, sizeof(key));
        if (am_add_session_policy_cache_entry(request, key, result, NULL) != AM_SUCCESS) {
            printf("test_cache_with_seed: capacity is %d\n", i);
            capacity = i;
            break;
        }
        if (i % 1000 == 0)
            printf("loaded %d..\n", i);
    }
    
    /* should refresh the whole lot */
    srand(seed);
    for(i = 0; i < capacity; i++) {
        create_random_cache_key(key, sizeof(key));
        assert_int_equal(am_add_session_policy_cache_entry(request, key, result, NULL), AM_SUCCESS);

        if (i % 1000 == 0)
            printf("reloaded %d..\n", i);
    }
    
    /* read them all back */
    srand(seed);
    for(i = 0; i < capacity; i++) {
        time_t ets;
        struct am_policy_result * r = NULL;
        struct am_namevalue * session = NULL;
        
        create_random_cache_key(key, sizeof(key));
        assert_int_equal(am_get_session_policy_cache_entry(request, key, &r, &session, &ets), AM_SUCCESS);
        test_policy_structure(r);

        if (i % 1000 == 0)
            printf("read %d..\n", i);
    }
    return capacity;
}

static int test_cache(int test_size, am_request_t * request, struct am_policy_result * result) {
    return test_cache_with_seed(543542, test_size, request, result);
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
    
    // destroy the cache, if it exists
    am_cache_destroy();
    assert_int_equal(am_init(AM_DEFAULT_AGENT_ID), AM_SUCCESS);
    am_init_worker(AM_DEFAULT_AGENT_ID);
        
    test_cache(test_size, &request, result);
    
    delete_am_policy_result_list(&result);
    
    am_shutdown_worker();
    am_cache_destroy();
    am_worker_pool_init_reset();
    am_net_init_ssl_reset();
}

void test_policy_cache_purge_many_entries(void **state) {
    
    const int test_size = 1024;
    const int cache_valid_secs = 100;
    
    char* buffer = NULL;
    struct am_policy_result * result;
    int capacity;
    
    am_config_t config;
    am_request_t request;
    
    memset(&config, 0, sizeof(am_config_t));
    memset(&request, 0, sizeof(am_request_t));
    
    config.token_cache_valid = cache_valid_secs;
    request.conf = &config;
    
    am_asprintf(&buffer, pll, policy_xml);
    result = am_parse_policy_xml(0l, buffer, strlen(buffer), 0);
    
    free(buffer);
    
    // destroy the cache, if it exists
    am_cache_destroy();
    assert_int_equal(am_init(AM_DEFAULT_AGENT_ID), AM_SUCCESS);
    am_init_worker(AM_DEFAULT_AGENT_ID);
    
    capacity = test_cache(test_size, &request, result);
    assert_int_equal(am_purge_caches(time(NULL) + cache_valid_secs + 1), capacity);

    delete_am_policy_result_list(&result);
    
    am_shutdown_worker();
    am_cache_destroy();
    am_worker_pool_init_reset();
    am_net_init_ssl_reset();
}

void test_policy_cache_purge_during_insert(void **state) {
    const int test_size = 4096 * 10; // must be beyond the capacity
    const int cache_valid = 6000;    // must be large enough to not time out during inster phases
    
    char* buffer = NULL;
    struct am_policy_result * result;
    int loaded;
    time_t t0;
    long elapsed;

    am_config_t config;
    am_request_t request;
    
    memset(&config, 0, sizeof(am_config_t));
    config.token_cache_valid = cache_valid;
    memset(&request, 0, sizeof(am_request_t));
    request.conf = &config;
    
    am_asprintf(&buffer, pll, policy_xml);
    result = am_parse_policy_xml(0l, buffer, strlen(buffer), 0);
    free(buffer);
    
    // destroy the cache, if it exists
    am_cache_destroy();
    assert_int_equal(am_init(AM_DEFAULT_AGENT_ID), AM_SUCCESS);
    am_init_worker(AM_DEFAULT_AGENT_ID);

    // time load to capacity
    printf("starting timing phase..\n");
    t0 = time(NULL);
    loaded = test_cache(test_size, &request, result);
    elapsed = time(NULL) - t0;

    assert_int_equal(am_purge_caches(time(NULL) + cache_valid + 1), loaded);

    printf("loading for %ld secs..\n", elapsed);
    config.token_cache_valid = elapsed + 2;
    loaded = test_cache(test_size, &request, result);

    // wait the TTL to expire
    printf("waiting for %ld + 1 secs..\n", elapsed);
    sleep( (elapsed + 4) );
    
    // this update should trigger purge 
    printf("verifying expiry during load.. \n");
    test_cache_with_seed(321213, 100, &request, result);
    assert_int_equal(am_purge_caches(time(NULL) + elapsed + 10), 100);

    delete_am_policy_result_list(&result);
    
    am_shutdown_worker();
    am_cache_destroy();
    am_worker_pool_init_reset();
    am_net_init_ssl_reset();
}



/**
 * Now vary the incoming URL a bit and check we can get the same values out.
 */
void test_policy_cache_with_many_different_entries_single_session(void **state) {
    
    int                         i;
    char*                       buffer = NULL;
    struct am_policy_result *   policy_result;
    char                        fake_session[64];
    char*                       urls[] = {
        "http://agent.a-example.com:8080/allowed.html",
        "http://agent.b-example.com:8080/allowed.html?attr1=value1",
        "http://agent.c-example.com:8080/also-allowed.html",
        "http://agent.d-example.com:8080/allow.php",
        "http://agent.c-example.com:8080/also-allowed.html",
        "http://agent.e-example.com:8080/allowed/index.html",
        "http://agent.a-example.com:8080/allowed.html",
    };
    am_config_t                 config;
    am_request_t                request;
    
    // destroy the cache, if it exists
    am_cache_destroy();
    
    assert_int_equal(am_init(AM_DEFAULT_AGENT_ID), AM_SUCCESS);
    am_init_worker(AM_DEFAULT_AGENT_ID);
    
    create_random_cache_key(fake_session, sizeof(fake_session));
    
    /**
     * Add the URLS above into the cache via the same session id
     */
    for (i = 0; i < sizeof(urls)/sizeof(urls[0]); i++) {
        memset(&config, 0, sizeof(am_config_t));
        memset(&request, 0, sizeof(am_request_t));
        request.conf = &config;
        
        buffer = get_policy_for_url(urls[i]);
        policy_result = am_parse_policy_xml(0l, buffer, strlen(buffer), 0);
        free(buffer);
        
        assert_int_equal(am_add_session_policy_cache_entry(&request, fake_session, policy_result, NULL), AM_SUCCESS);
    }
    
    /**
     * Check we can retrieve the URLs above from the cache via the same session id
     */
    for (i = 0; i < sizeof(urls)/sizeof(urls[0]); i++) {
        time_t ets;
        struct am_policy_result * r = NULL;
        struct am_policy_result * result = NULL;
        struct am_namevalue * session = NULL;

        memset(&config, 0, sizeof(am_config_t));
        memset(&request, 0, sizeof(am_request_t));
        request.conf = &config;
        request.orig_url = urls[i];
                
        if (am_get_session_policy_cache_entry(&request, fake_session, &r, &session, &ets) == AM_SUCCESS) {
            
            am_bool_t found = AM_FALSE;
            for (result = r; result != NULL; result = result->next) {
                if (strcmp(result->resource, urls[i]) == 0) {
                    found = AM_TRUE;
                }
            }
            
            if (found == AM_FALSE) {
                AM_LOG_ERROR(0, "Failed to match policy for URL %s, although results retrieved", urls[i]);
            }
            
            assert_int_equal(found, AM_TRUE);
        } else {
            AM_LOG_ERROR(0, "Failed to retrieve policy for URL %s", urls[i]);
        }
    }
        
    am_shutdown_worker();
    am_cache_destroy();
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

    am_cache_destroy();
    
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

        assert_int_equal(am_cache_init(AM_DEFAULT_AGENT_ID), AM_SUCCESS);

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
    
    am_cache_destroy();
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
