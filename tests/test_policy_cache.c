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
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#include "am.h"

#include "utility.h"
#include "list.h"

#include <setjmp.h>
#include <cmocka.h>

void* am_parse_policy_xml(unsigned long instance_id, const char* xml, size_t xml_sz, int scope);


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
    
    char* key_format;
    char* value_format;

    asprintf(&key_format, "%s%s", prefix, ",key:%d,%d");
    asprintf(&value_format, "%s%s", prefix, ",value:%d,%d,%d");
    
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

    assert_non_null(r);

    assert_string_equal(r->resource, "http://vb2.local.com:80/testwebsite");
    assert_int_equal(test_attributes("Attributes", r->response_attributes), 3);
    assert_int_equal(test_attributes("Decision", r->response_decisions), 3);
    
    struct am_action_decision* ad = r->action_decisions;

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

    (void)state;

    size_t size;
    char* buffer = NULL;
    struct am_policy_result* result;

    asprintf(&buffer, pll, policy_xml);
    size = strlen(pll);
    result = am_parse_policy_xml(0l, buffer, size, 0);

    free(buffer);

    test_policy_structure(result);
}


void test_policy_cache_simple(void **state) {

    (void)state;

    struct {
    } ctx;
    
    am_config_t config = {
        .instance_id = 101,
        .token_cache_valid = 0,
    };
    
    am_request_t request = {
        .conf                   = &config,
        .ctx                    = &ctx,
    };
    
    char* buffer = NULL;
    int size = asprintf(&buffer, pll, policy_xml);
    struct am_policy_result * result = am_parse_policy_xml(0l, buffer, size, 0);
    time_t ets;
    struct am_policy_result * r = NULL;
    struct am_namevalue * session = NULL;
    
    free(buffer);
    
    am_cache_init();
    
    am_add_session_policy_cache_entry(&request, "Policy-key", result, 0);
    am_get_session_policy_cache_entry(&request, "Policy-key", &r, &session, &ets);
    
    am_cache_shutdown();
    
    test_policy_structure(r);
}


const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*";


void create_random_cache_key(char * buffer, size_t size)
{
    int i;
    size_t count = size - 1;
    size_t len = sizeof(alphabet) - 1;
    
    for (i = 0; i < count; i++) {
        buffer[i] = alphabet[random() % len];
    }
    buffer[count] = 0;
}

static void test_cache(int test_size, am_request_t * request, struct am_policy_result * result)
{
    int i;
    char key[64];
    
    // create initial entries
    srandom(543542);
    for(i = 0; i < test_size; i++) {
        create_random_cache_key(key, sizeof(key));
        assert_int_equal(am_add_session_policy_cache_entry(request, key, result, 0), AM_SUCCESS);
    }
    
    // should refresh the whole lot
    srandom(543542);
    for(i = 0; i < test_size; i++) {
        create_random_cache_key(key, sizeof(key));
        assert_int_equal(am_add_session_policy_cache_entry(request, key, result, 0), AM_SUCCESS);
    }
    
    // read them all back
    srandom(543542);
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

    // create initial entries
    for(i = 0; i < test_size; i++) {
        assert_int_equal(am_add_session_policy_cache_entry(request, keys [i], result, 0), AM_SUCCESS);
    }
    
    // should refresh the whole lot
    for(i = 0; i < test_size; i++) {
        assert_int_equal(am_add_session_policy_cache_entry(request, keys [i], result, 0), AM_SUCCESS);
    }
    
    // read them all back
    for(i = 0; i < test_size; i++) {
        time_t ets;
        struct am_policy_result * r = NULL;
        struct am_namevalue * session = NULL;
        
        assert_int_equal(am_get_session_policy_cache_entry(request, keys [i], &r, &session, &ets), AM_SUCCESS);
        test_policy_structure(r);
    }
}



void test_policy_cache_many_entries(void **state) {

    (void)state;

    const int test_size = 198;
    
    struct {
    } ctx;
    
    am_config_t config = {
        .instance_id = 101,
        .token_cache_valid = 0,
    };
    
    am_request_t request = {
        .conf                   = &config,
        .ctx                    = &ctx,
    };
    
    char* buffer = NULL;
    int size = asprintf(&buffer, pll, policy_xml);
    struct am_policy_result * result = am_parse_policy_xml(0l, buffer, size, 0);
    
    free(buffer);
    
    am_cache_init();
    
    test_cache(test_size, &request, result);
    
    delete_am_policy_result_list(&result);
    
    assert_int_equal(am_cache_shutdown(), AM_SUCCESS);
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

void test_policy_cache_multithread()
{
    struct {
        
    } ctx;
    
    am_config_t config = {
        .instance_id = 101,
        .token_cache_valid = 0,
    };
    
    am_request_t request = {
        .conf                   = &config,
        .ctx                    = &ctx,
    };
    
    char* buffer = 0;
    int size = asprintf(&buffer, pll, policy_xml);
    struct am_policy_result* result = am_parse_policy_xml(0l, buffer, size, 0);
    // this must be slightly less than the maximum because re-use of shm chunks might use more space
    const int test_size = 195;
    
    char* keys [test_size];
    char key_buffer[64];
    int i;
    
    struct test_cache_params params = {
        .test_size = test_size,
        .keys = keys,
        
        .iterations = 32,
        
        .request = &request,
        .result = result,
    };
    
    long t0 = clock();
    int nthreads = 2;
    pthread_t threads [nthreads];
    void* arg = NULL;
    double dt;

    free(buffer);
    
    for (i = 0; i < test_size; i++) {
        create_random_cache_key(key_buffer, sizeof(key_buffer));
        keys[i] = strdup(key_buffer);
    }
    
    am_cache_init();

    fprintf(stdout, "info: started multithreaded cache tests.. ");
    fflush(stdout);

    for (i = 0; i < nthreads; i++) {
        if (pthread_create(threads + i, NULL, test_cache_procedure, &params)) {
            perror("create thread\n");
        }
    }
    
    for (i = 0; i < nthreads; i++) {
        if (pthread_join(threads[i], &arg)) {
            perror("create thread\n");
        }
    }
  
    dt = ((double) (clock() - t0)) / CLOCKS_PER_SEC;
    fprintf(stdout, "finished after %lf secs\n", dt);

    assert_int_equal(am_cache_shutdown(), AM_SUCCESS);
    
    delete_am_policy_result_list(&result);

    for(i = 0; i < test_size; i++) {
        free(keys[i]);
    }
}


/**
 * This is an internal test of the mechanism for replaying a given number of randomly generated strings
 */
void test_key_creation(void **state) {

    (void)state;

    const int test_size = 10;
    char* keys[test_size];
    char key[64];
    int i;
    
    srandom(543542);
    for(i = 0; i < test_size; i++) {
        create_random_cache_key(key, sizeof(key));
        keys[i] = strdup(key);
    }
    
    srandom(543542);
    for(i = 0; i < test_size; i++) {
        create_random_cache_key(key, sizeof(key));
        assert_string_equal(key, keys[i]);
    }
}
