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
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "am.h"
#include "utility.h"



typedef am_return_t (* am_state_func_t)(am_request_t *);

void am_test_get_state_funcs(am_state_func_t const ** func_array_p, int * func_array_len_p);

void am_worker_pool_startup(void);

static am_status_t get_post_data(struct am_request * request)
{
    return AM_SUCCESS;
}

static am_status_t set_custom_response(struct am_request * request, const char * data, const char * content_type)
{
    return AM_SUCCESS;
}


void test_simple_fail(void **state) {

    (void)state;

    am_state_func_t const * func_array = 0;
    int array_len = 0;
    
    am_test_get_state_funcs(&func_array, &array_len);
    am_state_func_t notification_handler = func_array[2];
    
    char * post_data =
        "<NotificationSet version='1.0'>"
        " <Notification>"
        //option - invalidate config changed ( not for specific instance )
        //" <AgentConfigChangeNotification />"
        //option - invalidate session by sid ( state must be present, not is not used )
        //" <SessionNotification>"
        //"  <Session sid='my-session' state='destroyed' />"
        //" </SessionNotification>"
        //option remove specific resources from the cache - check that it is the right service
        //these can't be removed by resource from the session cache
        " <PolicyChangeNotification serviceName='identified-service' >"
        "  <ResourceName type='added' >a.b.c:3232/d/e/f</ResourceName>"
        "  <ResourceName type='deleted' >a.b.c:3232/d/e/f</ResourceName>"
        "  <ResourceName type='modified' >a.b.c:3232/d/e/f</ResourceName>"
        "  </PolicyChangeNotification>"
        " </Notification>"
        "</NotificationSet>";
    
    struct {
    } ctx;
    
    am_config_t config = {
        .notif_enable               = AM_TRUE,
        .notif_url                  = "https://www.notify.com:1234/am",
        .override_notif_url         = AM_TRUE,
        
        .url_eval_case_ignore       = AM_FALSE,
    };
    
    am_request_t request = {
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = 0,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.notify.com:90/am",
        
        .post_data                  = post_data,
        .post_data_sz               = strlen(post_data),

        .am_get_post_data_f         = get_post_data,
        
        .am_set_custom_response_f   = set_custom_response,
    };
    
    //am_init_worker();
    am_worker_pool_startup();
    
    // this is not a notification
    assert_int_equal(notification_handler(&request), AM_FAIL);
    
    am_shutdown_worker();
}


void test_simple_notification(void **state) {

    am_state_func_t const * func_array = 0;
    int array_len = 0;
    
    am_test_get_state_funcs(&func_array, &array_len);
    am_state_func_t notification_handler = func_array[2];
    
    char * post_data =
        "<NotificationSet version='1.0'>"
        " <Notification>"
        //option - invalidate config changed ( not for specific instance )
        //" <AgentConfigChangeNotification />"
        //option - invalidate session by sid ( state must be present, not is not used )
        //" <SessionNotification>"
        //"  <Session sid='my-session' state='destroyed' />"
        //" </SessionNotification>"
        //option remove specific resources from the cache - check that it is the right service
        //these can't be removed by resource from the session cache
        " <PolicyChangeNotification serviceName='identified-service' >"
        "  <ResourceName type='added' >a.b.c:3232/d/e/f</ResourceName>"
        "  <ResourceName type='deleted' >a.b.c:3232/d/e/f</ResourceName>"
        "  <ResourceName type='modified' >a.b.c:3232/d/e/f</ResourceName>"
        "  </PolicyChangeNotification>"
        " </Notification>"
        "</NotificationSet>";
    
    struct {
    } ctx;
    
    am_config_t config = {
        .notif_enable               = AM_TRUE,
        .notif_url                  = "https://www.notify.com:1234/am",
        .override_notif_url         = AM_FALSE,
        
        .url_eval_case_ignore       = AM_FALSE,
    };
    
    am_request_t request = {
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = 0,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.notify.com:1234/am",
 
        .post_data                  = post_data,
        .post_data_sz               = strlen(post_data),
        
        .am_get_post_data_f         = get_post_data,
        
        .am_set_custom_response_f   = set_custom_response,
    };
    
    //am_init_worker();
    am_worker_pool_startup();
    
    // this is a notification
    assert_int_equal(notification_handler(&request), AM_OK);
    
    am_shutdown_worker();
}


void test_session_notification_on_policy_cache(void **state) {

    const char * session_id = "XXX";
    
    char * session_notification =
        "<NotificationSet version='1.0'>"
        " <Notification>"
        "  <SessionNotification> <Session sid='XXX' state='destroyed' /> </SessionNotification>"
        " </Notification>"
        "</NotificationSet>";

    am_state_func_t const * func_array = 0;
    int array_len = 0;
    
    am_test_get_state_funcs(&func_array, &array_len);
    am_state_func_t notification_handler = func_array [2];
    
    struct {
    } ctx;
    
    am_config_t config = {
        .instance_id                = 101,
        .token_cache_valid          = 0,
        
        .notif_enable               = AM_TRUE,
        .notif_url                  = "https://www.notify.com:1234/am",
        .override_notif_url         = AM_FALSE,
        
        .url_eval_case_ignore       = AM_FALSE,
    };
    
    am_request_t request = {
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = 0,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.notify.com:1234/am",

        .post_data                  = session_notification,
        .post_data_sz               = strlen(session_notification),
        
        .am_get_post_data_f         = get_post_data,
        
        .am_set_custom_response_f   = set_custom_response,
    };

    char * xml =
        "<PolicyService version='1.0' revisionNumber='60'>"
        "  <PolicyResponse requestId='4' issueInstant='1424783306343' >"
    
        "    <ResourceResult name='http://vb2.local.com:80/testwebsite'>"
        "      <PolicyDecision>"
    
        "        <ResponseAttributes>"
        "           <!-- these can have multiple (0..n) value elements -->"
        "           <AttributeValuePair>"
        "             <Attribute name='Attributes,key:0,0'/> <Value>Attributes,value:0,0,0</Value> <Value>Attributes,value:0,0,1</Value>"
        "           </AttributeValuePair>"
        "           <AttributeValuePair>"
        "             <Attribute name='Attributes,key:0,1'/> <Value>Attributes,value:0,1,0</Value>"
        "           </AttributeValuePair>"
        "        </ResponseAttributes>"
    
        "        <ActionDecision timeToLive='1234'>"
        "          <!-- these can have no value elements, which defaults to ? -->"
        "          <AttributeValuePair>"
        "            <Attribute name='PUT'/> <Value>deny</Value>"
        "          </AttributeValuePair>"
        "          <Advices>"
        "            <AttributeValuePair>"
        "              <Attribute name='Advices,key:0,0'/> <Value>Advices,value:0,0,0</Value>"
        "            </AttributeValuePair>"
        "            <AttributeValuePair>"
        "              <Attribute name='Advices,key:0,1'/> <Value>Advices,value:0,1,0</Value>"
        "            </AttributeValuePair>"
        "          </Advices>"
        "        </ActionDecision>"
    
        "        <ResponseDecisions>"
        "          <AttributeValuePair>"
        "            <Attribute name='Decision,key:0,0'/> <Value>Decision,value:0,0,0</Value>"
        "          </AttributeValuePair>"
        "          <AttributeValuePair>"
        "            <Attribute name='Decision,key:0,1'/> <Value>Decision,value:0,1,0</Value>"
        "          </AttributeValuePair>"
        "          <AttributeValuePair>"
        "            <Attribute name='Decision,key:0,2'/> <Value>Decision,value:0,2,0</Value>"
        "          </AttributeValuePair>"
        "        </ResponseDecisions>"
    
        "      </PolicyDecision>"
        "    </ResourceResult>"
        "  </PolicyResponse>"
        "</PolicyService>";
    
    char* pll = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
        "<ResponseSet vers='1.0' svcid='poicy' reqid='48'>"
        "  <Response><![CDATA[%s]]></Response>"
        "</ResponseSet>";

    char * buffer = NULL;
    int size = asprintf(&buffer, pll, xml);
    
    struct am_policy_result * result = am_parse_policy_xml(0l, buffer, size, 0);
    time_t ets;
    struct am_policy_result * r = NULL;
    struct am_namevalue * session = NULL;
    
    free(buffer);
    
    am_cache_init();
    
    assert_int_equal(am_add_session_policy_cache_entry(&request, session_id, result, 0), AM_SUCCESS);
    
    delete_am_policy_result_list(&result);

    // find the session
    assert_int_equal(am_get_session_policy_cache_entry(&request, session_id, &r, &session, &ets), AM_SUCCESS);
    delete_am_policy_result_list(&r);

    //am_init_worker();
    am_worker_pool_startup();
    
    // this is a notification
    assert_int_equal(notification_handler(&request), AM_OK);

    am_shutdown_worker();

    // wait for the worker to have finished
    assert_int_equal(am_get_session_policy_cache_entry(&request, session_id, &r, &session, &ets), AM_NOT_FOUND);
    
    am_cache_shutdown();
}



void test_resource_notification_on_policy_cache(void **state) {

    am_state_func_t const * func_array = 0;
    int array_len = 0;
    
    am_test_get_state_funcs(&func_array, &array_len);
    am_state_func_t notification_handler = func_array [2];
    
    const char * session_id = "XXX";
    
    char * session_notification =
    "<NotificationSet version='1.0'>"
    " <Notification>"
    "  <PolicyChangeNotification serviceName='identified-service' >"
    "   <ResourceName type='deleted' >a.b.c:3232/d/e/f</ResourceName>"
    "   <ResourceName type='modified' >a.b.c:3232/d/e/f</ResourceName>"
    "  </PolicyChangeNotification>"
    " </Notification>"
    "</NotificationSet>";
    
    struct {
    } ctx;
    
    am_config_t config = {
        .instance_id                = 101,
        .token_cache_valid          = 0,
        
        .notif_enable               = AM_TRUE,
        .notif_url                  = "https://www.notify.com:1234/am",
        .override_notif_url         = AM_FALSE,
        
        .url_eval_case_ignore       = AM_FALSE,
    };
    
    am_request_t request = {
        .conf                       = &config,
        .ctx                        = &ctx,
        
        .method                     = AM_REQUEST_POST,
        .token                      = 0,
        
        .overridden_url             = "https://www.override.com:90/am",
        .normalized_url             = "https://www.notify.com:1234/am",
        
        .post_data                  = session_notification,
        .post_data_sz               = strlen(session_notification),
        
        .am_get_post_data_f         = get_post_data,
        
        .am_set_custom_response_f   = set_custom_response,
    };
    
    char * xml =
        "<PolicyService version='1.0' revisionNumber='60'>"
        "  <PolicyResponse requestId='4' issueInstant='1424783306343' >"
    
        "    <ResourceResult name='a.b.c:3232/d/e/f'>"
        "      <PolicyDecision>"
    
        "        <ResponseAttributes>"
        "          <!-- these can have multiple (0..n) value elements -->"
        "          <AttributeValuePair>"
        "            <Attribute name='Attributes,key:0,0'/> <Value>Attributes,value:0,0,0</Value> <Value>Attributes,value:0,0,1</Value>"
        "          </AttributeValuePair>"
        "          <AttributeValuePair>"
        "            <Attribute name='Attributes,key:0,1'/> <Value>Attributes,value:0,1,0</Value>"
        "          </AttributeValuePair>"
        "        </ResponseAttributes>"
    
        "        <ActionDecision timeToLive='1234'>"
        "          <!-- these can have no value elements, which defaults to ? -->"
        "          <AttributeValuePair>"
        "            <Attribute name='PUT'/> <Value>deny</Value>"
        "          </AttributeValuePair>"
        "          <Advices>"
        "            <AttributeValuePair>"
        "              <Attribute name='Advices,key:0,0'/> <Value>Advices,value:0,0,0</Value>"
        "            </AttributeValuePair>"
        "            <AttributeValuePair>"
        "              <Attribute name='Advices,key:0,1'/> <Value>Advices,value:0,1,0</Value>"
        "            </AttributeValuePair>"
        "          </Advices>"
        "        </ActionDecision>"
    
        "        <ResponseDecisions>"
        "          <AttributeValuePair>"
        "            <Attribute name='Decision,key:0,0'/> <Value>Decision,value:0,0,0</Value>"
        "          </AttributeValuePair>"
        "          <AttributeValuePair>"
        "            <Attribute name='Decision,key:0,1'/> <Value>Decision,value:0,1,0</Value>"
        "          </AttributeValuePair>"
        "          <AttributeValuePair>"
        "            <Attribute name='Decision,key:0,2'/> <Value>Decision,value:0,2,0</Value>"
        "          </AttributeValuePair>"
        "        </ResponseDecisions>"
    
        "      </PolicyDecision>"
        "    </ResourceResult>"
        "  </PolicyResponse>"
        "</PolicyService>";
    
    char * pll = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
        "<ResponseSet vers='1.0' svcid='poicy' reqid='48'>"
        "  <Response><![CDATA[%s]]></Response>"
        "</ResponseSet>";
    
    char * buffer = NULL;
    int size = asprintf(&buffer, pll, xml);

    // when the worker has finished, the session result list should be unchanged, but policy cache entry removed
    time_t ets;
    struct am_policy_result * r = NULL;
    struct am_namevalue * session = NULL;
    struct am_policy_result * p;
    struct am_policy_result * result = am_parse_policy_xml(0l, buffer, size, 0);

    free(buffer);
    
    am_cache_init();
    assert_int_equal(am_add_session_policy_cache_entry(&request, session_id, result, 0), AM_SUCCESS);

    // add the resources to the policy cache
    for(p = result; p; p = p->next) {
        am_add_policy_cache_entry(&request, p->resource, 500);
    }
    delete_am_policy_result_list(&result);
    
    //am_init_worker();
    am_worker_pool_startup();
    
    // send a resource notification for the cached resource
    assert_int_equal(notification_handler(&request), AM_OK);
    am_shutdown_worker();
    
    assert_int_equal(am_get_session_policy_cache_entry(&request, session_id, &r, &session, &ets), AM_SUCCESS);
    
    if (r != NULL) {
        assert_int_equal(strcmp(r->resource, "a.b.c:3232/d/e/f"), 0);
        assert_int_equal(am_get_policy_cache_entry(&request, r->resource, 0), AM_NOT_FOUND);
    }
    delete_am_policy_result_list(&r);

    am_cache_shutdown();
}
