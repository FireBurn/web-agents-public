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

#ifndef AM_H
#define AM_H

/**
 * This is our representation of "boolean".  Try to avoid boolean itself as although supposed to be part of the language
 * for some time now, it seems to be a grey area.  This is needed by log.h.
 */
typedef enum {
    AM_FALSE = 0,
    AM_TRUE
} am_bool_t;

#define TO_BOOL(x) (((x)==0) ? AM_FALSE : AM_TRUE)

#include "error.h"
#include "log.h"
#include "config.h"

#ifndef AM_URI_SIZE
#define AM_URI_SIZE                 4096
#endif

#ifndef AM_PATH_SIZE
#define AM_PATH_SIZE                256
#endif

#ifndef AM_HOST_SIZE
#define AM_HOST_SIZE                256
#endif

#ifndef AM_PROTO_SIZE
#define AM_PROTO_SIZE               6
#endif

#ifndef AM_HASH_TABLE_KEY_SIZE
#define AM_HASH_TABLE_KEY_SIZE      128
#endif

#ifndef AM_HASH_TABLE_SIZE
#define AM_HASH_TABLE_SIZE          6151 /* must be a prime */
#endif

#ifndef AM_SHARED_MAX_RESIZE
#define AM_SHARED_MAX_RESIZE        2
#endif

#ifndef AM_LOG_QUEUE_DEPTH
#define AM_LOG_QUEUE_DEPTH          1024 /* must not be less than max number of simultaneus log requests */
#endif

#ifndef AM_MAX_INSTANCES
#define AM_MAX_INSTANCES            32 /* max number of agent configuration instances */
#endif

#ifndef AM_NET_POOL_TIMEOUT
#define AM_NET_POOL_TIMEOUT         5 /* sec TODO: 30? */
#endif

#ifndef AM_MAX_THREADS_POOL
#define AM_MAX_THREADS_POOL         AM_MAX_INSTANCES
#endif

#ifndef AM_USER_GROUP_NAME_LIMIT
#define AM_USER_GROUP_NAME_LIMIT    20
#endif

#ifndef AM_LOG_QUEUE_SIZE
#define AM_LOG_QUEUE_SIZE           2048 /* must be a power of two */
#endif

#ifndef AM_LOG_MESSAGE_SIZE
#define AM_LOG_MESSAGE_SIZE         16384
#endif

/* Default agent id.
 * Used in: a) unit tests, 
 * b) webserver environments which do not support multiple server instances.
 */
#define AM_DEFAULT_AGENT_ID         0 

#define EMPTY               "(empty)"
#define LOGEMPTY(x)         (x == NULL ? EMPTY : x)
#define NOTNULL(x)          (x == NULL ? "" : x)
#define ISVALID(x)          (x != NULL && *x != '\0')
#define ISINVALID(x)        (x == NULL || *x == '\0')
#ifndef MIN
#define MIN(a, b)           (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b)           (((a) > (b)) ? (a) : (b))
#endif
#define CMP(a, b)           (((a) < (b)) ? -1 : (a) == (b) ? 0 : 1)

#define AM_JSON_TEMPLATE_LOCATION "{"\
        "\"error\": {"\
        " \"errors\": ["\
        "  {"\
        "   \"message\": \"%s\","\
        "   \"location\": \"%s\""\
        "  }"\
        " ],"\
        " \"code\": %d"\
        " }"\
        "}"

#define AM_JSON_TEMPLATE_DATA "{"\
        "\"error\": {"\
        " \"errors\": ["\
        "  {"\
        "   \"message\": \"%s\","\
        "   \"data\": \"%s\""\
        "  }"\
        " ],"\
        " \"code\": %d"\
        " }"\
        "}"

#define AM_JSON_TEMPLATE_LOCATION_DATA "{"\
        "\"error\": {"\
        " \"errors\": ["\
        "  {"\
        "   \"message\": \"%s\","\
        "   \"location\": \"%s\","\
        "   \"type\": \"%s\","\
        "   \"data\": \"%s\""\
        "  }"\
        " ],"\
        " \"code\": %d"\
        " }"\
        "}"

typedef enum {
    AM_OK = 0, AM_FAIL, AM_RETRY, AM_QUIT
} am_return_t;

#define RETURN_TYPE_TO_BOOL(x)   (((x) == AM_OK) ? AM_TRUE : AM_FALSE)


enum {
    AM_REQUEST_UNKNOWN = 0,
    AM_REQUEST_GET,
    AM_REQUEST_POST,
    AM_REQUEST_HEAD,
    AM_REQUEST_PUT,
    AM_REQUEST_DELETE,
    AM_REQUEST_TRACE,
    AM_REQUEST_OPTIONS,
    AM_REQUEST_CONNECT,
    AM_REQUEST_COPY,
    AM_REQUEST_INVALID,
    AM_REQUEST_LOCK,
    AM_REQUEST_UNLOCK,
    AM_REQUEST_MOVE,
    AM_REQUEST_MKCOL,
    AM_REQUEST_PATCH,
    AM_REQUEST_PROPFIND,
    AM_REQUEST_PROPPATCH,
    AM_REQUEST_VERSION_CONTROL,
    AM_REQUEST_CHECKOUT,
    AM_REQUEST_UNCHECKOUT,
    AM_REQUEST_CHECKIN,
    AM_REQUEST_UPDATE,
    AM_REQUEST_LABEL,
    AM_REQUEST_REPORT,
    AM_REQUEST_MKWORKSPACE,
    AM_REQUEST_MKACTIVITY,
    AM_REQUEST_BASELINE_CONTROL,
    AM_REQUEST_MERGE,
    AM_REQUEST_CONFIG,
    AM_REQUEST_ENABLE_APP,
    AM_REQUEST_DISABLE_APP,
    AM_REQUEST_STOP_APP,
    AM_REQUEST_STOP_APP_RSP,
    AM_REQUEST_REMOVE_APP,
    AM_REQUEST_STATUS,
    AM_REQUEST_STATUS_RSP,
    AM_REQUEST_INFO,
    AM_REQUEST_INFO_RSP,
    AM_REQUEST_DUMP,
    AM_REQUEST_DUMP_RSP,
    AM_REQUEST_PING,
    AM_REQUEST_PING_RSP
};

enum {
    AM_LOG_LEVEL_NONE = 0,
    AM_LOG_LEVEL_ALWAYS = 1 << 0,
    AM_LOG_LEVEL_ERROR = 1 << 1,
    AM_LOG_LEVEL_WARNING = 1 << 2,
    AM_LOG_LEVEL_INFO = 1 << 3,
    AM_LOG_LEVEL_DEBUG = 1 << 4,
    AM_LOG_LEVEL_REMOTE = 1 << 5,
    AM_LOG_LEVEL_AUDIT = 1 << 6,
    AM_LOG_LEVEL_AUDIT_REMOTE = 1 << 7,
    AM_LOG_LEVEL_AUDIT_ALLOW = 1 << 8,
    AM_LOG_LEVEL_AUDIT_DENY = 1 << 9
};

struct url {
    unsigned int port;
    int error;
    char ssl;
    char proto[AM_PROTO_SIZE + 1];
    char host[AM_HOST_SIZE + 1];
    char path[AM_URI_SIZE + 1];
    char query[AM_URI_SIZE + 1];
};

typedef struct am_request {
    am_status_t status;
    unsigned int retry;

    am_bool_t not_enforced;
    am_bool_t is_logout_url;
    am_bool_t token_in_post;
    am_bool_t is_dummypost_url;
    am_bool_t is_json_url;

    const char *orig_url;
    struct url url; /* parsed/normalized request url (split in values)*/
    char *normalized_url; /*normalized request url*/
    char *overridden_url; /*normalized/overridden request url*/
    const char *cookies;
    const char *content_type;
    char method;

    char *token;
    struct am_session_info session_info;

    char *client_ip;
    char *client_host;

    const char *user;
    const char *user_password;

    struct am_namevalue *sattr; /*session attributes (cache or direct)*/
    struct am_policy_result *pattr; /*policy attributes (cache or direct)*/
    struct am_namevalue *response_attributes; /*pointers to the data inside policy am_policy_result if any*/
    struct am_namevalue *response_decisions;
    struct am_namevalue *policy_advice;

    const char *client_fqdn;

    char *post_data;
    size_t post_data_sz;
    const char *post_data_url;

    unsigned long instance_id;
    am_config_t *conf; /*agent configuration*/

    void *ctx; /*web container/request context*/
#ifdef _WIN32
    void *ctx_class;
#endif
    am_status_t(*am_get_request_url_f)(struct am_request *);
    am_status_t(*am_get_post_data_f)(struct am_request *);
    am_status_t(*am_set_post_data_f)(struct am_request *);
    am_status_t(*am_set_user_f)(struct am_request *, const char *);
    am_status_t(*am_set_method_f)(struct am_request *);
    am_status_t(*am_set_header_in_request_f)(struct am_request *, const char *, const char *);
    am_status_t(*am_add_header_in_response_f)(struct am_request *, const char *, const char *);
    am_status_t(*am_set_cookie_f)(struct am_request *, const char *);
    am_status_t(*am_render_result_f)(struct am_request *);
    am_status_t(*am_set_custom_response_f)(struct am_request *, const char *, const char *);

} am_request_t;

struct am_ssl_options {
    char cert_key_file[AM_PATH_SIZE];
    char cert_key_pass[AM_PATH_SIZE];
    char cert_file[AM_PATH_SIZE];
    char cert_ca_file[AM_PATH_SIZE];
    char ciphers[AM_PATH_SIZE];
    char tls_opts[AM_PATH_SIZE];
    int verifypeer;
};

unsigned long am_instance_id(const char *);

void am_process_request(am_request_t *r);
void am_request_free(am_request_t *r);

const char *am_method_num_to_str(int method);
int am_method_str_to_num(const char *method_str);

int am_init(int id);
int am_init_worker(int id);
int am_shutdown(int id);
int am_shutdown_worker();

int am_configuration_init(int id);
int am_configuration_shutdown();
int am_cache_init(int id);
int am_cache_shutdown();
void am_cache_destroy();

int am_log_get_current_owner();
int am_re_init_worker();
void am_log_re_init(int status);

void am_log_init(int id, int s);
void am_log_init_worker(int id, int s);
void am_log_shutdown(int id);
void am_log_register_instance(unsigned long instance_id, const char *debug_log, int log_level, int log_size,
        const char *audit_log, int audit_level, int audit_size);

void am_config_free(am_config_t **c);
am_config_t *am_get_config_file(unsigned long instance_id, const char *filename);
int am_get_agent_config(unsigned long instance_id, const char *config_file, am_config_t **cnf);

char *base64_decode(const char *in, size_t *length);
char *base64_encode(const void *in, size_t *length);
void am_free(void *ptr);
int am_asprintf(char **buffer, const char *fmt, ...);
char *am_json_escape(const char *str, size_t *escaped_sz);

char *am_normalize_pattern(const char *url);

#endif
