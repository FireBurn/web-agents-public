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
#include "platform.h"
#include "am.h"
#include "utility.h"
#include "list.h"

enum {
    UINT64_TYPE = 0,
    UINT32_TYPE,
    SINT32_TYPE,
    STR32_TYPE,
    ARRAY32_TYPE,
    MAP32_TYPE
};

enum {
    U32_MARKER = 0xCE,
    U64_MARKER = 0xCF,
    S32_MARKER = 0xD2,
    STR32_MARKER = 0xDB,
    ARRAY32_MARKER = 0xDD,
    MAP32_MARKER = 0xDF
};

struct cache_object {
    uint8_t type;

    union {
        uint64_t u64;
        uint32_t u32;
        int32_t s32;
        uint32_t arr_size;
        uint32_t map_size;
        uint32_t str_size;
    } obj;
};

/* write to the heap allocated memory buffer stream */
static size_t write_to_membuf(struct cache_object_ctx *ctx, const void *data, size_t sz) {
    void *temp;
    if (ctx->data == NULL) {
#define INITIAL_BUFFER_SZ 8192
        ctx->data = malloc(INITIAL_BUFFER_SZ);
        ctx->alloc_size = INITIAL_BUFFER_SZ;
    }
    if (ctx->data == NULL) {
        ctx->error = AM_ENOMEM;
        ctx->alloc_size = ctx->data_size = 0;
        return 0;
    }
    if ((ctx->data_size + sz) > ctx->alloc_size) {
        ctx->alloc_size = (ctx->alloc_size + sz) << 1;
        temp = realloc(ctx->data, ctx->alloc_size);
        if (temp == NULL) {
            if (ctx->data != NULL) free(ctx->data);
            ctx->error = AM_ENOMEM;
            ctx->alloc_size = ctx->data_size = 0;
            return 0;
        }
        ctx->data = temp;
    }
    memcpy((uint8_t *) ctx->data + ctx->data_size, data, sz);
    ctx->data_size += sz;
    return sz;
}

/* read from memory buffer stream */
static int read_from_membuf(struct cache_object_ctx *ctx, void *data, size_t sz) {
    if (ctx->data_size < (ctx->offset + sz))
        return -1;
    memcpy(data, (uint8_t *) ctx->data + ctx->offset, sz);
    ctx->offset += sz;
    return 0;
}

/* init cache object context */
void cache_object_ctx_init(struct cache_object_ctx *ctx) {
    ctx->error = 0;
    ctx->data = NULL;
    ctx->alloc_size = ctx->data_size = ctx->offset = 0;
    ctx->external = 0;
    ctx->write = write_to_membuf;
    ctx->read = read_from_membuf;
}

/* init cache object context with the external data (deserialization use only) */
void cache_object_ctx_init_data(struct cache_object_ctx *ctx, void *data, size_t sz) {
    ctx->error = 0;
    ctx->data = data;
    ctx->alloc_size = ctx->data_size = sz;
    ctx->offset = 0;
    ctx->external = 1;
    ctx->write = write_to_membuf;
    ctx->read = read_from_membuf;
}

/* destroy cache object context */
void cache_object_ctx_destroy(struct cache_object_ctx *ctx) {
    if (ctx->data != NULL && !ctx->external)
        free(ctx->data);
    ctx->error = 0;
    ctx->data = NULL;
    ctx->alloc_size = ctx->data_size = ctx->offset = 0;
    ctx->write = NULL;
    ctx->read = NULL;
}

static int write_byte(struct cache_object_ctx *ctx, uint8_t x) {
    return (ctx->write(ctx, &x, sizeof (uint8_t)) != (sizeof (uint8_t)));
}

/* write signed 32 bit integer */
static int cache_object_write_s32(struct cache_object_ctx *ctx, int32_t val) {
    int32_t i;
    if (write_byte(ctx, S32_MARKER) != 0) {
        ctx->error = AM_ERROR;
        return -1;
    }
    i = htonl(val);
    ctx->write(ctx, &i, sizeof (int32_t));
    return 0;
}

/* write unsigned 32 bit integer */
static int cache_object_write_u32(struct cache_object_ctx *ctx, uint32_t val) {
    uint32_t i;
    if (write_byte(ctx, U32_MARKER) != 0) {
        ctx->error = AM_ERROR;
        return -1;
    }
    i = htonl(val);
    ctx->write(ctx, &i, sizeof (uint32_t));
    return 0;
}

/* write unsigned 64 bit integer */
static int cache_object_write_u64(struct cache_object_ctx *ctx, uint64_t val) {
    uint64_t i;
    if (write_byte(ctx, U64_MARKER) != 0) {
        ctx->error = AM_ERROR;
        return -1;
    }
    i = htonll(val);
    ctx->write(ctx, &i, sizeof (uint64_t));
    return 0;
}

/* write char buffer of sz length */
static int cache_object_write_str(struct cache_object_ctx *ctx, const char *data, uint32_t sz) {
    uint32_t i;
    if (write_byte(ctx, STR32_MARKER) != 0) {
        ctx->error = AM_ERROR;
        return -1;
    }
    i = htonl(sz);
    ctx->write(ctx, &i, sizeof (uint32_t));
    if (sz > 0)
        ctx->write(ctx, data, sz);
    return 0;
}

/* write array of sz elements */
static int cache_object_write_array(struct cache_object_ctx *ctx, uint32_t sz) {
    uint32_t i;
    if (write_byte(ctx, ARRAY32_MARKER) != 0) {
        ctx->error = AM_ERROR;
        return -1;
    }
    i = htonl(sz);
    ctx->write(ctx, &i, sizeof (uint32_t));
    return 0;
}

/* write map (name-value pair) of sz elements */
static int cache_object_write_map(struct cache_object_ctx *ctx, uint32_t sz) {
    uint32_t i;
    if (write_byte(ctx, MAP32_MARKER) != 0) {
        ctx->error = AM_ERROR;
        return -1;
    }
    i = htonl(sz);
    ctx->write(ctx, &i, sizeof (uint32_t));
    return 0;
}

static int cache_object_read(struct cache_object_ctx *ctx, struct cache_object *obj) {
    uint8_t type_marker = 0;

    if (ctx->read(ctx, &type_marker, sizeof (uint8_t)) != 0) {
        ctx->error = AM_ERROR;
        return -1;
    }

    switch (type_marker) {
        case U64_MARKER:
            obj->type = UINT64_TYPE;
            ctx->read(ctx, &obj->obj.u64, sizeof (uint64_t));
            obj->obj.u64 = ntohll(obj->obj.u64);
            break;
        case U32_MARKER:
            obj->type = UINT32_TYPE;
            ctx->read(ctx, &obj->obj.u32, sizeof (uint32_t));
            obj->obj.u32 = ntohl(obj->obj.u32);
            break;
        case S32_MARKER:
            obj->type = SINT32_TYPE;
            ctx->read(ctx, &obj->obj.s32, sizeof (int32_t));
            obj->obj.s32 = (int32_t) ntohl(obj->obj.s32);
            break;
        case STR32_MARKER:
            obj->type = STR32_TYPE;
            ctx->read(ctx, &obj->obj.u32, sizeof (uint32_t));
            obj->obj.str_size = ntohl(obj->obj.u32);
            break;
        case ARRAY32_MARKER:
            obj->type = ARRAY32_TYPE;
            ctx->read(ctx, &obj->obj.u32, sizeof (uint32_t));
            obj->obj.arr_size = ntohl(obj->obj.u32);
            break;
        case MAP32_MARKER:
            obj->type = MAP32_TYPE;
            ctx->read(ctx, &obj->obj.u32, sizeof (uint32_t));
            obj->obj.map_size = ntohl(obj->obj.u32);
            break;
        default:
            ctx->error = AM_EINVAL;
            return -1;
    }
    return 0;
}

/* read signed 32 bit integer */
static int cache_object_read_s32(struct cache_object_ctx *ctx, int32_t *val) {
    struct cache_object obj;
    if (cache_object_read(ctx, &obj) == 0 &&
            obj.type == SINT32_TYPE) {
        *val = obj.obj.s32;
        return 0;
    }
    return -1;
}

/* read unsigned 64 bit integer */
static int cache_object_read_u64(struct cache_object_ctx *ctx, uint64_t *val) {
    struct cache_object obj;
    if (cache_object_read(ctx, &obj) == 0 &&
            obj.type == UINT64_TYPE) {
        *val = obj.obj.u64;
        return 0;
    }
    return -1;
}

/* read unsigned 32 bit integer */
static int cache_object_read_u32(struct cache_object_ctx *ctx, uint32_t *val) {
    struct cache_object obj;
    if (cache_object_read(ctx, &obj) == 0 &&
            obj.type == UINT32_TYPE) {
        *val = obj.obj.u32;
        return 0;
    }
    return -1;
}

static int cache_object_read_str_size(struct cache_object_ctx *ctx, uint32_t *size) {
    struct cache_object obj;
    if (cache_object_read(ctx, &obj) == 0 &&
            obj.type == STR32_TYPE) {
        *size = obj.obj.str_size;
        return 0;
    }
    return -1;
}

/* read char array into the heap allocated buffer */
static int cache_object_read_str(struct cache_object_ctx *ctx, char **data, uint32_t *size) {
    uint32_t str_size = 0;

    if (data == NULL || cache_object_read_str_size(ctx, &str_size) != 0)
        return -1;

    *data = malloc(str_size + 1);
    if (*data == NULL) {
        ctx->error = AM_ENOMEM;
        return -1;
    }

    if (ctx->read(ctx, *data, str_size) != 0) {
        free(*data);
        *data = NULL;
        return -1;
    }
    (*data)[str_size] = 0;
    if (size != NULL)
        *size = str_size;
    return 0;
}

/* read array (size) */
static int cache_object_read_array(struct cache_object_ctx *ctx, uint32_t *size) {
    struct cache_object obj;
    if (cache_object_read(ctx, &obj) == 0 &&
            obj.type == ARRAY32_TYPE) {
        *size = obj.obj.arr_size;
        return 0;
    }
    return -1;
}

/* read map (size) */
static int cache_object_read_map(struct cache_object_ctx *ctx, uint32_t *size) {
    struct cache_object obj;
    if (cache_object_read(ctx, &obj) == 0 &&
            obj.type == MAP32_TYPE) {
        *size = obj.obj.map_size;
        return 0;
    }
    return -1;
}

/* write initial key for the cache object */
int cache_object_write_key(struct cache_object_ctx *ctx, char *key) {
    return cache_object_write_str(ctx, key, (uint32_t) strlen(key));
}

/* move reader past the key string */
int cache_object_skip_key(struct cache_object_ctx *ctx) {
    uint32_t sz = 0;

    if (cache_object_read_str_size(ctx, &sz) != 0)
        return -1;

    if (ctx->data_size < (ctx->offset + sz)) {
        return -1;
    }
    ctx->offset += sz;

    return 0;
}

int am_name_value_serialise(struct cache_object_ctx *ctx, struct am_namevalue *list) {
    uint32_t count = 0;
    struct am_namevalue *p = list;

    while (p != NULL) {
        count++;
        p = p->next;
    }

    cache_object_write_map(ctx, count);

    p = list;
    while (p != NULL) {
        cache_object_write_str(ctx, p->n, (uint32_t) p->ns);
        cache_object_write_str(ctx, p->v, (uint32_t) p->vs);
        p = p->next;
    }
    return 0;
}

int am_action_decision_serialise(struct cache_object_ctx *ctx, struct am_action_decision *list) {
    uint32_t count = 0;
    struct am_action_decision *p = list;

    while (p != NULL) {
        count++;
        p = p->next;
    }

    cache_object_write_array(ctx, count);

    p = list;
    while (p != NULL) {
        cache_object_write_u64(ctx, p->ttl);
        cache_object_write_s32(ctx, p->method);
        cache_object_write_s32(ctx, p->action);
        am_name_value_serialise(ctx, p->advices);
        p = p->next;
    }
    return 0;
}

int am_policy_result_serialise(struct cache_object_ctx *ctx, struct am_policy_result *list) {
    uint32_t count = 0;
    struct am_policy_result *p = list;

    while (p != NULL) {
        count++;
        p = p->next;
    }

    cache_object_write_array(ctx, count);

    p = list;
    while (p != NULL) {
        cache_object_write_u64(ctx, p->created);
        cache_object_write_s32(ctx, p->index);
        cache_object_write_s32(ctx, p->scope);
        cache_object_write_str(ctx, p->resource, (uint32_t) strlen(p->resource));
        am_name_value_serialise(ctx, p->response_attributes);
        am_name_value_serialise(ctx, p->response_decisions);
        am_action_decision_serialise(ctx, p->action_decisions);
        p = p->next;
    }
    return 0;
}

int am_pdp_entry_serialise(struct cache_object_ctx *ctx, const char *url,
        const char *file, const char *content_type, int method) {
    cache_object_write_str(ctx, url, ISVALID(url) ? (uint32_t) strlen(url) : 0);
    cache_object_write_str(ctx, file, ISVALID(file) ? (uint32_t) strlen(file) : 0);
    cache_object_write_str(ctx, content_type, ISVALID(content_type) ? (uint32_t) strlen(content_type) : 0);
    cache_object_write_s32(ctx, method);
    return 0;
}

int am_pdp_entry_deserialise(struct cache_object_ctx *ctx, char **url,
        char **file, char **content_type, int *method) {
    cache_object_read_str(ctx, url, NULL);
    cache_object_read_str(ctx, file, NULL);
    cache_object_read_str(ctx, content_type, NULL);
    cache_object_read_s32(ctx, method);
    return 0;
}

struct am_namevalue *am_name_value_deserialise(struct cache_object_ctx *ctx) {
    struct am_namevalue *list = NULL;
    uint32_t count = 0;

    cache_object_read_map(ctx, &count);

    while (count--) {
        struct am_namevalue *r = malloc(sizeof (struct am_namevalue));
        if (r == NULL) {
            ctx->error = AM_ENOMEM;
            break;
        }
        cache_object_read_str(ctx, &r->n, (uint32_t *) & r->ns);
        cache_object_read_str(ctx, &r->v, (uint32_t *) & r->vs);
        r->next = NULL;
        AM_LIST_INSERT(list, r);
    }
    return list;
}

struct am_action_decision *am_action_decision_deserialise(struct cache_object_ctx *ctx) {
    struct am_action_decision *list = NULL;
    uint32_t count = 0;

    cache_object_read_array(ctx, &count);

    while (count--) {
        struct am_action_decision *r = malloc(sizeof (struct am_action_decision));
        if (r == NULL) {
            ctx->error = AM_ENOMEM;
            break;
        }
        cache_object_read_u64(ctx, &r->ttl);
        cache_object_read_s32(ctx, &r->method);
        cache_object_read_s32(ctx, &r->action);
        r->advices = am_name_value_deserialise(ctx);
        r->next = NULL;
        AM_LIST_INSERT(list, r);
    }
    return list;
}

struct am_policy_result *am_policy_result_deserialise(struct cache_object_ctx *ctx) {
    struct am_policy_result *list = NULL;
    uint32_t count = 0;

    cache_object_read_array(ctx, &count);

    while (count--) {
        struct am_policy_result *r = malloc(sizeof (struct am_policy_result));
        if (r == NULL) {
            ctx->error = AM_ENOMEM;
            break;
        }
        cache_object_read_u64(ctx, &r->created);
        cache_object_read_s32(ctx, &r->index);
        cache_object_read_s32(ctx, &r->scope);
        cache_object_read_str(ctx, &r->resource, NULL);
        r->response_attributes = am_name_value_deserialise(ctx);
        r->response_decisions = am_name_value_deserialise(ctx);
        r->action_decisions = am_action_decision_deserialise(ctx);
        r->next = NULL;
        AM_LIST_INSERT(list, r);
    }
    return list;
}

int am_policy_epoch_deserialise(struct cache_object_ctx *ctx, uint64_t *time_addr) {
    cache_object_read_u64(ctx, time_addr);
    return ctx->error;
}

int am_policy_epoch_serialise(struct cache_object_ctx *ctx, uint64_t time) {
    cache_object_write_u64(ctx, time);
    return ctx->error;
}


