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

#include "platform.h"
#include "am.h"
#include "utility.h"
#include "expat.h"
#include "list.h"

/*
 * XML parser for SAML elements (LARES response)
 */

typedef struct {
    unsigned long instance_id;
    char setting_value;
    char *data;
    int data_sz;
    int status;
    struct am_namevalue *list;
    void *parser;
} am_xml_parser_ctx_t;

static void start_element(void *userData, const char *name, const char **atts) {
    am_xml_parser_ctx_t *ctx = (am_xml_parser_ctx_t *) userData;

    am_free(ctx->data);
    ctx->data = NULL;
    ctx->data_sz = 0;
    ctx->setting_value = 0;
    
    if (strcmp(name, "saml:NameIdentifier") == 0) {
        ctx->setting_value = 1;
    }
}

static void end_element(void * userData, const char * name) {
    am_xml_parser_ctx_t *ctx = (am_xml_parser_ctx_t *) userData;
    char alloc = 0, *clean = NULL;
    size_t sz = 0;
    struct am_namevalue *el = NULL;
    char *val = ctx->data;
    int len = ctx->data_sz;

    ctx->setting_value = 0;
    if (!ISVALID(ctx->data)) return;

    if (memchr(val, '%', len) != NULL) {
        char *t = strndup(val, len);
        clean = url_decode(t);
        sz = strlen(clean);
        alloc = 1;
        am_free(t);
    } else {
        clean = (char *) val;
        sz = len;
    }

    if (create_am_namevalue_node("sid", 3, clean, sz, &el) == 0) {
        AM_LIST_INSERT(ctx->list, el);
    }
    if (alloc && clean) {
        free(clean);
    }
    am_free(ctx->data);
    ctx->data = NULL;
    ctx->data_sz = 0;
}

static void character_data(void *userData, const char *val, int len) {
    char *tmp;
    am_xml_parser_ctx_t *ctx = (am_xml_parser_ctx_t *) userData;
    if (ctx->setting_value == 0 || len <= 0) return;

    tmp = realloc(ctx->data, ctx->data_sz + len + 1);
    if (tmp == NULL) {
        am_free(ctx->data);
        ctx->data = NULL;
        ctx->data_sz = 0;
        ctx->status = AM_ENOMEM;
        return;
    }
    ctx->data = tmp;
    memcpy(ctx->data + ctx->data_sz, val, len);
    ctx->data_sz += len;
    ctx->data[ctx->data_sz] = 0;
}

static void entity_declaration(void *userData, const XML_Char *entityName,
        int is_parameter_entity, const XML_Char *value, int value_length, const XML_Char *base,
        const XML_Char *systemId, const XML_Char *publicId, const XML_Char *notationName) {
    am_xml_parser_ctx_t *ctx = (am_xml_parser_ctx_t *) userData;
    XML_StopParser(ctx->parser, XML_FALSE);
}

void *am_parse_session_saml(unsigned long instance_id, const char *xml, size_t xml_sz) {
    static const char *thisfunc = "am_parse_session_saml():";
    struct am_namevalue *e, *t, *r = NULL;

    am_xml_parser_ctx_t xctx = {.instance_id = instance_id,
        .list = NULL, .parser = NULL, .data_sz = 0, .data = NULL, .status = AM_SUCCESS};

    if (xml == NULL || xml_sz == 0) {
        AM_LOG_ERROR(instance_id, "%s memory allocation error", thisfunc);
        return NULL;
    } else {
        XML_Parser parser = XML_ParserCreate("UTF-8");
        xctx.parser = &parser;
        XML_SetUserData(parser, &xctx);
        XML_SetElementHandler(parser, start_element, end_element);
        XML_SetCharacterDataHandler(parser, character_data);
        XML_SetEntityDeclHandler(parser, entity_declaration);
        if (XML_Parse(parser, xml, (int) xml_sz, XML_TRUE) == XML_STATUS_ERROR) {
            const char *message = XML_ErrorString(XML_GetErrorCode(parser));
            XML_Size line = XML_GetCurrentLineNumber(parser);
            XML_Size col = XML_GetCurrentColumnNumber(parser);
            AM_LOG_ERROR(instance_id, "%s xml parser error (%d:%d) %s", thisfunc,
                    line, col, message);
            delete_am_namevalue_list(&xctx.list);
        } else {
            r = xctx.list;
        }
        XML_ParserFree(parser);
    }

    if (r != NULL) {

        AM_LIST_FOR_EACH(r, e, t) {
            AM_LOG_DEBUG(instance_id, "%s name: '%s' value: '%s'", thisfunc,
                    e->n, e->v != NULL ? e->v : "NULL");
        }
    }

    if (xctx.status != AM_SUCCESS) {
        AM_LOG_ERROR(instance_id, "%s %s", thisfunc, am_strerror(xctx.status));
    }

    return (void *) r;
}
