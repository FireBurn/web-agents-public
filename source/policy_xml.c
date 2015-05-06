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
 * XML parser for 'PolicyResponse' elements
 */

enum {
    AMP_RESOURCE_RESULT = 1 << 0,
    AMP_RESPONSE_ATTRIBUTE = 1 << 1,
    AMP_ACTION_DECISION = 1 << 2,
    AMP_RESPONSE_DECISION = 1 << 3,
    AMP_ATTRIBUTE_VALUE_PAIR = 1 << 4,
    AMP_ATTRIBUTE_VALUE = 1 << 5,
    AMP_ACTION_DECISION_ADVICE = 1 << 6,
    AMP_ATTRIBUTE_NAME = 1 << 7
};

typedef struct {
    int scope;
    int index;
    int ty;
    char *attribute_name;
    uint64_t ttl;
    unsigned long instance_id;
    struct am_policy_result *list;
    struct am_policy_result *curr_policy;
    struct am_action_decision *curr_action_decision;
    void *parser;
} am_xml_parser_ctx_t;

int create_am_namevalue_node(const char *n, size_t ns,
        const char *v, size_t vs, struct am_namevalue **node) {
    struct am_namevalue *t;
    if (n == NULL || ns == 0 || v == NULL || vs == 0) return 1;
    t = malloc(sizeof (struct am_namevalue));
    if (t == NULL) return 1;
    t->n = malloc(ns + 1);
    if (t->n == NULL) {
        free(t);
        return 1;
    }
    memcpy(t->n, n, ns);
    t->n[ns] = 0;
    t->ns = ns;
    t->v = malloc(vs + 1);
    if (t->v == NULL) {
        free(t->n);
        free(t);
        return 1;
    }
    memcpy(t->v, v, vs);
    t->v[vs] = 0;
    t->vs = vs;
    t->next = NULL;
    *node = t;
    return 0;
}

/**
 * Allocate storage for an am_action_decision from dynamic memory (malloc, as opposed to shared memory).
 * The result is placed into *node (see last parameter), while the function's return value seems to be 1
 * if things go wrong and 0 if we succeed - more of an exit status than a boolean value.
 */
int create_am_action_decision_node(boolean action, char method, uint64_t ttl, struct am_action_decision **node) {
    
    struct am_action_decision *action_decision = malloc(sizeof (struct am_action_decision));
    
    if (action_decision == NULL) {
        return 1;
    }
    action_decision->action = action;
    action_decision->method = method;
    action_decision->ttl = ttl;
    action_decision->advices = NULL;
    action_decision->next = NULL;
    *node = action_decision;
    return 0;
}

int create_am_policy_result_node(const char *resource, size_t resource_size, struct am_policy_result **node) {
    
    struct am_policy_result *policy_result;
    
    if (resource == NULL || resource_size == 0) {
        return 1;
    }
    policy_result = calloc(1, sizeof (struct am_policy_result));
    if (policy_result == NULL) {
        return 1;
    }
    policy_result->resource = malloc(resource_size + 1);
    if (policy_result->resource == NULL) {
        free(policy_result);
        return 1;
    }
    memcpy(policy_result->resource, resource, resource_size);
    policy_result->resource[resource_size] = '\0';
    policy_result->scope = -1;
    *node = policy_result;
    return 0;
}

static void start_element(void *userData, const char *name, const char **atts) {
    int i;
    am_xml_parser_ctx_t *ctx = (am_xml_parser_ctx_t *) userData;

    do {
        if (strcmp(name, "ResourceResult") == 0) {
            for (i = 0; atts[i]; i += 2) {
                if (strcasecmp(atts[i], "name") == 0) {
                    struct am_policy_result *el = NULL;
                    if (create_am_policy_result_node(atts[i + 1], strlen(atts[i + 1]), &el) != 0) {
                        return;
                    }
                    AM_LIST_INSERT(ctx->list, el);
                    el->index = ++ctx->index;
                    el->scope = ctx->scope;
                    ctx->curr_policy = el;
                    break;
                }
            }
            ctx->ty = AMP_RESOURCE_RESULT; /*reset the state*/
            break;
        }
        if (strcmp(name, "ResponseAttributes") == 0) {
            ctx->ty |= AMP_RESPONSE_ATTRIBUTE;
            break;
        }
        if (strcmp(name, "ActionDecision") == 0) {
            if (ctx->curr_policy) {
                struct am_action_decision *el = NULL;
                if (create_am_action_decision_node(AM_FALSE, AM_REQUEST_UNKNOWN, 0, &el) == 0) {
                    AM_LIST_INSERT(ctx->curr_policy->action_decisions, el);
                    ctx->curr_action_decision = el;

                    for (i = 0; atts[i]; i += 2) {
                        if (strcasecmp(atts[i], "timeToLive") == 0) {
#ifdef _WIN32
                            el->ttl = _strtoui64(atts[i + 1], NULL, AM_BASE_TEN);
#else
                            el->ttl = strtoull(atts[i + 1], NULL, AM_BASE_TEN);
#endif
                            break;
                        }
                    }
                }
            }
            /* if out of context, silently ignore */
            ctx->ty |= AMP_ACTION_DECISION;
            break;
        }
        if (strcmp(name, "ResponseDecisions") == 0) {
            ctx->ty |= AMP_RESPONSE_DECISION;
            break;
        }
        if (strcmp(name, "AttributeValuePair") == 0) {
            ctx->ty |= AMP_ATTRIBUTE_VALUE_PAIR;
            break;
        }
        if (strcmp(name, "Attribute") == 0) {
            for (i = 0; atts[i]; i += 2) {
                if (strcasecmp(atts[i], "name") == 0) {
                    ctx->attribute_name = strdup(atts[i + 1]);
                    ctx->ty |= AMP_ATTRIBUTE_NAME;
                    break;
                }
            }
            break;
        }
        if (strcmp(name, "Value") == 0) {
            ctx->ty |= AMP_ATTRIBUTE_VALUE;
            break;
        }
        if (strcmp(name, "Advices") == 0) {
            ctx->ty |= AMP_ACTION_DECISION_ADVICE;
            break;
        }
    } while (0);
}

static void end_element(void *userData, const char *name) {
    am_xml_parser_ctx_t *ctx = (am_xml_parser_ctx_t *) userData;

    if (strcmp(name, "ResourceResult") == 0) {
        ctx->ty = 0;
    }
    if (strcmp(name, "ResponseAttributes") == 0) {
        ctx->ty &= (~AMP_RESPONSE_ATTRIBUTE);
    }
    if (strcmp(name, "ActionDecision") == 0) {
        ctx->ty &= (~AMP_ACTION_DECISION);
        ctx->curr_action_decision = NULL;
    }
    if (strcmp(name, "ResponseDecisions") == 0) {
        ctx->ty &= (~AMP_RESPONSE_DECISION);
    }
    if (strcmp(name, "AttributeValuePair") == 0) {
        ctx->ty &= (~AMP_ATTRIBUTE_VALUE_PAIR);
        am_free(ctx->attribute_name);
        ctx->attribute_name = NULL;
    }
    if (strcmp(name, "Attribute") == 0) {
        ctx->ty &= (~AMP_ATTRIBUTE_NAME);
    }
    if (strcmp(name, "Value") == 0) {
        ctx->ty &= (~AMP_ATTRIBUTE_VALUE);
    }
    if (strcmp(name, "Advices") == 0) {
        ctx->ty &= (~AMP_ACTION_DECISION_ADVICE);
    }
}

static void character_data(void *userData, const char *val, int len) {
    am_xml_parser_ctx_t *ctx = (am_xml_parser_ctx_t *) userData;
    if (len <= 0 || val[0] == '\r' || val[0] == '\n') return;

    if (ctx->attribute_name) {
        switch (ctx->ty) {
            case AMP_RESOURCE_RESULT + AMP_RESPONSE_ATTRIBUTE + AMP_ATTRIBUTE_VALUE_PAIR + AMP_ATTRIBUTE_VALUE:
                if (ctx->curr_policy) {
                    struct am_namevalue *el = NULL;
                    if (create_am_namevalue_node(ctx->attribute_name, strlen(ctx->attribute_name), val, len, &el) == 0) {
                        AM_LIST_INSERT(ctx->curr_policy->response_attributes, el);
                    }
                }
                break;

            case AMP_RESOURCE_RESULT + AMP_RESPONSE_DECISION + AMP_ATTRIBUTE_VALUE_PAIR + AMP_ATTRIBUTE_VALUE:
                if (ctx->curr_policy) {
                    struct am_namevalue *el = NULL;
                    if (create_am_namevalue_node(ctx->attribute_name, strlen(ctx->attribute_name), val, len, &el) == 0) {
                        AM_LIST_INSERT(ctx->curr_policy->response_decisions, el);
                    }
                }
                break;

            case AMP_RESOURCE_RESULT + AMP_ACTION_DECISION + AMP_ATTRIBUTE_VALUE_PAIR + AMP_ATTRIBUTE_VALUE:
                if (ctx->curr_action_decision) {
                    ctx->curr_action_decision->method = am_method_str_to_num(ctx->attribute_name);
                    ctx->curr_action_decision->action = strncasecmp(val, "allow", len) == 0;
                }
                break;

            case AMP_RESOURCE_RESULT + AMP_ACTION_DECISION + AMP_ACTION_DECISION_ADVICE + AMP_ATTRIBUTE_VALUE_PAIR + AMP_ATTRIBUTE_VALUE:
                if (ctx->curr_action_decision) {
                    struct am_namevalue *el = NULL;
                    if (create_am_namevalue_node(ctx->attribute_name, strlen(ctx->attribute_name), val, len, &el) == 0) {
                        AM_LIST_INSERT(ctx->curr_action_decision->advices, el);
                    }
                }
                break;
        }
    }
}

static void entity_declaration(void *userData, const XML_Char *entityName,
        int is_parameter_entity, const XML_Char *value, int value_length, const XML_Char *base,
        const XML_Char *systemId, const XML_Char *publicId, const XML_Char *notationName) {
    am_xml_parser_ctx_t *ctx = (am_xml_parser_ctx_t *) userData;
    XML_StopParser(ctx->parser, XML_FALSE);
}

void *am_parse_policy_xml(unsigned long instance_id, const char *xml, size_t xml_sz, int scope) {
    static const char *thisfunc = "am_parse_policy_xml():";
    char *begin, *stream = NULL;
    size_t data_sz;
    struct am_policy_result *r = NULL;

    am_xml_parser_ctx_t xctx = {.instance_id = instance_id,
        .list = NULL, .parser = NULL, .ty = 0, .attribute_name = NULL, .index = 0,
        .curr_policy = NULL, .scope = scope};

    if (xml == NULL || xml_sz == 0) {
        AM_LOG_ERROR(instance_id, "%s memory allocation error", thisfunc);
        return NULL;
    }

    begin = strstr(xml, "![CDATA[");
    if (begin != NULL) {
        char *end = strstr(begin + 8, "]]>");
        if (end != NULL) {
            stream = begin + 8;
            data_sz = end - (begin + 8);
        }
    } else {
        /*no CDATA*/
        stream = (char *) xml;
        data_sz = xml_sz;
    }

    if (stream != NULL && data_sz > 0) {
        XML_Parser parser = XML_ParserCreate("UTF-8");
        xctx.parser = &parser;
        XML_SetUserData(parser, &xctx);
        XML_SetElementHandler(parser, start_element, end_element);
        XML_SetCharacterDataHandler(parser, character_data);
        XML_SetEntityDeclHandler(parser, entity_declaration);
        if (XML_Parse(parser, stream, (int) data_sz, XML_TRUE) == XML_STATUS_ERROR) {
            const char *message = XML_ErrorString(XML_GetErrorCode(parser));
            XML_Size line = XML_GetCurrentLineNumber(parser);
            XML_Size col = XML_GetCurrentColumnNumber(parser);
            AM_LOG_ERROR(instance_id, "%s xml parser error (%lu:%lu) %s", thisfunc,
                    (unsigned long) line, (unsigned long) col, message);
            delete_am_policy_result_list(&xctx.list);
        } else {
            r = xctx.list;
        }
        XML_ParserFree(parser);
    }

    return (void *) r;
}

static void delete_am_action_decision_list(struct am_action_decision **list) {
    struct am_action_decision *t = list != NULL ? *list : NULL;
    if (t != NULL) {
        delete_am_action_decision_list(&t->next);
        delete_am_namevalue_list(&t->advices);
        free(t);
        t = NULL;
    }
}

void delete_am_policy_result_list(struct am_policy_result **list) {
    struct am_policy_result *t = list != NULL ? *list : NULL;
    if (t != NULL) {
        delete_am_policy_result_list(&t->next);
        delete_am_namevalue_list(&t->response_attributes);
        delete_am_namevalue_list(&t->response_decisions);
        delete_am_action_decision_list(&t->action_decisions);
        am_free(t->resource);
        free(t);
        t = NULL;
    }
}

/* split am_policy_result list into two for parallel processing inside validate_policy() */
void am_policy_result_split(struct am_policy_result **list, struct am_policy_result **odd,
        struct am_policy_result **even) {
    struct am_policy_result *odd_tail = NULL;
    struct am_policy_result *even_tail = NULL;
    *odd = *even = NULL;
    if (list || *list == NULL) {
        return;
    } else {
        struct am_policy_result *iterator = *list;
        while (iterator != NULL) {
            struct am_policy_result *next = NULL;
            if (iterator->index % 2 == 0) {
                if (*even == NULL) {
                    *even = even_tail = iterator;
                } else {
                    even_tail->next = iterator;
                    even_tail = iterator;
                }
            } else {
                if (*odd == NULL) {
                    *odd = odd_tail = iterator;
                } else {
                    odd_tail->next = iterator;
                    odd_tail = iterator;
                }
            }
            next = iterator->next;
            iterator->next = NULL;
            iterator = next;
        }
    }
}
