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
 * Copyright 2014 - 2016 ForgeRock AS.
 */

#include "platform.h"
#include "am.h"
#include "utility.h"

#define URL_MATCHING_STACK_SZ 64

static const char *policy_fetch_scope_str[] = {
    "self",
    "subtree",
    "response-attributes-only"
};

const char *am_policy_strerror(char status) {
    switch (status) {
        case AM_EXACT_MATCH: return "exact match";
        case AM_EXACT_PATTERN_MATCH: return "exact pattern match";
        default:
            return "no match";
    }
}

static char compare_resource(am_request_t *r, const char *pattern, const char *resource) {
    char status = AM_FALSE;
    char case_sensitive = (r != NULL && r->conf != NULL) ?
            !(r->conf->url_eval_case_ignore) : AM_FALSE;
    if (case_sensitive) {
        if (strcmp(pattern, resource) == 0)
            status = AM_TRUE;
    } else {
        if (strcasecmp(pattern, resource) == 0)
            status = AM_TRUE;
    }
    return status;
}

typedef struct {
    const char *p, *u;
    enum { multilevel, onelevel, none } skip;

} matching_stack_t;

static am_bool_t compare_chars(am_request_t * r, char a, char b) {
    return r->conf->url_eval_case_ignore ? tolower(a) == tolower(b) : a == b;

}

/*
 * algorithm for matcing URLs with patterns that have * and -*- as wildcards
 *
 * this has full backtracking.
 */
static am_bool_t url_pattern_match_with_backtrack(am_request_t *r, matching_stack_t * stack, int stacksize,
                      const char * pattern, const char * url) {
    const char *p = pattern, *u = url;
   
    int top = 0;

    stack[top].skip = none;

#define push(a, b, s)     stack[top].p = a; stack[top].u = b; stack[top].skip = s
#define next(a, b)        a = stack[top].p; b = ++stack[top].u

    if (*p == '*') {
        p += 1; push(p, u, multilevel);

    } else if (*p == '-' && p[1] == '*' && p[2] == '-') {
        p += 3; push(p, u, onelevel);

    }

    while (*u) {
        if (compare_chars(r, *p, *u)) {
            p++; u++;

        } else {
            do {
                if (stack[top].skip == multilevel) {
                    if (*stack[top].u != '?')
                        break;

                } else if (stack[top].skip == onelevel) {
                    if (*stack[top].u != '?' && *stack[top].u != '/')
                        break;

                } else {
                    return AM_FALSE;

                }

                if (top-- == 0)
                    return AM_FALSE;

            } while (1);

            next(p, u);

        }

        if (*p == '*') {
            if (++top == stacksize)
                return AM_FALSE;

            p += 1; push(p, u, multilevel);

        } else if (*p == '-' && p[1] == '*' && p[2] == '-') {
            if (++top == stacksize)
                return AM_FALSE;

            p += 3; push(p, u, onelevel);

        }

    }
    return *p == 0;

}

/*
 * decide whether a URL matches a URL pattern using a backtracking algorithm
 * and a stack allocated here.
 *
 * this uses a heap allocated stack which is large enough to allow 64 frames, which
 * corresponds to patterns with 64 wildcard characters * or -*-. Should be large enough.
 */
am_bool_t compare_pattern_resource(am_request_t *r, const char * pattern, const char * url) {
    matching_stack_t * stack = malloc(sizeof(matching_stack_t) * URL_MATCHING_STACK_SZ);
    am_bool_t out;

    if (stack) {
        out = url_pattern_match_with_backtrack(r, stack, URL_MATCHING_STACK_SZ, pattern, url);
        free(stack);

    } else {
        AM_LOG_ERROR(r->instance_id, "unable to allocate URL pattern matching stack");
        out = AM_FALSE;

    }
    return out;

}

#define end_of_protocol(offsets) (offsets [0])
#define start_of_host(offsets) (end_of_protocol(offsets) + 3)

#define port_marker(offsets) (offsets [1])
#define start_of_port(offsets) (port_marker(offsets) + 1)
#define end_of_port(offsets) start_of_path(offsets)

#define start_of_path(offsets) (offsets [2])

/**
 * Gets offsets of parts of a URL, setting them in the array (allocated by the caller).
 * Returns AM_TRUE if the url passes the basic sanity tests of having '://' followed by a path section.
 * Note: a pattern with wildcards does not have to pass this test, but the incoming URL must.
 *
 * The returned offsets are as follows:
 * 0 <- offset of '://' end of scheme
 * 1 <- the ':' before a port number if it exists
 * 2 <- the '/' at the start of the path section, or if there is no path, a '?' or '\0'
 */
static am_bool_t policy_get_url_offsets(const char *url, int *offsets) {
    am_bool_t got_protocol = AM_FALSE;
    int i;
    
    port_marker(offsets) = 0;
    
    for (i = 0; url [i]; i++) {
        switch (url [i]) {
            case ':':
                if (got_protocol) {
                    port_marker(offsets) = i;
                } else {
                    end_of_protocol(offsets) = i;
                    if (url [++i] == '/' && url [++i] == '/')
                        got_protocol = AM_TRUE;
                    else
                        return AM_FALSE;
                }
                break;
                
            case '/':
            case '?':
                if (got_protocol) {
                    start_of_path(offsets) = i; // start of path (or query, as in a.b.c?query)
                    return AM_TRUE;
                }
                break;
        }
    }
    if (got_protocol) {
        start_of_path(offsets) = i; // no path, set to offset of '\0'
        return AM_TRUE;
    }
    return AM_FALSE;
}

/*
 * Normalise the resource pattern by adding the default port for the protocol if it is unspecified.
 *
 * @param an input resource pattern
 * @return if the port can be derived, an allocated string with the noralised pattern, else NULL
 */
char *am_normalize_pattern(const char *url) {
    unsigned port = 0;
    char *protocol;
    int offsets [] = { 0, 0, 0 };
    
    policy_get_url_offsets(url, offsets);
    if (end_of_protocol(offsets) && !port_marker(offsets)) {
        // do we have a wildcard intended to include the port?
        if (url [start_of_path(offsets) - 1] == '*')
            return NULL;
        
        // determine default port for the protocol
        protocol = strndup(url, end_of_protocol(offsets));
        if (strcasecmp(protocol, "http") == 0) {
            port = 80;
        } else if (strcasecmp(protocol, "https") == 0) {
            port = 443;
        }
        free(protocol);
        
        if (port) {
            // reconstruct URL with the default port
            char * buffer = NULL;
            am_asprintf(&buffer, "%.*s:%u%s", start_of_path(offsets), url, port, url + start_of_path(offsets));
            return buffer;
        }
    }
    return NULL;
}

/*
 * Match sections within the pattern and resource.
 */
static char compare_pattern_sections(am_request_t *r,
                                     const char *pattern_base, size_t pattern_lo, size_t pattern_hi,
                                     const char *resource_base, size_t resource_lo, size_t resource_hi) {
    char * pattern_section = strndup(pattern_base + pattern_lo, pattern_hi - pattern_lo);
    char * resource_section = strndup(resource_base + resource_lo, resource_hi - resource_lo);
    
    char c;
    if (pattern_section && resource_section)
        c = compare_pattern_resource(r, pattern_section, resource_section);
    else
        c = AM_NO_MATCH;
    
    AM_FREE(pattern_section, resource_section);
    return c;
}

char policy_compare_url(am_request_t *r, const char *pattern, const char *resource) {
    static const char *thisfunc = "policy_compare_url():";
    char has_wildcard = AM_FALSE;
    int pi[3] = {0, 0, 0};
    int ri[3] = {0, 0, 0};
    char match;
    unsigned long instance_id = r != NULL ? r->instance_id : 0;

    if (pattern == NULL || resource == NULL)
        return AM_NO_MATCH;

    /* validate pattern */
    if (strchr(pattern, '*') != NULL) {
        if (strlen(pattern) == 1 || strstr(pattern, " *") != NULL || strstr(pattern, "* ") != NULL) {
            /*
             * pattern matching algorithm forbids:
             * - wildcard only (i.e. "all allowed")
             * - white-space before/after a wildcard, though this is unlikely to be matched, because url list 
             *   is passed down to an agent as a space separated value object
             */
            AM_LOG_WARNING(instance_id, "%s invalid pattern '%s'",
                    thisfunc, pattern);
            return AM_NO_MATCH;
        }
        has_wildcard = AM_TRUE;
    }

    if (!has_wildcard) {
        /* no wildcard */
        match = compare_resource(r, pattern, resource);
        return match ? AM_EXACT_MATCH : AM_NO_MATCH;
    }

    /* resource must have regular URL structure */
    if (! policy_get_url_offsets(resource, ri))
        return AM_NO_MATCH;
    
    if (! policy_get_url_offsets(pattern, pi)) {
        /* pattern has not got regular URL structure, so match the resource as a whole */
        return compare_pattern_resource(r, pattern, resource) ? AM_EXACT_PATTERN_MATCH : AM_NO_MATCH;
    }
    
    /* compare protocol */
    if (! compare_pattern_sections(r, pattern, 0, end_of_protocol(pi), resource, 0, end_of_protocol(ri)))
        return AM_NO_MATCH;
    
    if (port_marker(pi) && port_marker(ri)) {
        /* compare hosts - up to ports */
        if (! compare_pattern_sections(r, pattern, start_of_host(pi), port_marker(pi), resource, start_of_host(ri), port_marker(ri)))
            return AM_NO_MATCH;

        /* compare ports */
        if (! compare_pattern_sections(r, pattern, start_of_port(pi), start_of_path(pi), resource, start_of_port(ri), start_of_path(ri)))
            return AM_NO_MATCH;
    } else {
        /* compare hosts - up to paths */
        if (! compare_pattern_sections(r, pattern, start_of_host(pi), start_of_path(pi), resource, start_of_host(ri), start_of_path(ri)))
            return AM_NO_MATCH;
    }
    
    /* compare paths and query */
    if (! compare_pattern_sections(r, pattern, start_of_path(pi), strlen(pattern), resource, start_of_path(ri), strlen(resource)))
        return AM_NO_MATCH;
    
    return AM_EXACT_PATTERN_MATCH;
}

int am_scope_to_num(const char *scope) {
    int i;
    if (scope != NULL) {
        for (i = 0; i < ARRAY_SIZE(policy_fetch_scope_str); i++) {
            if (strcasecmp(scope, policy_fetch_scope_str[i]) == 0) {
                return i;
            }
        }
    }
    return 0;
}

const char *am_scope_to_str(int scope) {
    if (scope >= ARRAY_SIZE(policy_fetch_scope_str)) {
        return policy_fetch_scope_str[0];
    }
    return policy_fetch_scope_str[scope];
}
