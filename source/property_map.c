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

#ifndef PROPERTY_HASH_TABLE_PRIME
#define PROPERTY_HASH_TABLE_PRIME 83
#endif

#define HASH32(data, len) am_hash_buffer(data, len)

/*
 * this is a map entry, and they are linked where there are hash collisions
 */
struct map_entry
{
    char *key, *value;
    struct map_entry *n;
};

/*
 * create the initial hash table, which has a fixed length
 */
struct map_entry **property_map_create() {
    struct map_entry **map = calloc(PROPERTY_HASH_TABLE_PRIME, sizeof(struct map_entry *));
    return map;
}

/*
 * free all memory used by the hash table and its entires
 */
void property_map_delete(struct map_entry **map) {
    struct map_entry *e;
    int h;
    for (h = 0; h < PROPERTY_HASH_TABLE_PRIME; h++) {
        while ( (e = map[h]) ) {
            map[h] = e->n;
            free(e->key);
            if (e->value)
                free(e->value);
            
            free(e);
        }
    }
    free(map);
}

/*
 * iterate through the hash map with callback for each map entry
 */
void property_map_visit(struct map_entry **map, am_bool_t (*callback)(char *key, char *value, void *data), void *data) {
    struct map_entry *e;
    int h;
    for (h = 0; h < PROPERTY_HASH_TABLE_PRIME; h++) {
        for (e =  map[h]; e; e = e->n) {
            if (! callback(e->key, e->value, data))
                return;
        }
    }
}

/*
 * return a value from the hash map for a key
 */
char *property_map_get_value(struct map_entry **map, const char *key) {
    struct map_entry *e;
    
    uint32_t h = HASH32(key, strlen(key)) % PROPERTY_HASH_TABLE_PRIME;
    for (e = map[h]; e; e = e->n) {
        if (strcmp(key, e->key) == 0)
            return e->value;
    }
    return NULL;
}

/*
 * get hash map entry, and create one if it doesn't exist
 */
static struct map_entry *property_map_get_or_create(struct map_entry **map, const char *key, size_t len) {
    struct map_entry *e;
    
    uint32_t h = HASH32(key, len) % PROPERTY_HASH_TABLE_PRIME;
    for (e = map[h]; e; e = e->n) {
        if (strncmp(key, e->key, len) == 0 && e->key[len] == 0)
            return e;
    }
    
    e = malloc(sizeof(struct map_entry));
    e->key = strndup(key, len);
    e->value = 0;
    
    e->n = map[h];
    map[h] = e;
    
    return e;
}

/*
 * remove a key from the hash map
 */
am_bool_t property_map_remove_key(struct map_entry **map, const char *key) {
    struct map_entry **addr, *e;
    
    uint32_t h = HASH32(key, strlen(key)) % PROPERTY_HASH_TABLE_PRIME;
    for (addr = map + h; (e = *addr); addr = &e->n) {
        if (strcmp(key, e->key) == 0) {
            break;
        }
    }
    if (e) {
        *addr = e->n;
        free(e->key);
        if (e->value)
            free(e->value);
        
        free(e);
    }
    return e != NULL;
}

/*
 * return address of value, which can be updated in user space, but must be freeable
 */
char **property_map_get_value_addr(struct map_entry **map, const char *key) {
    struct map_entry *e = property_map_get_or_create(map, key, strlen(key));
    return &e->value;
}

/*
 * return pointer to non-space character, and set length to last non-space character
 */
static char *get_nonspace_section(char *s, char *e, size_t *len) {
    while (s < e && isspace(*s))
        s++;
    
    while (s < e && isspace(e[-1]))
        e--;
    
    *len = e - s;
    return s;
}

/*
 * parse <property> = <value> configuration element
 */
static void property_map_parse_line(struct map_entry **map, char *source, am_bool_t override, void (*logf)(const char *format, ...), char *line, size_t line_ln) {
    char *eq = memchr(line, '=', line_ln);
    if ( eq ) {
        size_t key_ln, value_ln;
        
        char *key = get_nonspace_section(line, eq, &key_ln);
        struct map_entry *p = property_map_get_or_create(map, key, key_ln);

        char *value = get_nonspace_section(eq + 1, line + line_ln, &value_ln);
        char *old_value = p->value;
        
        if (old_value) {
            if (override) {
                p->value = strndup(value, value_ln);
                if (strcmp(old_value, p->value)) {
                    logf("%s property %s updates value '%s' to '%s'\n", source, p->key, old_value, p->value);
                }
                free(old_value);
            }
        } else {
            p->value = strndup(value, value_ln);
            logf("%s property %s set to '%s'\n", source, p->key, p->value);
        }
    }
}

/*
 * parse the content of a configuraiton file (data, data_sz) changing mapped properties only if verride is set
 */
void property_map_parse(struct map_entry **map, char *source, am_bool_t override, void (*logf)(const char *format, ...), char *data, size_t data_sz) {
    int i;
    int s = 0;
    for (i = 0; i < data_sz; i++) {
        if (data[i] == '\n') {          /* NOTE: the line parser will strip \r for non-unix line endings */
            if (data[s] != '#') {       /* discard comment lines */
                property_map_parse_line(map, source, override, logf, data + s, i - s);
            }
            s = i + 1;
        }
    }
    if (s < data_sz) {
        if (data[s] != '#') {           /* discard comment lines */
            property_map_parse_line(map, source, override, logf, data + s, data_sz - s);
        }
    }
}

struct writer_data
{
    size_t len;
    char *buffer;
};

static am_bool_t writer_data_callback(char *key, char *value, void *data) {
    struct writer_data *fw = data;
    fw->len = (size_t) am_asprintf(&fw->buffer, "%s%s = %s\r\n", fw->buffer, key, value);
    if (fw->buffer == NULL) {
        return AM_FALSE;
    }
    return AM_TRUE;
}

/*
 * write property map to a string
 */
char *property_map_write_to_buffer(struct map_entry **map, size_t *data_sz) {
    struct writer_data writer_data = { 0, strdup("") };
    property_map_visit(map, writer_data_callback, &writer_data);
    
    *data_sz = writer_data.len;
    return writer_data.buffer;
}

