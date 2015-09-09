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
#define MAP_EXTENSION_SIZE 64

/* property flags */

enum entry_type { plaintext, property, property_removed };

struct map_entry
{
    char *key, *value;
    enum entry_type type;
};

struct property_map
{
    size_t size, alloc;
    struct map_entry *entries;
};

/*
 * create property map
 */
struct property_map *property_map_create() {
    struct property_map *map = malloc(sizeof(struct property_map));
    if (map == NULL) {
        return NULL;
    }
    map->size = 0;
    map->alloc = 0;
    map->entries = NULL;
    
    return map;
}

/*
 * free all memory used by the hash table and its entires
 */
void property_map_delete(struct property_map *map) {
    int i;
    struct map_entry *e;
    for (i = 0; i < map->size; i++) {
        e = map->entries + i;
        free(e->key);
        if (e->value)
            free(e->value);
    }
    free(map->entries);
    free(map);
}

/*
 * return a value from the property map for a key
 */
char *property_map_get_value(struct property_map *map, const char *key) {
    int i;
    struct map_entry *e;
    for (i = 0; i < map->size; i++) {
        e = map->entries + i;
        switch (e->type) {
            case plaintext:
                break;
                
            case property:
            case property_removed:
                if (strcmp(key, e->key) == 0)
                    return e->value;
        }
    }
    return NULL;
}

/*
 * ensure that the map has space for another entry
 */
static am_bool_t property_map_get_space(struct property_map *map) {
    if (map->size == map->alloc) {
        size_t alloc = map->alloc + MAP_EXTENSION_SIZE;
        struct map_entry *entries = realloc(map->entries, alloc * sizeof(struct map_entry));
        if (entries == NULL) {
            return AM_FALSE;
        }
        map->alloc = alloc;
        map->entries = entries;
    }
    return AM_TRUE;
}

/*
 * get property map entry, and create one if it doesn't exist
 */
static struct map_entry *property_map_get_or_create(struct property_map *map, const char *key, size_t len) {
    int i;
    struct map_entry *e;
    for (i = 0; i < map->size; i++) {
        e = map->entries + i;
        switch (e->type) {
            case plaintext:
                break;
                
            case property:
            case property_removed:
                if (strncmp(key, e->key, len) == 0 && e->key [len] == 0) {
                    e->type = property;
                    return e;
                }
        }
    }
    if (! property_map_get_space(map))
        return NULL;
    
    e = map->entries + map->size++;
    e->type = property;
    e->key = strndup(key, len);
    e->value = NULL;
    
    return e;
}

struct map_entry *property_map_add_plaintext(struct property_map *map, const char *text, size_t len) {
    struct map_entry *e;
    
    if (! property_map_get_space(map))
        return NULL;
    
    e = map->entries + map->size++;
    e->type = plaintext;
    e->key = strndup(text, len);
    e->value = NULL;
    
    return e;
}

/*
 * remove a key from the property map
 */
am_bool_t property_map_remove_key(struct property_map *map, const char *key) {
    int i;
    struct map_entry *e;
    for (i = 0; i < map->size; i++) {
        e = map->entries + i;
        if (e->type == property && strcmp(key, e->key) == 0) {
            break;
        }
    }
    if (i < map->size) {
        e = map->entries + i;
        e->type = property_removed;
        if (e->value)
        {
            free(e->value);
            e->value = 0;
        }
    }
    return i < map->size;
}

void property_map_visit(struct property_map *map, am_bool_t (*callback)(char *key, char *value, void *data), void *data) {
    int i;
    struct map_entry *e;
    for (i = 0; i < map->size; i++) {
        e = map->entries + i;
        if (e->type == property) {
            if (! callback(e->key, e->value, data))
                break;
        }
    }
}

/*
 * return address of value, which can be updated (freed and replaced) in callers space
 */
char **property_map_get_value_addr(struct property_map *map, const char *key) {
    struct map_entry *e = property_map_get_or_create(map, key, strlen(key));
    
    /* out of memory */
    if (e == NULL) {
        return NULL;
    }
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
static void property_map_parse_line(struct property_map *map, char *source, am_bool_t override, void (*logf)(const char *format, ...), char *line, size_t line_ln) {
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
    } else {
        size_t text_ln;
        char *text = get_nonspace_section(line, line + line_ln, &text_ln);
        property_map_add_plaintext(map, text, text_ln);
    }
}

/*
 * parse the content of a configuraiton file (data, data_sz) changing mapped properties only if verride is set
 */
void property_map_parse(struct property_map *map, char *source, am_bool_t override, void (*logf)(const char *format, ...), char *data, size_t data_sz) {
    int i;
    int s = 0;
    for (i = 0; i < data_sz; i++) {
        if (data[i] == '\n') {          /* NOTE: the line parser will strip \r for non-unix line endings */
            if (data[s] == '#') {
                property_map_add_plaintext(map, data + s, i - s);
            } else {
                property_map_parse_line(map, source, override, logf, data + s, i - s);
            }
            s = i + 1;
        }
    }
    if (s < data_sz) {
        if (data[s] == '#') {
            property_map_add_plaintext(map, data + s, i - s);
        } else {
            property_map_parse_line(map, source, override, logf, data + s, data_sz - s);
        }
    }
}

/*
 * write property map to a string
 */
char *property_map_write_to_buffer(struct property_map *map, size_t *data_sz) {
    size_t len = 0;
    char * buffer = malloc(0);
    
    int i;
    for (i = 0; i < map->size; i++) {
        struct map_entry * e = map->entries + i;
        switch (e->type) {
            case plaintext:
                len = (size_t) am_asprintf(&buffer, "%s%s\r\n", buffer, e->key);
                if (buffer == NULL) {
                    * data_sz = 0;
                    return NULL;
                }
                break;
                
            case property:
                len = (size_t) am_asprintf(&buffer, "%s%s = %s\r\n", buffer, e->key, e->value);
                if (buffer == NULL) {
                    * data_sz = 0;
                    return NULL;
                }
                break;
                
            case property_removed:
                break;
        }
    }
    *data_sz = len;
    return buffer;
}

