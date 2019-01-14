/*
 * Label data operations
 * Copyright (C) 2015-2019, Wazuh Inc.
 * February 27, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"

/* Append a new label into an array of (size) labels at the moment of inserting. Returns the new pointer. */
wlabel_t* labels_add(wlabel_t *labels, size_t * size, const char *key, const char *value, unsigned int hidden, int overwrite) {
    size_t i;

    if (overwrite) {
        for (i = 0; labels && labels[i].key; i++) {
            if (!strcmp(labels[i].key, key)) {
                break;
            }
        }
    } else {
        i = *size;
    }

    if (!labels || i == *size) {
        os_realloc(labels, (*size + 2) * sizeof(wlabel_t), labels);
        labels[(*size)++].key = strdup(key);
        memset(labels + *size, 0, sizeof(wlabel_t));
    } else if (labels) {
        free(labels[i].value);
    }

    labels[i].value = strdup(value);
    labels[i].flags.hidden = hidden;
    return labels;
}

/* Search for a key at a label array and get the value, or NULL if no such key found. */
const char* labels_get(const wlabel_t *labels, const char *key) {
    int i;

    if (!labels) {
        return NULL;
    }

    for (i = 0; labels[i].key; i++) {
        if (!strcmp(labels[i].key, key)) {
            return labels[i].value;
        }
    }

    return NULL;
}

/* Free label array */
void labels_free(wlabel_t *labels) {
    int i;

    if (labels) {
        for (i = 0; labels[i].key != NULL; i++) {
            free(labels[i].key);
            free(labels[i].value);
        }

        free(labels);
    }
}

/* Format label array into string. Return 0 on success or -1 on error. */
int labels_format(const wlabel_t *labels, char *str, size_t size) {
    int i;
    size_t z = 0;

    for (i = 0; labels[i].key != NULL; i++) {
        z += (size_t)snprintf(str + z, size - z, "%s\"%s\":%s\n",
            labels[i].flags.hidden ? "!" : "",
            labels[i].key,
            labels[i].value);

        if (z >= size)
            return -1;
    }

    return 0;
}

/*
 * Parse labels from agent-info file.
 * Returns pointer to new null-key terminated array.
 * If no such file, returns NULL.
 * Free resources with labels_free().
 */
wlabel_t* labels_parse(const char *path) {
    char buffer[OS_MAXSTR];
    char *key;
    char *value;
    char *end;
    unsigned int hidden;
    size_t size = 0;
    wlabel_t *labels;
    FILE *fp;

    if (!(fp = fopen(path, "r"))) {
        if (errno == ENOENT) {
            mdebug1(FOPEN_ERROR, path, errno, strerror(errno));
        } else {
            merror(FOPEN_ERROR, path, errno, strerror(errno));
        }

        return NULL;
    }

    os_calloc(1, sizeof(wlabel_t), labels);

    /*
    "key1":value1\n
    !"key2":value2\n
    */

    while (fgets(buffer, OS_MAXSTR, fp)) {
        switch (*buffer) {
        case '!':
            if (buffer[1] == '\"') {
                hidden = 1;
                key = buffer + 2;
            } else {
                continue;
            }

            break;
        case '\"':
            hidden = 0;
            key = buffer + 1;
            break;
        default:
            continue;
        }

        if (!(value = strstr(key, "\":"))) {
            continue;
        }

        *value = '\0';
        value += 2;

        if (!(end = strchr(value, '\n'))) {
            continue;
        }

        *end = '\0';
        labels = labels_add(labels, &size, key, value, hidden, 0);
    }

    fclose(fp);
    return labels;
}

// Duplicate label array
wlabel_t * labels_dup(const wlabel_t * labels) {
    wlabel_t * copy = NULL;
    int i;

    if (!labels) {
        return NULL;
    }

    os_malloc(sizeof(wlabel_t), copy);

    for (i = 0; labels[i].key; i++) {
        os_realloc(copy, sizeof(wlabel_t) * (i + 2), copy);
        os_strdup(labels[i].key, copy[i].key);
        os_strdup(labels[i].value, copy[i].value);
        copy[i].flags = labels[i].flags;
    }

    copy[i].key = copy[i].value = NULL;
    return copy;
}
