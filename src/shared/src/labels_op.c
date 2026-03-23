/*
 * Label data operations
 * Copyright (C) 2015, Wazuh Inc.
 * February 27, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"

/* Append a new label into an array of (size) labels at the moment of inserting. Returns the new pointer. */
wlabel_t* labels_add(wlabel_t *labels, size_t * size, const char *key, const char *value, label_flags_t flags, int overwrite) {
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
    labels[i].flags.hidden = flags.hidden;
    labels[i].flags.system = flags.system;
    return labels;
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
