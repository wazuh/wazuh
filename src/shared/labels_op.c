/*
 * Label data operations
 * Copyright (C) 2017 Wazuh Inc.
 * February 27, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"

/* Append a new label into an array of (size) labels at the moment of inserting. Returns the first argument. */
wlabel_t* labels_add(wlabel_t *labels, size_t size, const char *key, const char *value, unsigned int hidden) {
    os_realloc(labels, (size + 2) * sizeof(wlabel_t), labels);
    labels[size].key = strdup(key);
    labels[size].value = strdup(value);
    labels[size].flags.hidden = hidden;
    memset(labels + size, 0, sizeof(wlabel_t));
    return labels;
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
