/*
 * Label Configuration
 * Copyright (C) 2017 Wazuh Inc.
 * February 20, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "labels-config.h"
#include "config.h"

const char *xml_label = "label";
const char *xml_key = "key";

static void AddLabel(label_t **labels, size_t *size, const char *key, const char *value);

int Read_Labels(XML_NODE node, void *d1, __attribute__((unused)) void *d2) {
    int i;
    size_t labels_z = 0;
    label_t *labels = *(label_t **)d1;

    /* Get label size */

    if (labels) {
        while (labels[labels_z].key) {
            labels_z++;
        }
    }

    for (i = 0; node[i]; i++) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL, __local_name);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, __local_name, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_label) == 0) {
            if (node[i]->attributes[0] && strcmp(node[i]->attributes[0], xml_key) == 0) {
                if (strlen(node[i]->values[0]) > 0) {
                    if (strlen(node[i]->content) == 0) {
                        merror("%s: WARN: label '%s' is empty.", __local_name, node[i]->values[0]);
                    }
                    AddLabel(&labels, &labels_z, node[i]->values[0], node[i]->content);
                } else {
                    merror("%s: ERROR: label with empty key.", __local_name);
                    return OS_INVALID;
                }
            } else {
                merror("%s: ERROR: expected 'key' attribute.", __local_name);
                return OS_INVALID;
            }
        } else {
            merror(XML_INVELEM, __local_name, node[i]->element);
            return (OS_INVALID);
        }
    }

    *(label_t **)d1 = labels;
    return 0;
}

void AddLabel(label_t **labels, size_t *size, const char *key, const char *value) {
    os_realloc(*labels, (*size + 2) * sizeof(label_t), *labels);
    (*labels)[*size].key = strdup(key);
    (*labels)[*size].value = strdup(value);
    memset((*labels) + ++(*size), 0, sizeof(label_t));
}
