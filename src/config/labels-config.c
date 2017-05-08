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
#include "config.h"

const char *xml_label = "label";
const char *xml_key = "key";
const char *xml_hidden = "hidden";

int Read_Labels(XML_NODE node, void *d1, __attribute__((unused)) void *d2) {
    int i;
    int j;
    unsigned int hidden;
    const char *key;
    size_t labels_z = 0;
    wlabel_t **labels = (wlabel_t **)d1;

    /* Get label size */

    if (*labels) {
        while ((*labels)[labels_z].key) {
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
            key = NULL;
            hidden = 0;

            for (j = 0; node[i]->attributes[j]; j++) {
                if (strcmp(node[i]->attributes[j], xml_key) == 0) {
                    if (strlen(node[i]->values[j]) > 0) {
                        key = node[i]->values[j];
                    } else {
                        merror("%s: ERROR: label with empty key.", __local_name);
                        return OS_INVALID;
                    }
                } else if (strcmp(node[i]->attributes[j], xml_hidden) == 0) {
                    if (strcmp(node[i]->values[j], "yes") == 0)
                        hidden = 1;
                    else if (strcmp(node[i]->values[j], "no") == 0)
                        hidden = 0;
                    else {
                        merror("%s: ERROR: Invalid content for attribute '%s'.", __local_name, node[i]->attributes[j]);
                        return OS_INVALID;
                    }
                }
            }

            if (!key) {
                merror("%s: ERROR: expected 'key' attribute for label.", __local_name);
                return OS_INVALID;
            }

            if (strlen(node[i]->content) == 0) {
                merror("%s: WARN: label '%s' is empty.", __local_name, key);
            }

            if (labels_get(*labels, key)) {
                merror("%s: WARN: label '%s' duplicated. Ignoring.", __local_name, key);
            } else {
                *labels = labels_add(*labels, labels_z++, key, node[i]->content, hidden);
            }
        } else {
            merror(XML_INVELEM, __local_name, node[i]->element);
            return (OS_INVALID);
        }
    }

    return 0;
}
