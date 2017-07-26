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

    if (!*labels) {
        merror("Labels pointer is null.");
        return OS_INVALID;
    }

    /* Get label size */

    while ((*labels)[labels_z].key) {
        labels_z++;
    }

    for (i = 0; node[i]; i++) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            goto error;
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            goto error;
        } else if (strcmp(node[i]->element, xml_label) == 0) {
            key = NULL;
            hidden = 0;

            for (j = 0; node[i]->attributes[j]; j++) {
                if (strcmp(node[i]->attributes[j], xml_key) == 0) {
                    if (strlen(node[i]->values[j]) > 0) {
                        key = node[i]->values[j];
                    } else {
                        merror("Label with empty key.");
                        goto error;
                    }
                } else if (strcmp(node[i]->attributes[j], xml_hidden) == 0) {
                    if (strcmp(node[i]->values[j], "yes") == 0)
                        hidden = 1;
                    else if (strcmp(node[i]->values[j], "no") == 0)
                        hidden = 0;
                    else {
                        merror("Invalid content for attribute '%s'.", node[i]->attributes[j]);
                        goto error;
                    }
                }
            }

            if (!key) {
                merror("Expected 'key' attribute for label.");
                goto error;
            }

            if (strlen(node[i]->content) == 0) {
                mwarn("Label '%s' is empty.", key);
            }

            if (labels_get(*labels, key)) {
                mwarn("Label '%s' duplicated. Ignoring.", key);
            } else {
                *labels = labels_add(*labels, labels_z++, key, node[i]->content, hidden);
            }
        } else {
            merror(XML_INVELEM, node[i]->element);
            goto error;
        }
    }

    return 0;

error:
    labels_free(*labels);
    return OS_INVALID;
}
