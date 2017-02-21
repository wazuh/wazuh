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

#ifndef LABELS_H
#define LABELS_H

/* Label data structure */

typedef struct _label_t {
    char *key;
    char *value;
} label_t;

#endif
