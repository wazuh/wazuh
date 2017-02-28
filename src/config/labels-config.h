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

/* Label flags bitfield */

typedef struct label_flags_t {
    unsigned int hidden:1;
} label_flags_t;

/* Label data structure */

typedef struct label_t {
    char *key;
    char *value;
    label_flags_t flags;
} label_t;

#endif
