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

#ifndef LABELS_OP_H
#define LABELS_OP_H

 /* Label flags bitfield */

 typedef struct label_flags_t {
     unsigned int hidden:1;
 } label_flags_t;

 /* Label data structure */

 typedef struct wlabel_t {
     char *key;
     char *value;
     label_flags_t flags;
 } wlabel_t;

/* Append a new label into an array of (size) labels at the moment of inserting. Returns the first argument. */
wlabel_t* labels_add(wlabel_t *labels, size_t size, const char *key, const char *value, unsigned int hidden);

/* Format label array into string. Return 0 on success or -1 on error. */
int labels_format(const wlabel_t *labels, char *str, size_t size);

#endif
