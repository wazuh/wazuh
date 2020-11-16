/*
 * Label data operations
 * Copyright (C) 2015-2020, Wazuh Inc.
 * February 27, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef LABELS_OP_H
#define LABELS_OP_H

 /* Label flags bitfield */

 typedef struct label_flags_t {
     unsigned int hidden:1;
     unsigned int system:1;
 } label_flags_t;

 /* Label data structure */

 typedef struct wlabel_t {
     char *key;
     char *value;
     label_flags_t flags;
 } wlabel_t;

/* Append a new label into an array of (size) labels at the moment of inserting. Returns the new pointer. */
wlabel_t* labels_add(wlabel_t *labels, size_t * size, const char *key, const char *value, label_flags_t flags, int overwrite);

/* Search for a key at a label array and get the value, or NULL if no such key found. */
char* labels_get(const wlabel_t *labels, const char *key);

/* Free label array */
void labels_free(wlabel_t *labels);

/* Format label array into string. Return 0 on success or -1 on error. */
int labels_format(const wlabel_t *labels, char *str, size_t size);

// Duplicate label array
wlabel_t * labels_dup(const wlabel_t * labels);

/**
 * @brief Function to parse labels JSON from Wazuh DB - global.db - labels table.
 * If there are no labels for the agent, returns NULL. Free resources 
 * with labels_free().
 * 
 * @param json_labels The JSON with the labels taken from Wazuh DB.
 * @retval A wlabel_t structure with all the labels on sucess. Null on error or when no labels.
 */
wlabel_t* labels_parse(cJSON *json_labels);

#endif
