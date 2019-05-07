/* Copyright (C) 2015-2019, Wazuh Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _W_ROTATION
#define _W_ROTATION
#define PATH_SEP_ROT '/'

typedef struct rotation_node {
    int first_value;
    int second_value;
    char *string_value;
    struct rotation_node *next;
    struct rotation_node *prev;
} rotation_node;

typedef struct rotation_list {
    int count;
    rotation_node *first;
    rotation_node *last;
} rotation_list;

rotation_list *get_rotation_list(char *tag, char *ext);
void purge_rotation_list(rotation_list *list, int keep_files);
void add_new_rotation_node(rotation_list *list, char *value, int keep_files);

#endif
