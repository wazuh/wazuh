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

/*  Rotation node
 * - first_value: The day of the log
 * - second_value: The counter of the log
 * - string_value: The path of the log
 * - next: Next node with the next log
 *
 * - prev: Previous node with the previous log
 */
typedef struct rotation_node {
    int first_value;
    int second_value;
    char *string_value;
    struct rotation_node *next;
    struct rotation_node *prev;
} rotation_node;

/*  Rotation list
 * - count: The number of elements of the list
 * - first: The oldest log
 * - last: The newest log
 */
typedef struct rotation_list {
    int count;
    rotation_node *first;
    rotation_node *last;
} rotation_list;

// Generate the rotation list for the given tag and extension
rotation_list *get_rotation_list(char *tag, char *ext);

// Purge the rotation list to 'keep_files' number of files if it's enabled
void purge_rotation_list(rotation_list *list, int keep_files);

// Add a new node to the rotation list
void add_new_rotation_node(rotation_list *list, char *value, int keep_files);

#endif
