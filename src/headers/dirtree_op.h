/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Common API for dealing with directory trees */

#ifndef _OS_DIRTREE
#define _OS_DIRTREE

typedef struct _OSDirTree OSDirTree;

typedef struct _OSTreeNode {
    struct _OSTreeNode *next;
    OSDirTree *child;

    char *value;
    void *data;
} OSTreeNode;

struct _OSDirTree {
    OSTreeNode *first_node;
    OSTreeNode *last_node;
};

OSDirTree *OSDirTree_Create(void);
void OSDirTree_AddToTree(OSDirTree *tree, const char *str, void *data, char sep) __attribute__((nonnull(1, 2)));
void *OSDirTree_SearchTree(const OSDirTree *tree, const char *str, char sep) __attribute__((nonnull));

OSTreeNode *OSDirTree_GetFirstNode(OSDirTree *tree) __attribute__((nonnull));

#endif /* _OS_DIRTREE */

