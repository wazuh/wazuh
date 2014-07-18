/* @(#) $Id: ./src/headers/dirtree_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */

/* Common API for dealing with directory trees */


#ifndef _OS_DIRTREE
#define _OS_DIRTREE

typedef struct _OSTreeNode
{
    struct _OSTreeNode *next;
    void *child;

    char *value;
    void *data;
}OSTreeNode;


typedef struct _OSDirTree
{
    OSTreeNode *first_node;
    OSTreeNode *last_node;
}OSDirTree;


OSDirTree *OSDirTree_Create(void);
void OSDirTree_AddToTree(OSDirTree *tree, const char *str, void *data, char sep) __attribute__((nonnull(1,2)));
void *OSDirTree_SearchTree(const OSDirTree *tree, const char *str, char sep) __attribute__((nonnull));

OSTreeNode *OSDirTree_GetFirstNode(OSDirTree *tree) __attribute__((nonnull));

#endif

/* EOF */
