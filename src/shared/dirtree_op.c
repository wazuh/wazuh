/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Common API for dealing with directory trees */

#include "shared.h"

static OSDirTree *_OSTreeNode_Add(OSDirTree *tree, const char *str,
                                  void *data, char sep) __attribute__((nonnull(2)));


/* Create the tree
 * Returns NULL on error
 */
OSDirTree *OSDirTree_Create()
{
    OSDirTree *my_tree;

    my_tree = (OSDirTree *) calloc(1, sizeof(OSDirTree));
    if (!my_tree) {
        return (NULL);
    }

    my_tree->first_node = NULL;
    my_tree->last_node = NULL;

    return (my_tree);
}

/* Get first node from tree (starting from parent)
 * Returns null on invalid tree (not initialized)
 */
OSTreeNode *OSDirTree_GetFirstNode(OSDirTree *tree)
{
    return (tree->first_node);
}

/* Look for an entry in the middle of the tree
 * Should not be called directly
 */
static OSDirTree *_OSTreeNode_Add(OSDirTree *tree, const char *str,
                                  void *data, char sep)
{
    char *tmp_str;
    OSTreeNode *newnode;
    OSTreeNode *curnode;

    /* Look for a next entry */
    tmp_str = strchr(str, sep);
    if (tmp_str) {
        *tmp_str = '\0';
    }

    /* Create new tree */
    if (!tree) {
        tree = (OSDirTree *) calloc(1, sizeof(OSDirTree));
        if (!tree) {
            return (NULL);
        }

        tree->first_node = NULL;
        tree->last_node = NULL;
    }

    curnode = tree->first_node;

    /* Loop over all nodes */
    while (curnode) {
        if (strcmp(curnode->value, str) == 0) {
            /* If we have other elements, keep going */
            if (tmp_str) {
                curnode->child = _OSTreeNode_Add(curnode->child,
                                                 tmp_str + 1, data, sep);
            }
            break;
        }
        curnode = curnode->next;
    }

    /* Add a new entry, if not found */
    if (!curnode) {
        os_calloc(1, sizeof(OSTreeNode), newnode);

        if (!tree->first_node && !tree->last_node) {
            tree->last_node = newnode;
            tree->first_node = newnode;
        } else {
            tree->last_node->next = newnode;
        }

        newnode->next = NULL;
        tree->last_node = newnode;
        os_strdup(str, newnode->value);

        /* If we have other elements, keep going */
        if (tmp_str) {
            newnode->child = _OSTreeNode_Add(newnode->child,
                                             tmp_str + 1, data, sep);
            newnode->data = NULL;
        }
        /* Otherwise, set the data in here */
        else {
            newnode->data = data;
            newnode->child = NULL;
        }
    }

    /* Fix the string back */
    if (tmp_str) {
        *tmp_str = sep;
    }

    return (tree);
}

/* Add a new string to the tree, setting the data at the final leaf.
 * The tree will be divided by the "separator", where each token
 * will delimit the child.
 * For example, /etc/my/name.conf will become:
 *              /etc/
 *                   -> /my
 *                        -> /name.conf
 * Str must not be NULL.
 */
void OSDirTree_AddToTree(OSDirTree *tree, const char *str, void *data, char sep)
{
    char *tmp_str;
    OSTreeNode *newnode;
    OSTreeNode *curnode;

    /* First character doesn't count as a separator */
    tmp_str = strchr(str + 1, sep);
    if (tmp_str) {
        *tmp_str = '\0';
    }

    curnode = tree->first_node;
    while (curnode) {
        if (strcmp(str, curnode->value) == 0) {
            /* If we have other elements, keep going */
            if (tmp_str) {
                curnode->child = _OSTreeNode_Add(curnode->child,
                                                 tmp_str + 1, data, sep);
            }
            break;
        }

        curnode = curnode->next;
    }

    /* If we didn't find an entry, create one */
    if (!curnode) {
        os_calloc(1, sizeof(OSTreeNode), newnode);
        printf("XX Adding MAIN node: %s\n", str);

        if (!tree->first_node && !tree->last_node) {
            tree->last_node = newnode;
            tree->first_node = newnode;
        } else {
            printf("XXX last new node: %s\n", tree->last_node->value);
            tree->last_node->next = newnode;
            tree->last_node = newnode;
        }

        newnode->next = NULL;
        os_strdup(str, newnode->value);

        /* If we have other elements, keep going */
        if (tmp_str) {
            newnode->child = _OSTreeNode_Add(newnode->child,
                                             tmp_str + 1, data, sep);
            newnode->data = NULL;
        }
        /* Otherwise, set the data in here */
        else {
            newnode->data = data;
            newnode->child = NULL;
        }
    }

    /* Fix the string back */
    if (tmp_str) {
        *tmp_str = sep;
    }

    return;
}

void *OSDirTree_SearchTree(const OSDirTree *tree, const char *str, char sep)
{
    void *ret = NULL;
    char *tmp_str;
    const OSTreeNode *curnode;

    /* First character doesn't count as a separator */
    tmp_str = strchr(str + 1, sep);
    if (tmp_str) {
        *tmp_str = '\0';
    }

    printf("looking for: %s\n", str);

    /* If our tree is not empty, look for the main entry */
    curnode = tree->first_node;
    while (curnode) {
        printf("comparing: '%s' and '%s'\n", str, curnode->value);
        if (strcmp(str, curnode->value) == 0) {
            printf("found node: %s\n", str);

            /* If we have other elements, keep going */
            if (tmp_str) {
                ret = OSDirTree_SearchTree(curnode->child, tmp_str + 1, sep);
            } else {
                ret = curnode->data;
            }
            break;
        }

        curnode = curnode->next;
    }

    /* Fix the string back */
    if (tmp_str) {
        *tmp_str = sep;
    }

    return (ret);
}
