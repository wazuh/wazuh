/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef RBTREE_OP_WRAPPERS_H
#define RBTREE_OP_WRAPPERS_H

#include <rbtree_op.h>

void * __wrap_rbtree_insert(rb_tree * tree, const char * key, void * value);

char **__wrap_rbtree_keys(const rb_tree *tree);

#endif
