/*   $OSSEC, list_op.h, v0.1, 2005/10/28, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Common list API */


#ifndef _OS_LIST
#define _OS_LIST
typedef struct _OSList
{
    struct _OSList *next;
    void *data;
}OSList;


OSList *OS_CreateList();
OSList *OS_GetFirstNode(OSList *);
int OS_AddData(OSList *list, void *data);

#endif
