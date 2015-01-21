/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/* Rules are needed for lists */

#ifndef __LISTS_H
#define __LISTS_H

#include "cdb/cdb.h"
#include "cdb/uint32.h"

#define LR_STRING_MATCH 0
#define LR_STRING_NOT_MATCH 1
#define LR_STRING_MATCH_VALUE 2

#define LR_ADDRESS_MATCH 10
#define LR_ADDRESS_NOT_MATCH 11
#define LR_ADDRESS_MATCH_VALUE 12

typedef struct ListNode {
    int loaded;
    char *cdb_filename;
    char *txt_filename;
    struct cdb cdb;
    struct ListNode *next;
} ListNode;

typedef struct ListRule {
    int loaded;
    int field;
    int lookup_type;
    OSMatch *matcher;
    char *filename;
    ListNode *db;
    struct ListRule *next;
} ListRule;

/* Create the rule list */
void OS_CreateListsList();

/* Add rule information to the list */
int OS_AddList( ListNode *new_listnode );

int Lists_OP_LoadList(char *listfile);

int OS_DBSearchKey(ListRule *lrule, char *key);

int OS_DBSearch(ListRule *lrule, char *key);

void OS_ListLoadRules();

ListRule *OS_AddListRule(ListRule *first_rule_list, int lookup_type, int field, char *listname, OSMatch *matcher);

ListNode *OS_GetFirstList();

ListNode *OS_FindList(char *listname);

#endif /* __LISTS_H */

