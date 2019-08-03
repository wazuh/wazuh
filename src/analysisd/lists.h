/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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
    pthread_mutex_t mutex;
} ListNode;

typedef struct ListRule {
    int loaded;
    int field;
    int lookup_type;
    OSMatch *matcher;
    char *dfield;
    char *filename;
    ListNode *db;
    struct ListRule *next;
    pthread_mutex_t mutex;
} ListRule;

/* Create the rule list */
void OS_CreateListsList(void);

/* Add rule information to the list */
int OS_AddList( ListNode *new_listnode );

int Lists_OP_LoadList(char *listfile);

int OS_DBSearchKey(ListRule *lrule, char *key);

int OS_DBSearch(ListRule *lrule, char *key);

void OS_ListLoadRules(void);

ListRule *OS_AddListRule(ListRule *first_rule_list, int lookup_type, int field, const char *dfield, char *listname, OSMatch *matcher);

ListNode *OS_GetFirstList(void);

ListNode *OS_FindList(const char *listname);

void Lists_OP_CreateLists(void);

#endif /* __LISTS_H */
