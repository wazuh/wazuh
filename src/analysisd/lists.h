/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/* Rules are needed for lists */

#ifndef LISTS_H
#define LISTS_H

#include "cdb/cdb.h"
#include "cdb/uint32.h"

#define LR_STRING_MATCH 0
#define LR_STRING_NOT_MATCH 1
#define LR_STRING_MATCH_VALUE 2

#define LR_ADDRESS_MATCH 10
#define LR_ADDRESS_NOT_MATCH 11
#define LR_ADDRESS_MATCH_VALUE 12

/**
 * @brief Struct to save the CDB lists
 */
typedef struct ListNode {
    int loaded;
    char *cdb_filename;
    char *txt_filename;
    struct cdb cdb;
    struct ListNode *next;
    pthread_mutex_t mutex;
} ListNode;

/**
 * @brief Struct to asociate rules and CDB lists
 */
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

/**
 * @brief Create the rule list
 */
void OS_CreateListsList(void);

/**
 * @brief Add new node to the CDB list
 * @param new_listnode node to add in CDB list
 * @param cdblists list where save the node
 */
void OS_AddList( ListNode *new_listnode, ListNode **cdblists);

/**
 * @brief Load cdb list
 * @param listfile file name where find cdb list
 * @param cdblists ListNode where save cdb list
 * @param log_msg list to save log messages
 * @return 0 on success, otherwise -1
 */
int Lists_OP_LoadList(char *listfile, ListNode **cdblists, OSList* log_msg);

/**
 * @brief Search a word in a cdb list
 * @param lrule list of rules and cdb lists associated
 * @param key word which search in cdb list
 * @param lnode list of cdb lists
 * @return 1 if find it, otherwise 0
 */
int OS_DBSearch(ListRule *lrule, char *key, ListNode **l_node);

/**
 * @brief Asociate CDB lists and rules
 * @param l_node list of cdb lists
 * @param lrule list of rules and cdb lists associated
 */
void OS_ListLoadRules(ListNode **l_node, ListRule **lrule);

/**
 * @brief Add new node in list of rules and cdb lists associated
 * @param first_rule_list list of rules and cdb lists associated
 * @param lookup_type lookup option
 * @param field
 * @param dfield field extracted in the decodification phase
 * @param listname the list name
 * @param matcher word to match
 * @param l_node list of cdb lists
 * @return first_rule_list with the node added
 */
ListRule *OS_AddListRule(ListRule *first_rule_list, int lookup_type, int field,
                         const char *dfield, char *listname, OSMatch *matcher,
                         ListNode **l_node);

/**
 * @brief Find a cdb list
 * @param listname name of the list
 * @param l_node list of cdb lists
 * @return the cdb lists if find it, otherwise NULL
 */
ListNode *OS_FindList(const char *listname, ListNode **l_node);

/**
 * @brief Initialize the cdb lookup lists
 */
void Lists_OP_CreateLists(void);

/**
 * @brief Remove a list of cdb lists
 * @param l_node list to remove
 */
void os_remove_cdblist(ListNode **l_node);

/**
 * @brief Remove a list of rules and cdb lists associated
 * @param l_rule list to remove
 */
void os_remove_cdbrules(ListRule **l_rule);

#endif /* LISTS_H */
