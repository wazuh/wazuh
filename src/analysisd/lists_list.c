/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rules.h"
#include "cdb/cdb.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

ListNode *os_analysisd_cdblists;
ListRule *os_analysisd_cdbrules;

/* Create the ListRule */
void OS_CreateListsList() {
    os_analysisd_cdblists = NULL;
    os_analysisd_cdbrules = NULL;
}

void OS_ListLoadRules(ListNode **l_node, ListRule **lrule) {

    while (*lrule != NULL) {

        if (!(*lrule)->loaded) {
            (*lrule)->db = OS_FindList((*lrule)->filename, l_node);
            (*lrule)->loaded = 1;
        }

        *lrule = (*lrule)->next;
    }
}

/* External AddList */
void OS_AddList(ListNode *new_listnode, ListNode **cdblists) {

    if (*cdblists == NULL) {
        /* First list */
        *cdblists = new_listnode;
    } else {
        /* Add new list to the end */
        ListNode *last_list_node = *cdblists;

        while (last_list_node->next != NULL) {
            last_list_node = last_list_node->next;
        }
        last_list_node->next = new_listnode;

    }
}

ListNode *OS_FindList(const char *listname, ListNode **l_node) {

    ListNode *last_list_node = *l_node;
    if (last_list_node != NULL) {
        do {
            if (strcmp(last_list_node->txt_filename, listname) == 0 ||
                    strcmp(last_list_node->cdb_filename, listname) == 0) {
                /* Found first match returning */
                return (last_list_node);
            }
            last_list_node = last_list_node->next;
        } while (last_list_node != NULL);
    }
    return (NULL);
}

ListRule *OS_AddListRule(ListRule *first_rule_list, int lookup_type, int field,
                         const char *dfield, char *listname, OSMatch *matcher,
                         ListNode **l_node) {

    ListRule *new_rulelist_pt = NULL;
    new_rulelist_pt = (ListRule *)calloc(1, sizeof(ListRule));
    if (!new_rulelist_pt) {
        return (NULL);
    }

    new_rulelist_pt->field = field;
    new_rulelist_pt->next = NULL;
    new_rulelist_pt->matcher = matcher;
    new_rulelist_pt->lookup_type = lookup_type;
    new_rulelist_pt->filename = strdup(listname);
    new_rulelist_pt->dfield = field == RULE_DYNAMIC ? strdup(dfield) : NULL;
    new_rulelist_pt->mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

    if ((new_rulelist_pt->db = OS_FindList(listname, l_node)) == NULL) {
        os_free(new_rulelist_pt->filename);
        os_free(new_rulelist_pt->dfield);
        os_free(new_rulelist_pt);
        return NULL;
    }

    new_rulelist_pt->loaded = 1;

    if (first_rule_list == NULL) {
        mdebug1("Adding First rulelist item: filename: %s field: %d lookup_type: %d",
               new_rulelist_pt->filename,
               new_rulelist_pt->field,
               new_rulelist_pt->lookup_type);
        first_rule_list = new_rulelist_pt;
    } else {
        while (first_rule_list->next) {
            first_rule_list = first_rule_list->next;
        }
        mdebug1("Adding rulelist item: filename: %s field: %d lookup_type: %d",
               new_rulelist_pt->filename,
               new_rulelist_pt->field,
               new_rulelist_pt->lookup_type);
        first_rule_list->next = new_rulelist_pt;
    }
    return first_rule_list;
}

static int _OS_CDBOpen(ListNode *lnode)
{
    int fd;
    if (lnode->loaded != 1) {
        if ((fd = open(lnode->cdb_filename, O_RDONLY)) == -1) {
            merror(OPEN_ERROR, lnode->cdb_filename, errno, strerror (errno));
            return -1;
        }
        cdb_init(&lnode->cdb, fd);
        lnode->loaded = 1;
    }
    return 0;
}

/* Lock the list of a rule, opening its CDB file on first use.
 * Every access to the CDB of a list (find, position and length of the value,
 * read) happens with the list locked: cdb_find keeps the search state inside
 * the shared cdb struct, so two threads searching the same list at once would
 * continue each other's search.
 * Returns 1 with the list locked, 0 if the rule has no list and -1 if the CDB
 * file cannot be opened. The list is left unlocked when it does not return 1. */
static int _OS_DBLock(ListRule *lrule, ListNode **db)
{
    w_mutex_lock(&lrule->mutex);
    *db = lrule->db;
    w_mutex_unlock(&lrule->mutex);

    if (*db == NULL) {
        return 0;
    }

    w_mutex_lock(&(*db)->mutex);
    if (_OS_CDBOpen(*db) == -1) {
        w_mutex_unlock(&(*db)->mutex);
        return -1;
    }

    return 1;
}

/* Copy the value of the key just found by cdb_find as a NUL-terminated string,
 * as OSMatch_Execute may run str functions on it.
 * Must be called with the list locked. Returns NULL if the value cannot be read. */
static char *_OS_DBReadValue(ListNode *db, unsigned *vlen)
{
    char *val;
    unsigned vpos = cdb_datapos(&db->cdb);

    *vlen = cdb_datalen(&db->cdb);
    val = (char *) calloc(*vlen + 1, sizeof(char));
    if (!val) {
        return NULL;
    }

    if (cdb_read(&db->cdb, val, *vlen, vpos) == -1) {
        free(val);
        return NULL;
    }

    return val;
}

/* Look up an address, and if it is not listed, each of its prefixes that end
 * in '.', from the longest to the shortest.
 * Must be called with the list locked. Returns 1 when the address or one of
 * its prefixes is found, leaving its value ready for _OS_DBReadValue. */
static int _OS_DBFindAddress(ListNode *db, char *key)
{
    char *tmpkey;
    size_t len;
    int found = 0;

    /* First lookup for a single IP address */
    if (cdb_find(&db->cdb, key, strlen(key)) > 0) {
        return 1;
    }

    /* IP address not found, look for matching subnets */
    os_strdup(key, tmpkey);
    len = strlen(tmpkey);
    while (len > 0) {
        if (tmpkey[len - 1] == '.' && cdb_find(&db->cdb, tmpkey, len) > 0) {
            found = 1;
            break;
        }
        tmpkey[--len] = '\0';
    }
    free(tmpkey);

    return found;
}

static int OS_DBSearchKeyValue(ListRule *lrule, char *key)
{
    int result = 0;
    char *val = NULL;
    unsigned vlen = 0;
    ListNode *db;

    if (_OS_DBLock(lrule, &db) != 1) {
        return 0;
    }

    if (cdb_find(&db->cdb, key, strlen(key)) > 0) {
        val = _OS_DBReadValue(db, &vlen);
    }
    w_mutex_unlock(&db->mutex);

    if (val) {
        result = OSMatch_Execute(val, vlen, lrule->matcher);
        free(val);
    }

    return result;
}

static int OS_DBSeachKey(ListRule *lrule, char *key)
{
    int found;
    ListNode *db;

    if ((found = _OS_DBLock(lrule, &db)) != 1) {
        return found;
    }

    found = cdb_find(&db->cdb, key, strlen(key)) > 0;
    w_mutex_unlock(&db->mutex);

    return found;
}

static int OS_DBSeachKeyAddress(ListRule *lrule, char *key)
{
    int found;
    ListNode *db;

    if ((found = _OS_DBLock(lrule, &db)) != 1) {
        return found;
    }

    found = _OS_DBFindAddress(db, key);
    w_mutex_unlock(&db->mutex);

    return found;
}

static int OS_DBSearchKeyAddressValue(ListRule *lrule, char *key)
{
    int result = 0;
    char *val = NULL;
    unsigned vlen = 0;
    ListNode *db;

    if (_OS_DBLock(lrule, &db) != 1) {
        return 0;
    }

    if (_OS_DBFindAddress(db, key)) {
        val = _OS_DBReadValue(db, &vlen);
    }
    w_mutex_unlock(&db->mutex);

    if (val) {
        result = OSMatch_Execute(val, vlen, lrule->matcher);
        free(val);
    }

    return result;
}

int OS_DBSearch(ListRule *lrule, char *key, ListNode **l_node)
{
    //XXX - god damn hack!!! Jeremy Rossi
    w_mutex_lock(&lrule->mutex);
    if (lrule->loaded == 0) {
        lrule->db = OS_FindList(lrule->filename, l_node);
        lrule->loaded = 1;
    }
    w_mutex_unlock(&lrule->mutex);

    switch (lrule->lookup_type) {
        case LR_STRING_MATCH:
            if (OS_DBSeachKey(lrule, key) == 1) {
                return 1;
            }
            return 0;
        case LR_STRING_NOT_MATCH:
            if (OS_DBSeachKey(lrule, key) == 1) {
                return 0;
            }
            return 1;
        case LR_STRING_MATCH_VALUE:
            if (OS_DBSearchKeyValue(lrule, key) == 1) {
                return 1;
            }
            return 0;
        case LR_ADDRESS_MATCH:
            return OS_DBSeachKeyAddress(lrule, key) == 1;
        case LR_ADDRESS_NOT_MATCH:
            if (OS_DBSeachKeyAddress(lrule, key) == 0) {
                return 1;
            }
            return 0;
        case LR_ADDRESS_MATCH_VALUE:
            return OS_DBSearchKeyAddressValue(lrule, key);
        default:
            mdebug1("lists_list.c::OS_DBSearch should never hit default");
            return 0;
    }
}

void os_remove_cdblist(ListNode **l_node) {

    ListNode *tmp;

    while (*l_node) {

        tmp = *l_node;
        *l_node = (*l_node)->next;

        /* The CDB file is opened on the first lookup of the list: release
         * its mapping and descriptor only if that happened */
        if (tmp->loaded) {
            cdb_free(&tmp->cdb);
            close(tmp->cdb.fd);
            w_mutex_destroy(&tmp->cdb.mutex);
        }
        w_mutex_destroy(&tmp->mutex);

        os_free(tmp->cdb_filename);
        os_free(tmp->txt_filename);
        os_free(tmp);
    }

}

void os_remove_cdbrules(ListRule **l_rule) {

    ListRule *tmp;

    while (*l_rule) {

        tmp = *l_rule;
        *l_rule = (*l_rule)->next;

        if (tmp->matcher) OSMatch_FreePattern(tmp->matcher);
        os_free(tmp->matcher);
        os_free(tmp->dfield);
        os_free(tmp->filename);
        w_mutex_destroy(&tmp->mutex);
        os_free(tmp);
    }

}
