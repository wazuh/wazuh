/* @(#) $Id: ./src/analysisd/lists_list.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
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

/* Global */
ListNode *global_listnode;
ListRule *global_listrule;

/*
 */
ListNode *_OS_AddList(ListNode *new_listnode);


/* Create the ListRule */
void OS_CreateListsList()
{
    global_listnode = NULL;
    global_listrule = NULL;

    return;
}

/* Get first listnode  */
ListNode *OS_GetFirstList()
{
    ListNode *listnode_pt = global_listnode;

    return(listnode_pt);
}

ListRule *OS_GetFirstListRule()
{
    ListRule *listrule_pt = global_listrule;
    return listrule_pt;
}

void OS_ListLoadRules()
{
    ListRule *lrule = global_listrule;
    while(lrule != NULL)
    {
        if(!lrule->loaded)
        {
            lrule->db = OS_FindList(lrule->filename);
            lrule->loaded=1;
        }
        lrule = lrule->next;
    }
}

ListRule *_OS_AddListRule(ListRule *new_listrule)
{

    if(global_listrule == NULL)
    {
        global_listrule = new_listrule;
    }
    else
    {
        ListRule *last_list_rule = global_listrule;
        while(last_list_rule->next != NULL)
        {
            last_list_rule = last_list_rule->next;
        }
        last_list_rule->next = new_listrule;
    }
    return(global_listrule);
}



/* External AddList */
int OS_AddList(ListNode *new_listnode)
{
    if(global_listnode == NULL)
    {
        /* First list */
        global_listnode = new_listnode;
    }
    else
    {
        /* Adding new list to the end */
        ListNode *last_list_node = global_listnode;

        while(last_list_node->next != NULL)
        {
            last_list_node = last_list_node->next;
        }
        last_list_node->next = new_listnode;

    }
    return 0; 
}

ListNode *OS_FindList(char *listname)
{
    ListNode *last_list_node = OS_GetFirstList();
    if (last_list_node != NULL) {
        do
        {
            if (strcmp(last_list_node->txt_filename, listname) == 0 ||
                strcmp(last_list_node->cdb_filename, listname) == 0)
            {
                /* Found first match returning */
                return(last_list_node);
            }
            last_list_node = last_list_node->next;
        } while (last_list_node != NULL);
    }
    return(NULL);
}

ListRule *OS_AddListRule(ListRule *first_rule_list,
                         int lookup_type,
                         int field,
                         char *listname,
                         OSMatch *matcher)
{
    ListRule *new_rulelist_pt = NULL;
    new_rulelist_pt = (ListRule *)calloc(1,sizeof(ListRule));
    new_rulelist_pt->field = field;
    new_rulelist_pt->next = NULL;
    new_rulelist_pt->matcher = matcher;
    new_rulelist_pt->lookup_type = lookup_type;
    new_rulelist_pt->filename = listname;
    if((new_rulelist_pt->db = OS_FindList(listname)) == NULL)
        new_rulelist_pt->loaded = 0;
    else
        new_rulelist_pt->loaded = 1;
    if(first_rule_list == NULL)
    {
        debug1("Adding First rulelist item: filename: %s field: %d lookup_type: %d",
               new_rulelist_pt->filename,
               new_rulelist_pt->field,
               new_rulelist_pt->lookup_type);
    	first_rule_list = new_rulelist_pt;
    }
    else
    {
    	while(first_rule_list->next)
    	{
        	first_rule_list = first_rule_list->next;
        }
        debug1("Adding rulelist item: filename: %s field: %d lookup_type: %d",
               new_rulelist_pt->filename,
               new_rulelist_pt->field,
               new_rulelist_pt->lookup_type);
        first_rule_list->next = new_rulelist_pt;
    }
    return first_rule_list;
}

int _OS_CDBOpen(ListNode *lnode)
{
    int fd;
    if (lnode->loaded != 1)
    {
        if((fd = open(lnode->cdb_filename, O_RDONLY)) == -1)
        {
            merror(OPEN_ERROR, ARGV0, lnode->cdb_filename, strerror (errno));
            return -1;
        }
        cdb_init(&lnode->cdb, fd);
        lnode->loaded = 1;
    }
    return 0;
}

int OS_DBSearchKeyValue(ListRule *lrule, char *key)
{
    int result=-1;
    char *val;
    unsigned vlen, vpos;
    if (lrule->db!= NULL)
    {
        if(_OS_CDBOpen(lrule->db) == -1) return 0;
        if(cdb_find(&lrule->db->cdb, key, strlen(key)) > 0 ) {
            vpos = cdb_datapos(&lrule->db->cdb);
            vlen = cdb_datalen(&lrule->db->cdb);
            val = malloc(vlen);
            cdb_read(&lrule->db->cdb, val, vlen, vpos);
            result = OSMatch_Execute(val, vlen, lrule->matcher);
            free(val);
            return result;
        } else {
            return 0;
        }
    }
    return 0;
}



int OS_DBSeachKey(ListRule *lrule, char *key)
{
    if (lrule->db != NULL)
    {
        if(_OS_CDBOpen(lrule->db) == -1) return -1;
        if( cdb_find(&lrule->db->cdb, key, strlen(key)) > 0 ) return 1;
    }
    return 0;
}

int OS_DBSeachKeyAddress(ListRule *lrule, char *key)
{
    //char _ip[128];
    //_ip[127] = "\0";
    if (lrule->db != NULL)
    {
        if(_OS_CDBOpen(lrule->db) == -1) return -1;
        //snprintf(_ip,128,"%s",key);
        //XXX Breka apart string on the . boundtrys a loop over to longest match.

        if( cdb_find(&lrule->db->cdb, key, strlen(key)) > 0 ) {
            return 1;
        }
        else
        {
            char *tmpkey;
            os_strdup(key, tmpkey);
            while(strlen(tmpkey) > 0)
            {
                if(tmpkey[strlen(tmpkey) - 1] == '.')
                {
                    if( cdb_find(&lrule->db->cdb, tmpkey, strlen(tmpkey)) > 0 ) {
                        free(tmpkey);
                        return 1;
                    }
                }
                tmpkey[strlen(tmpkey) - 1] = '\0';
            }
            free(tmpkey);
        }
    }
    return 0;
}

int OS_DBSearchKeyAddressValue(ListRule *lrule, char *key)
{
    int result=-1;
    char *val;
    unsigned vlen, vpos;
    if (lrule->db!= NULL)
    {
        if(_OS_CDBOpen(lrule->db) == -1) return 0;

        // First lookup for a single IP address
        if(cdb_find(&lrule->db->cdb, key, strlen(key)) > 0 ) {
            vpos = cdb_datapos(&lrule->db->cdb);
            vlen = cdb_datalen(&lrule->db->cdb);
            val = malloc(vlen);
            cdb_read(&lrule->db->cdb, val, vlen, vpos);
            result = OSMatch_Execute(val, vlen, lrule->matcher);
            free(val);
            return result;
        } else {
            // IP address not found, look for matching subnets
            char *tmpkey;
            os_strdup(key, tmpkey);
            while(strlen(tmpkey) > 0)
            {
                if(tmpkey[strlen(tmpkey) - 1] == '.')
                {
                    if( cdb_find(&lrule->db->cdb, tmpkey, strlen(tmpkey)) > 0 ) {
                        vpos = cdb_datapos(&lrule->db->cdb);
                        vlen = cdb_datalen(&lrule->db->cdb);
                        val = malloc(vlen);
                        cdb_read(&lrule->db->cdb, val, vlen, vpos);
                        result = OSMatch_Execute(val, vlen, lrule->matcher);
                        free(val);
                        free(tmpkey);
                        return result;
                    }
                }
                tmpkey[strlen(tmpkey) - 1] = '\0';
            }
            free(tmpkey);
            return 0;
        }
    }
    return 0;
}

int OS_DBSearch(ListRule *lrule, char *key)
{
    //XXX - god damn hack!!! Jeremy Rossi
    if (lrule->loaded == 0)
    {
        lrule->db = OS_FindList(lrule->filename);
        lrule->loaded = 1;
    }
    switch(lrule->lookup_type)
    {
        case LR_STRING_MATCH:
            //debug1("LR_STRING_MATCH");
            if(OS_DBSeachKey(lrule, key) == 1)
                return 1;
            else
                return 0;
            break;
        case LR_STRING_NOT_MATCH:
            //debug1("LR_STRING_NOT_MATCH");
            if(OS_DBSeachKey(lrule, key) == 1)
                return 0;
            else
                return 1;
            break;
        case LR_STRING_MATCH_VALUE:
            //debug1("LR_STRING_MATCH_VALUE");
           if (OS_DBSearchKeyValue(lrule, key) == 1)
                return 1;
            else
                return 0;
            break;
        case LR_ADDRESS_MATCH:
            //debug1("LR_ADDRESS_MATCH");
            return OS_DBSeachKeyAddress(lrule, key);
            break;
        case LR_ADDRESS_NOT_MATCH:
            //debug1("LR_ADDRESS_NOT_MATCH");
            if (OS_DBSeachKeyAddress(lrule, key) == 0)
                return 1;
            else
                return 0;
            break;
        case LR_ADDRESS_MATCH_VALUE:
            //debug1("LR_ADDRESS_MATCH_VALUE");
            if (OS_DBSearchKeyAddressValue(lrule, key) == 0)
                return 1;
            else
                return 0;
            break;
        default:
            debug1("lists_list.c::OS_DBSearch should never hit default");
            return 0;
    }
    return 0;
}

