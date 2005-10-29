/*   $OSSEC, list_op.c, v0.1, 2005/10/28, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Common API for dealing with lists */ 


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug_op.h"
#include "list_op.h"
#include "error_messages/error_messages.h"



/* Create the list 
 * No error returned
 */
OSList *OS_CreateList()
{
    OSList *my_list = NULL;
    return(my_list);
}

/* Get first node from rule 
 * Returns null on invalid list
 */
OSList *OS_GetFirstNode(OSList *list)
{
    return(list);
}


/* Add data to the list
 * Returns 1 on sucess and 0 on failure
 */
int OS_AddData(OSList *list, void *data)
{
    OSList *tmp_list = list;
    OSList *newnode;

    if(tmp_list == NULL)
    {
        tmp_list = calloc(1, sizeof(OSList));
        if(!tmp_list)
        {
            merror(MEM_ERROR, ARGV0);
            return(0);
        }

        tmp_list->data = data;
        tmp_list->next = NULL;

        return(1);
    }
    
    
    while(tmp_list->next != NULL)
    {
        tmp_list = tmp_list->next;
    }
    

    newnode = calloc(1, sizeof(OSList));
    if(!newnode)
    {
        merror(MEM_ERROR, ARGV0);
        return(0);
    }

    tmp_list->next = newnode;

    newnode->data = data;
    newnode->next = NULL;
    
    return(1);
}

/* EOF */
