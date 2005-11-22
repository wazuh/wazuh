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
 * Return NULL on error
 */
OSList *OSList_Create()
{
    OSList *my_list;

    my_list = calloc(1, sizeof(OSList));
    if(!my_list)
        return(NULL);
    
    my_list->first_node = NULL;
    my_list->last_node = NULL;
    my_list->cur_node = NULL;
    my_list->currently_size = 0;
    my_list->max_size = 0;
    
    return(my_list);
}


/* Get first node from list
 * Returns null on invalid list
 */
OSListNode *OSList_GetFirstNode(OSList *list)
{
    list->cur_node = list->first_node;
    return(list->first_node);
}


/* Get last node from list
 * Returns null on invalid list
 */
OSListNode *OSList_GetLastNode(OSList *list)
{
    list->cur_node = list->last_node;
    return(list->last_node);
}


/* Get next node from list
 * Returns null on invalid list
 */
OSListNode *OSList_GetNextNode(OSList *list)
{
    if(list->cur_node == NULL)
        return(NULL);
        
    list->cur_node = list->cur_node->next;
    
    return(list->cur_node);
}
  

/* Delete currently node from list
 * Pointer goes to the next node available.
 * Returns void
 */
void OSList_DeleteCurrentlyNode(OSList *list)
{
    OSListNode *prev;
    OSListNode *next;
    
    if(list->cur_node == NULL)
        return;
    
    prev = list->cur_node->prev;
    next = list->cur_node->next;

    
    /* Setting the previous node of the next one
     * and the next node of the previous one.. :)
     */
    prev->next = next->prev;
    
    /* Freeing the node memory */
    free(list->cur_node);

    /* Setting the currently node to the next one */
    list->cur_node = next;
}


/* Add data to the list
 * Returns 1 on sucess and 0 on failure
 */
int OSList_AddData(OSList *list, void *data)
{
    OSListNode *newnode;    


    /* Allocating memory for new node */
    newnode = calloc(1, sizeof(OSListNode));
    if(!newnode)
    {
        merror(MEM_ERROR, ARGV0);
        return(0);
    }

    newnode->prev = list->last_node;
    newnode->next = NULL;
    newnode->data = data;


    /* If we don't havea first node, assign it */
    if(!list->first_node)
    {
        list->first_node = newnode;
    }
    
    /* If we have a last node, set the next to new node */
    if(list->last_node)
    {
        list->last_node->next = newnode;
    }
    
    
    /* newnode become last node */
    list->last_node = newnode;

    return(1);
}

/* EOF */
