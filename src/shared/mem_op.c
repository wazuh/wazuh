/* @(#) $Id$ */

/* Copyright (C) 2005,2006 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


#include "mem_op.h"


/* Check if String is on array (Must be NULL terminated) */
int os_IsStrOnArray(char *str, char **array)
{
    if(!str || !array)
    {
        return(0);
    }

    while(*array)
    {
        if(strcmp(*array, str) == 0)
        {
            return(1);
        }
        array++;
    }
    return(0);
}


/* Clear the memory of one char and one char** */
void os_FreeArray(char *ch1, char **ch2)
{
    /* Cleaning char * */
    if(ch1)
    {
        free(ch1);
        ch1 = NULL;
    }
    
    /* Cleaning chat ** */
    if(ch2)
    {
        char **nch2 = ch2;
            
        while(*ch2 != NULL)
        {
            free(*ch2);
            ch2++;
        }
    
        free(nch2);
        nch2 = NULL;
    }
    
    return;
}


/* os_LoadString: v0.1
 * Allocate memory at "*at" and copy *str to it.
 * If *at already exist, realloc the memory and strcat str
 * on it.
 * It will return the new string on success or NULL on memory error.
 */
char *os_LoadString(char *at, char *str)
{
    if(at == NULL)
    {
        int strsize = 0;
        if((strsize = strlen(str)) < OS_SIZE_2048)
        {
            at = calloc(strsize+1,sizeof(char));
            if(at == NULL)
            {
                merror(MEM_ERROR,ARGV0);
                return(NULL);
            }
            strncpy(at, str, strsize);
            return(at);
        }
        else
        {
            merror(SIZE_ERROR,ARGV0,str);
            return(NULL);
        }
    }
    else /*at is not null. Need to reallocat its memory and copy str to it*/
    {
        int strsize = strlen(str);
        int atsize = strlen(at);
        int finalsize = atsize+strsize+1;

        if((atsize > OS_SIZE_2048) || (strsize > OS_SIZE_2048))
        {
            merror(SIZE_ERROR,ARGV0,str);
            return(NULL);
        }

        at = realloc(at, (finalsize)*sizeof(char));

        if(at == NULL)
        {
            merror(MEM_ERROR,ARGV0);
            return(NULL);
        }

        strncat(at,str,strsize);

        at[finalsize-1] = '\0';

        return(at);
    }
    return(NULL);
}


/* EOF */
