/*   $OSSEC, os_match_compile.c, v0.1, 2006/04/17, Daniel B. Cid$   */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "os_regex.h"
#include "os_regex_internal.h"


/** int OSMatch_Compile(char *pattern, OSMatch *reg, int flags) v0.1
 * Compile a pattern to be used later.
 * Allowed flags are:
 *      - OS_CASE_SENSITIVE
 * Returns 1 on success or 0 on error.
 * The error code is set on reg->error.
 */
int OSMatch_Compile(char *pattern, OSMatch *reg, int flags)
{
    int i = 0;
    int count = 0;
    int end_of_string = 0;
    
    char *pt;
    char *new_str;
    char *new_str_free = NULL;

    
    /* Checking for references not initialized */
    if(reg == NULL)
    {
        return(0);
    }
    

    /* Initializing OSRegex structure */
    reg->error = 0;
    reg->patterns = NULL;
    reg->size = NULL;


    /* The pattern can't be null */
    if(pattern == NULL)
    {
        reg->error = OS_REGEX_PATTERN_NULL;
        goto compile_error;
    }


    /* Maximum size of the pattern */
    if(strlen(pattern) > OS_PATTERN_MAXSIZE)
    {
        reg->error = OS_REGEX_MAXSIZE;
        goto compile_error;
    }
    
    
    /* Duping the pattern for our internal work */
    new_str = strdup(pattern);
    if(!new_str)
    {
        reg->error = OS_REGEX_OUTOFMEMORY;
        goto compile_error;
    }
    new_str_free = new_str;
    pt = new_str;
    
    
    /* Getting the number of sub patterns */
    do
    {
        /* The pattern must be always lower case if 
         * case sensitive is set
         */
        if(!(flags & OS_CASE_SENSITIVE))
        {
            *pt = charmap[(uchar)*pt];
        }
       
        /* Number of sub patterns */ 
        if(*pt == OR)
        {
            count++;
        }
        pt++;    
    }while(*pt != '\0');
    
    
    /* For the last pattern */
    count++;
    reg->patterns = calloc(count +1, sizeof(char *));
    reg->size = calloc(count +1, sizeof(int));
    
    
    /* Memory allocation error check */
    if(!reg->patterns || !reg->size)
    {
        reg->error = OS_REGEX_OUTOFMEMORY;
        goto compile_error;
    }


    /* Initializing each sub pattern */
    for(i = 0; i<=count; i++)
    {
        reg->patterns[i] = NULL;
        reg->size[i] = 0;
    }
    i = 0;
    
    
    /* Reassigning pt to the beginning of the string */
    pt = new_str;

    
    /* Getting the sub patterns */
    do
    {
        if((*pt == OR) || (*pt == '\0'))
        {
            if(*pt == '\0')
            {
                end_of_string = 1;
            }

            *pt = '\0';

            
            reg->patterns[i] = strdup(new_str);

            if(!reg->patterns[i])
            {
                reg->error = OS_REGEX_OUTOFMEMORY;
                goto compile_error;

            }

            /* If string starts with ^, decrement size */
            if(*new_str == BEGINREGEX)
            {
                reg->size[i] = strlen(reg->patterns[i]) -1;
            }
            else
            {
                reg->size[i] = strlen(reg->patterns[i]);
            }

            if(end_of_string)
            {
                break;
            }

            new_str = ++pt;
            i++;
            continue;
        }
        pt++;

    }while(!end_of_string);


    /* Success return */
    free(new_str_free);
    return(1);
    
    
    /* Error handling */
    compile_error:
    
    if(new_str_free)
    {
        free(new_str_free);
    }
    
    OSMatch_FreePattern(reg);

    return(0);
}


/* EOF */
