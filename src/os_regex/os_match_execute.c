/*   $OSSEC, os_match_execute.c, v0.1, 2006/04/18, Daniel B. Cid$   */

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

#include "os_regex.h"
#include "os_regex_internal.h"


/** Internal matching **/
int _OS_Match(char *pattern, char *str, int size)
{
    int i = 0,j;
    char *pt = pattern;

    /* Look to match the first pattern */
    do
    {
        /* Match */
        if(charmap[(uchar)str[i]] == *pt)
        {
            pt++;
            j = i+1;

            while(*pt != '\0')
            {
                if(str[j] == '\0')
                    return(FALSE);
                    
                else if(*pt != charmap[(uchar)str[j]])
                {
                    pt = pattern;           
                    goto nnext;
                }
                j++;pt++;
            }
            return(TRUE);
            nnext:
            continue;
        }
    }while(++i <= size);

    return(FALSE);
}


/** int OSMatch_Execute(char *str, int str_len, OSMatch *reg) v0.1
 * Compare an already compiled pattern with
 * a not NULL string.
 * Returns 1 on success or 0 on error.
 * The error code is set on reg->error.
 */
int OSMatch_Execute(char *str, int str_len, OSMatch *reg)
{
    short int i = 0;
    
    /* The string can't be NULL */
    if(str == NULL)
    {
        reg->error = OS_REGEX_STR_NULL;
        return(0);
    }


    /* Looping on all sub patterns */
    while(reg->patterns[i])
    {
        if(reg->patterns[i][0] == BEGINREGEX)
        {
            if(strncmp(reg->patterns[i] +1, str, reg->size[i]) == 0)
                return(1);
        }
        else
        {
            if(_OS_Match(reg->patterns[i], str, str_len - reg->size[i]))
                return(1);
        }
        i++;
    }

    return(0);
}    


/* EOF */
