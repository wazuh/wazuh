/*   $OSSEC, mem_op.c, v0.1, 2005/04/05, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <stdlib.h>

/* Clear the memory of one char and one char** */
void ClearStrMem(char *ch1, char **ch2)
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

/* EOF */
