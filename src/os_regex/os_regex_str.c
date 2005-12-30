/*   $OSSEC, os_regex_str.c, v0.1, 2005/12/29, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
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
#include "os_regex_internal.h"


/** int OS_StrIsNum(char *str) v0.1
 * Checks if a specific string is numeric (like "129544")
 */
int OS_StrIsNum(char *str)
{
    if(str == NULL)
        return(FALSE);
        
    while(*str != '\0')
    {
        if(!_IsD(*str))
            return(FALSE); /* 0 */
        str++;    
    }

    return(TRUE);
}

/** int OS_StrStartsWith(char *str, char *pattern) v0.1
 * Verifies if a string starts with the provided pattern.
 * Returns 1 on success or 0 on failure.
 */
#define startswith(x,y) (strncmp(x,y,strlen(y)) == 0?1:0)  
#define OS_StrStartsWith startswith 
//int OS_StrStartsWith(char *str, char *pattern)
//{
//}

/* EOF */
