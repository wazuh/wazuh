/*      $OSSEC, regex_op.c, v0.1, 2005/10/02, Daniel B. Cid$      */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <string.h>
#include <regex.h>

#include "headers/debug_op.h"
#include "error_messages/error_messages.h"


/* OS_PRegex:
 * Compile a posix regex, returning NULL on error
 * Returns 1 if matches, 0 if not.
 */
int OS_PRegex(char *str, char *regex)
{
    regex_t preg;
    
    if(!str || !regex)
        return(0);
    
    
    if(regcomp(&preg, regex, REG_EXTENDED|REG_NOSUB) != 0)
    {
        merror("%s: Regex compile error (%s)\n",ARGV0, regex);
    }

    if(regexec(&preg, str, strlen(str), NULL, 0) != 0)
    {
        /* Didn't match */
        regfree(&preg);
        return(0);
    }

    regfree(&preg);
    return(1);
    
}


/* EOF */
