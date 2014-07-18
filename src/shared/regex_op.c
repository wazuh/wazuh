/* @(#) $Id: ./src/shared/regex_op.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WIN32
#include "shared.h"
#include <regex.h>



/* OS_PRegex:
 * Compile a posix regex, returning NULL on error
 * Returns 1 if matches, 0 if not.
 */
int OS_PRegex(const char *str, const char *regex)
{
    regex_t preg;

    if(!str || !regex)
        return(0);


    if(regcomp(&preg, regex, REG_EXTENDED|REG_NOSUB) != 0)
    {
        merror("%s: Posix Regex compile error (%s).", __local_name, regex);
        return(0);
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

#endif

/* EOF */
