/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "shared.h"
#include "string.h"

/** os_trimcrlf
 * Trims the cr and/or LF from the last positions of a string
 */
void os_trimcrlf(char *str)
{
    int len;

    len=strlen(str);
    len--;

    while (str[len]=='\n' || str[len]=='\r')
    {
       str[len]='\0'; 
       len--;
    } 
}

/**  os_substring
 *   Breaks a string into fields based on the delimiter
 *   and returns field in numbered position
 *   Parameters:
 *      str - the string to be searched
 *      delimiter - the string to be used as delimiter
 *      pos - the field to be returned
 */
char* os_substring(char *str, char *pattern, int pos)
{
   char *ret;
   int  i;

   return(ret);
}


/* EOF */
