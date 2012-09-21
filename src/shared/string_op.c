/* @(#) $Id: ./src/shared/string_op.c, 2011/11/01 dcid Exp $
 */

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

/* Remove offending char (e.g., double quotes) from source */
char *os_strip_char(const char *source, char remove) {
    char *clean = malloc( strlen(source) + 1 );
    int i;

    for( i=0; *source; source++ ) {
        if ( *source != remove ) {
            clean[i] = *source;
            i++;
        }
    }
    clean[i] = 0;

    return clean;
}

/* Do a substring */
int os_substr(char *dest, const char *src, int position, int length) {
    dest[0]='\0';

    if( src == NULL ) {
        return -2;
    }
    if( position > strlen(src) ) {
        return -1;
    }

    strncat(dest, (src + position), length);
    // Return Success
    return 0;
}


/* EOF */
