/* @(#) $Id: ./src/headers/string_op.h, 2011/09/08 dcid Exp $
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


#ifndef H_STRINGOP_OS
#define H_STRINGOP_OS


/** os_trimcrlf
 * Trims the cr and/or LF from the last positions of a string
 */
void os_trimcrlf(char *str);

/* Similiar to Perl's substr() function */
int os_substr(char *dest, const char *src, size_t position, size_t length);

/* Remove a character from a string */
char *os_strip_char(const char *source, char remove);

/* Escape a list of characters with a backslash */
char *os_shell_escape(const char *src);

#endif

/* EOF */
