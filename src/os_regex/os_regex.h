/*   $OSSEC, os_regex.h, v0.3, 2005/04/05, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* See README for details */
/* http://www.ossec.net/c/os_regex/ */

#ifndef __OS_REGEX_H
#define __OS_REGEX_H

/*
 * OS_StrBreak.
 * Break a string in "size" pieces, divided by a character
 * "match"
 * Returns 0 in case of success.
 */
char **OS_StrBreak(char match, char * str, int size);

/* OS_GetPiece.
 * Get a piece from a string (str), divided by(in the middle of) 
 * initialpattern and finalpattern. 
 * It will return a pointer to  a string. This pointer must be freeed
 * after use.
 * Returns the new string (or NULL in case of error)
 *
 * initialpattern and finalpattern may contain regular expressions.
 * Look at OS_Regex for the available ones.
 */
char *OS_GetPiece(char *initialpattern, char *finalpattern, char *str);
char **OS_RegexStr(char *pattern, char *str);

/* OS_WordMatch.
 * Match if a word is present in some string.
 * This word (match*) cannot contain regular expressions.
 * The only allowed "regexs" are: 
 *  | : To specify multiple strings
 *  ^ : To seach at the beginning of the string
 *
 * The sensitive case will by case sensitive.
 * The default is case Insensitive.
 */
int OS_WordMatch_Sensitive(char *match, char *str);
int OS_WordMatch(char *pattern, char *str);
#define OS_Match(pattern,str) OS_WordMatch(pattern,str)
#define OS_FastMatch(pattern,str) OS_WordMatch(pattern,str)

/* OS_Regex.
 * Match if a regex is present in some string.
 * We allow the following regex:
 *  \w,\w+,\W,\W+,\d,\d+,\D,\D+,\s,\s+,\S,\S+,
 *  \.,\.+, ^,$ and |
 *
 * Returns 0 in case of success (it matches)
 *
 * The sensitive case will by case sensitive.
 * The default is case insensitive.
 */
int OS_Regex(char *regex, char *str);
int OS_Regex_Sensitive(char *regex, char *str);

/* OS_StrIsNum.
 * Check if a string only contain digits.
 * Returns 0 in case of success
 */
int OS_StrIsNum(char * str);

/* Look at main.c for other examples */
#endif
