/*   $OSSEC, os_regex.h, v0.3, 2005/04/05, Daniel B. Cid$   */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* See README for details */


#ifndef __OS_REGEX_H
#define __OS_REGEX_H


/* OSRegex_Compile flags */
#define OS_RETURN_SUBSTRING     0000200
#define OS_CASE_SENSITIVE       0000400


/* Pattern maximum size */
#define OS_PATTERN_MAXSIZE      2048


/* Error codes */
#define OS_REGEX_REG_NULL       1
#define OS_REGEX_PATTERN_NULL   2
#define OS_REGEX_MAXSIZE        3
#define OS_REGEX_OUTOFMEMORY    4
#define OS_REGEX_STR_NULL       5
#define OS_REGEX_BADREGEX       6
#define OS_REGEX_BADPARENTHESIS 7
#define OS_REGEX_NO_MATCH       8


/* OSRegex structure */
typedef struct _OSRegex
{
    int error;
    int *flags;
    char **patterns;
    char **sub_strings;
    char ***prts_closure;
    char ***prts_str;
}OSRegex;


/* OSmatch structure */
typedef struct _OSMatch
{
    int error;
    int *size;
    char **patterns;
    int (**match_fp)(char *str, char *str2, int str_len, int size);
}OSMatch;


/*** Prototypes ***/


/** int OSRegex_Compile(char *pattern, OSRegex *reg, int flags) v0.1
 * Compile a regular expression to be used later.
 * Allowed flags are:
 *      - OS_CASE_SENSITIVE
 *      - OS_RETURN_SUBSTRING
 * Returns 1 on success or 0 on error.
 * The error code is set on reg->error.
 */
int OSRegex_Compile(char *pattern, OSRegex *reg, int flags);


/** char *OSRegex_Execute(char *str, OSRegex *reg) v0.1
 * Compare an already compiled regular expression with
 * a not NULL string.
 * Returns end of str on success or NULL on error.
 * The error code is set on reg->error.
 */
char *OSRegex_Execute(char *str, OSRegex *reg);


/** int OSRegex_FreePattern(SRegex *reg) v0.1
 * Release all the memory created by the compilation/executation
 * phases.
 * Returns void.
 */
void OSRegex_FreePattern(OSRegex *reg);


/** int OSRegex_FreeSubStrings(OSRegex *reg) v0.1
 * Release all the memory created to store the sub strings.
 * Returns void.
 */
void OSRegex_FreeSubStrings(OSRegex *reg);


/** int OS_Regex(char *pattern, char *str) v0.4
 * This function is a wrapper around the compile/execute
 * functions. It should only be used when the pattern is
 * only going to be used once.
 * Returns 1 on success or 0 on failure.
 */
int OS_Regex(char *pattern, char *str);



/** int OSMatch_Compile(char *pattern, OSMatch *reg, int flags) v0.1
 * Compile a pattern to be used later.
 * Allowed flags are:
 *      - OS_CASE_SENSITIVE
 * Returns 1 on success or 0 on error.
 * The error code is set on reg->error.
 */
int OSMatch_Compile(char *pattern, OSMatch *reg, int flags);


/** int OSMatch_Execute(char *str, int str_len, OSMatch *reg) v0.1
 * Compare an already compiled pattern with
 * a not NULL string.
 * Returns 1 on success or 0 on error.
 * The error code is set on reg->error.
 */
int OSMatch_Execute(char *str, int str_len, OSMatch *reg);


/** int OSMatch_FreePattern(OSMatch *reg) v0.1
 * Release all the memory created by the compilation/executation
 * phases.
 * Returns void.
 */
void OSMatch_FreePattern(OSMatch *reg);


int OS_Match2(char *pattern, char *str);

int OS_Match3(char *pattern, char *str, char* delimiter);


/* OS_WordMatch v0.3:
 * Searches for  pattern in the string
 */
int OS_WordMatch(char *pattern, char *str);
#define OS_Match OS_WordMatch


/** char **OS_StrBreak(char match, char *str, int size) v0.2
 * Split a string into multiples pieces, divided by a char "match".
 * Returns a NULL terminated array on success or NULL on error.
 */
char **OS_StrBreak(char match, char *str, int size);


/** int OS_StrHowClosedMatch(char *str1, char *str2) v0.1
 * Returns the number of characters that both strings
 * have in similar (start at the beginning of them).
 */
int OS_StrHowClosedMatch(char *str1, char *str2);


/** Inline prototypes **/


/** int OS_StrStartsWith(char *str, char *pattern) v0.1
 * Verifies if a string starts with the provided pattern.
 * Returns 1 on success or 0 on failure.
 */
#include <string.h>
#define startswith(x,y) (strncmp(x,y,strlen(y)) == 0?1:0)
#define OS_StrStartsWith startswith


/** int OS_StrIsNum(char *str) v0.1
 * Checks if a specific string is numeric (like "129544")
 */
int OS_StrIsNum(char *str);


/** int isValidChar(char c)
 * Checks if a specified char is in the following range:
 * a-z, A-Z, 0-9, _-.
 */
#include "os_regex_maps.h"
#define isValidChar(x) (hostname_map[(unsigned char)x])


#endif


/* EOF */
