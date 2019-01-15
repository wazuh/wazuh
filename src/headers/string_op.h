/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef H_STRINGOP_OS
#define H_STRINGOP_OS

#include <external/cJSON/cJSON.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>

#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS 0x80
#endif

/* converts a Windows format string to char* */
char *convert_windows_string(LPCWSTR string);
#endif

// Convert string to lowercase
#define str_lowercase(str_lc) { char *x = str_lc; while (*x != '\0') { *x = tolower(*x); x++; } }

// Convert double to string
#define w_double_str(x) ({char *do_str; os_calloc(20, sizeof(char),do_str); snprintf(do_str, 19, "%f", x); do_str;})

/* Trim the CR and/or LF from the last positions of a string */
void os_trimcrlf(char *str) __attribute__((nonnull));

/* Similiar to Perl's substr() function */
int os_substr(char *dest, const char *src, size_t position, ssize_t length) __attribute__((nonnull(1)));

/* Remove a character from a string */
char *os_strip_char(const char *source, char remove) __attribute__((nonnull));

/* Escape a list of characters with a backslash */
char *os_shell_escape(const char *src);

/* Count the number of repetitions of needle at haystack */
size_t os_strcnt(const char *haystack, char needle);

// Trim whitespaces from string
char * w_strtrim(char * string);

// Add a dynamic field with object nesting
void W_JSON_AddField(cJSON *root, const char *key, const char *value);

// Searches haystack for needle. Returns 1 if needle is found in haystack.
int w_str_in_array(const char * needle, const char ** haystack);

/* Filter escape characters */
char* filter_special_chars(const char *string);

// Replace substrings
char * wstr_replace(const char * string, const char * search, const char * replace);

// Locate first occurrence of non escaped character in string
char * wstr_chr(char * str, int character);

// Free string array
void free_strarray(char ** array);

/* Returns 0 if str is found */
int wstr_find_in_folder(char *path,const char *str,int strip_new_line);

/* Returns 0 if str is found */
int wstr_find_line_in_file(char *file,const char *str,int strip_new_line);

// Delete last occurrence of duplicated string
char * wstr_delete_repeated_groups(const char * string);

/* Concatenate strings with optional separator
 *
 * str1 must be a valid pointer to NULL or a string at heap
 * Returns 0 if success, or -1 if fail.
 */
int wm_strcat(char **str1, const char *str2, char sep);

// Check if str ends in str_end
int wstr_end(char *str, const char *str_end);

#endif
