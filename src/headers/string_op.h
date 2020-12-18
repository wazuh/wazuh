/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
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

// Convert string to uppercase
#define str_uppercase(str_lc) { char *x = str_lc; while (*x != '\0') { *x = toupper(*x); x++; } }


// Convert double to string
#define w_double_str(x) ({char *do_str; os_calloc(20, sizeof(char),do_str); snprintf(do_str, 19, "%f", x); do_str;})

// Convert long to string
#define w_long_str(x) ({char *do_str; os_calloc(32, sizeof(char),do_str); snprintf(do_str, 31, "%ld", x); do_str;})

// Replace a character in a string
#define wchr_replace(x, y, z) { char *x_it; for (x_it = x; *x_it != '\0'; x_it++) if (*x_it == y) *x_it = z; }

// Count the words of a string
#define w_word_counter(x) ({ int w_count = 0; char *w_it = x; \
    while (*w_it) { if (*w_it != ' ') { w_count++; while (*w_it != ' ' && *w_it != '\0') w_it++; continue;} w_it++;} w_count;})

// Check if a string is a number. It does not work with signs (+/-)
#define w_str_is_number(str) ({char *x = str; for (; *x != '\0'; x++) if (!isdigit(*x)) { x = NULL; break;} x;})

/* Trim the CR and/or LF from the last positions of a string */
void os_trimcrlf(char *str);

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

// Converts a CSV list into JSON style string array ("a,s,d" -> ["a","s","d"])
void csv_list_to_json_str_array(char * const csv_list, char **buffer);

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

/* Split a string within splitted_str
 *  - delim: Words delimiter
 *  - occurrences: Words by division
 *  - replace_delim: (Optional) Replace the delimiter with a new one
*/

void wstr_split(char *str, char *delim, char *replace_delim, int occurrences, char ***splitted_str);

// Check if the specified string is already in the array
int w_is_str_in_array(char *const *ar, const char *str);

// Remove zeros from the end of the decimal number
void w_remove_zero_dec(char *str_number);

/* Similar to strtok_r but checks for full delim appearances */
char *w_strtok_r_str_delim(const char *delim, char **remaining_str);

// Returns the characters number of the string source if, only if, source is included completely in str, 0 in other case.
int w_compare_str(const char * source, const char * str);
const char * find_string_in_array(char * const string_array[], size_t array_len, const char * const str, const size_t str_len);

char *decode_hex_buffer_2_ascii_buffer(const char * const encoded_buffer, const size_t buffer_size);

/**
 * @brief Parse boolean string
 *
 * @param string Input string.
 * @pre string is not null.
 * @retval 1 True.
 * @retval 0 False.
 * @retval -1 Cannot parse string.
 */
int w_parse_bool(const char * string);

/**
 * @brief Parse positive time string into seconds
 *
 * Format: ^[0-9]+(s|m|h|d|w)?
 *
 * s: seconds
 * m: minutes
 * h: hours
 * d: days
 * w: weeks
 *
 * Any character after the first byte is ignored.
 *
 * @param string Input string.
 * @pre string is not null.
 * @return Time represented in seconds.
 * @retval -1 Cannot parse string, or value is negative.
 */
long w_parse_time(const char * string);

/*
 * @brief Length of the initial segment of s which consists entirely of non-escaped bytes different from reject
 *
 * @param s String.
 * @param reject String delimiter.
 * @return size_t Number of bytes in s that are not reject.
 */
size_t strcspn_escaped(const char * s, char reject);

/**
 * @brief Escape JSON reserved characters
 *
 * Add an escape to the following bytes: \b \t \n \f \r " \
 *
 * @param string Input string
 * @return Pointer to a new string containg an escaped copy of "string"
 */
char * wstr_escape_json(const char * string);

/**
 * @brief Unescape JSON reserved characters
 *
 * Unescape sets '\b', '\t', '\n', '\f', '\r', '\"' and '\\'.
 * Bypass any other escape attempt.
 *
 * @param string Input string
 * @return Pointer to a new string containg an unescaped copy of "string"
 */
char * wstr_unescape_json(const char * string);

/**
 * @brief Lowercase a string
 *
 * @param string Input string
 * @return Pointer to a new string containing a lowercased copy of "string"
 */
char * w_tolower_str(const char *string);

/* b64 function prototypes */
char *decode_base64(const char *src);
char *encode_base64(int size, const char *src);

/**
 * @brief Verify the string is not truncated after executing snprintf
 * 
 * @param str Pointer to a buffer where the resulting string is stored.
 * @param size Maximum number of bytes to be used in the buffer.
 * @param format String that contains a format string that follows the same specifications as format in printf.
 * @param ... Depending on the format string, the function may expect a sequence of additional arguments.
 * @return int The number of characters that would have been written if size had been sufficiently large.
 */
int os_snprintf(char *str, size_t size, const char *format, ...);

/**
 * @brief Remove a substring from a string.
 * 
 * @param str Original string.
 * @param sub Substring to remove from the string.
 * @return char* String after removing the substring.
 */
char * w_remove_substr(char *str, const char *sub);

/**
 * @brief Returns a copy of the first n characters of str.
 * 
 * If str is longer than n, only n characters are copied (a terminating character ('\0') is added).
 * if n is zero an empty string is returned.
 * @param str String to copy.
 * @param n Maximum number of characters to copy.
 * @return char* New string copy of str[:n] or NULL if str is null
 */
char * w_strndup(const char *str, size_t n);

#endif
