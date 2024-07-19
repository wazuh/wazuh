/* Copyright (C) 2015, Wazuh Inc.
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

#include <cJSON.h>
#include <stdbool.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>

#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS 0x80
#endif

/* converts a Windows format string to char* */
char *convert_windows_string(LPCWSTR string);
#endif

// Time values for conversion
#define W_WEEK_SECONDS      604800
#define W_DAY_SECONDS       86400
#define W_HOUR_SECONDS      3600
#define W_MINUTE_SECONDS    60

// Time units
#define W_WEEKS_L   "week(s)"
#define W_WEEKS_S   "w"
#define W_DAYS_L    "day(s)"
#define W_DAYS_S    "d"
#define W_HOURS_L   "hour(s)"
#define W_HOURS_S   "h"
#define W_MINUTES_L "minute(s)"
#define W_MINUTES_S "m"
#define W_SECONDS_L "second(s)"
#define W_SECONDS_S "s"

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
char * wstr_chr(const char * str, char character);

/**
 * @brief Locate first occurrence of non escaped character in string.
 *
 * @param str A valid pointer to a string where look for a non escaped character.
 * @param character The non escaped character.
 * @param escape The character used to escape.
 * @return The position of the non escaped character, or NULL if fail.
 */
char * wstr_chr_escape(const char * str, char character, char escape);

/**
 * @brief Escape a specific character from a character string.
 *
 * @param dststr A valid pointer to a char buffer where escaped string will be stored.
 * @param dst_size The dststr size to control buffer overflow.
 * @param str A valid pointer to a string to escape.
 * @param escape The character used to escape.
 * @param match The value to escape.
 * @return The size of the dststr if success, or OS_INVALID if fail.
 */
ssize_t wstr_escape(char *dststr, size_t dst_size, const char *str, char escape, char match);

/**
 * @brief Unescape a specific character from a character string.
 *
 * @param dststr A valid pointer to a char buffer where unescaped string will be stored.
 * @param dst_size The dststr size to control buffer overflow.
 * @param str A valid pointer to a string to unescape.
 * @param escape The character used to unescape.
 * @return The size of the dststr if success, or OS_INVALID if fail.
 */
ssize_t wstr_unescape(char *dststr, size_t dst_size, const char *str, char escape);

// Free string array
void free_strarray(char ** array);

// Get the size of a string array
size_t strarray_size(char ** array);

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

/**
 * @brief Parse positive size string into bytes
 *
 * Format: ^[0-9]+(b|B|k|K|m|M|g|G)?
 *
 * b/B: bytes
 * k/K: kilobytes
 * m/M: megabytes
 * g/G: gigabytes
 *
 * Any character after the first byte is ignored.
 *
 * @param string Input string.
 * @pre string is not null.
 * @return Size represented in bytes.
 * @retval -1 Cannot parse string, or value is negative.
 */
ssize_t w_parse_size(const char * string);

/**
 * @brief Convert seconds into the greater valid time unit (s|m|h|d|w).
 * The conversion will always round down the output.
 *
 * s: seconds
 * m: minutes
 * h: hours
 * d: days
 * w: weeks
 *
 * @param seconds Positive amount of seconds.
 * @param long_format Format of the output.
 *                    TRUE: long format ("second(s)").
 *                    FALSE: short format ("s")
 * @return String with the time unit.
 * @retval "invalid" if the input is negative. A time unit if the input is valid.
 */
char* w_seconds_to_time_unit(long seconds, bool long_format);

/**
 * @brief Convert seconds into the greater time value.
 *  * The conversion will always round down the output.
 *
 * @param seconds Positive amount of seconds.
 * @return Value of the seconds converted to the greater time unit.
 * @retval - if the input is negative. A time value if the input is valid.
 */
long w_seconds_to_time_value(long seconds);

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

/**
 * @brief Split a string into an array of strings separated by given delimiters.
 * @param string_to_split String to split.
 * @param delim String with the delimiters used to split.
 * @param max_array_size Maximum number of strings returned in the array, if it is 0 no limit will be applied.
 * @return char** Returns an array of string.
 */
char ** w_string_split(const char *string_to_split, const char *delim, int max_array_size);

/**
 * @brief Append two strings
 *
 * This function produces a string with length #a + n, and joins the content
 * of a and the first n bytes of b.
 * Semantics are like: a += b[:n].
 *
 * @param a First string.
 * @param b Second string.
 * @param n Length of the left-substring in b that will be copied.
 * @return Pointer to a zero-ended string that contains the concatenation of a + b.
 * @pre a may be NULL. In that case, this function returns strdup(b).
 * @pre b must contain at less n valid bytes.
 * @post String a is freed and it's not valid after calling this function.
 */
char* w_strcat(char *a, const char *b, size_t n);

/**
 * @brief Append a string into the n-th position of a string array
 *
 * Extends the size of the array to (n + 1) pointers, sets array[n] to string,
 * and terminates the array with NULL.
 *
 * @param array Pointer to the source string array, that will be extended.
 * @param string Pointer to the string that will be inserted into the array.
 * @param n Position of the current tail of the array (null pointer).
 * @return A pointer to a string array.
 * @pre array has n valid positions before calling this function.
 * @post array holds the same pointer that this function received, i.e. strings are not duplicated.
 * @post The pointer to array is no longer valid as it's resized.
 */
char** w_strarray_append(char **array, char *string, int n);

/**
 * @brief Tokenize string separated by spaces, respecting double-quotes
 *
 * Splits words in a string separated by spaces into an array.
 * Parts within double-quotes are not splitted.
 * The backslash character escapes spaces, double-quotes and backslashes.
 *
 * @param string Pointer to the source string.
 * @return Pointer to a NULL-terminated string array.
 * @post The structure returned must be freed with free_strarray().
 */
char** w_strtok(const char *string);

/**
 * @brief Concatenate a NULL-terminated string list into a single string
 *
 * @param list String list to concatenate
 * @param sep Optional separator. Set to 0 if unused.
 * @return Allocated string with list concatenation.
 */
char* w_strcat_list(char ** list, char sep);

/**
 * @brief Convert a given string to hexadecimal and store it in a buffer
 * @param src_buf Input buffer containing the string to be converted
 * @param src_size Input buffer size
 * @param dst_buf Output buffer where to store the converted string
 * @param dst_size Output buffer size
 * @return OS_SUCCESS on success, OS_INVALID on failure
 */
int print_hex_string(const char *src_buf, unsigned int src_size, char *dst_buf, unsigned int dst_size);

#endif
