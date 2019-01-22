/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#ifndef __OS_INTERNAL_H
#define __OS_INTERNAL_H

/* Prototype for the _OsMatch */
int _OS_Match(const char *pattern, const char *str, size_t str_len, size_t size) __attribute__((nonnull));
int _os_strncmp(const char *pattern, const char *str, size_t str_len, size_t size) __attribute__((nonnull));
int _os_strcmp_last(const char *pattern, const char *str, size_t str_len, size_t size) __attribute__((nonnull));
int _os_strcmp(const char *pattern, const char *str, size_t str_len, size_t size) __attribute__((nonnull));
int _os_strmatch(const char *pattern, const char *str, size_t str_len, size_t size) __attribute__((nonnull));

#define BACKSLASH   '\\'
#define ENDSTR      '\0'
#define ENDLINE     '\n'
#define BEGINREGEX  '^'
#define ENDREGEX    '$'
#define OR          '|'
#define AND         '&'

#define TRUE         1
#define FALSE        0

/* Pattern flags */
#define BEGIN_SET   0000200
#define END_SET     0000400

/* uchar */
typedef unsigned char uchar;

/* _IsD Returns 1 if it is a number */
#define _IsD(x) ((x >= 48) && (x <= 57))

/* Is it a character?
 * a-z or A-Z or 0-9
 * Returns 1 if true
 */
#define _IsW(x) ((x >= 48 && x <= 57 )|| \
                 (x >= 65 && x <= 90 )|| \
                 (x >= 97 && x <= 122))

/* Is it a ' ' (blank)
 * Ascii 32
 * Returns 1 if true
 */
#define _IsS(x) (x == 32)

/* Check for parenthesis */
#define prts(x) (x == '(')

/* Is it '+' or '*'
 * Returns 1 on success
 */
#define isPlus(x)    ((x == '+') || (x == '*'))

/* True char */
#define TRUECHAR    1

/* Is "y" a valid "x"?.
 * Returns 1 on success
 */
#define Regex(x,y)   (regexmap[x][y] == TRUECHAR)
#define Regex2(x,y)   (x == 'd' && y >= 48 && y <= 57)|| \
                     (x == 's' && y == 32)|| \
                     ((x == 'p') && \
                      ((y >= 40 && y <= 46)|| \
                      (y >= 58 && y <= 63)))|| \
                     ((x == 'w') && \
                      ((y == '_')|| \
                      (y >= 48 && y <= 57)|| \
                      (y >= 65 && y <= 90)|| \
                      (y >= 97 && y <= 122)))|| \
                     (x == '.')|| \
                     ((x == '\\') && (y == '\\'))|| \
                     ((x == 'n') && (y == '\n'))|| \
                     (x == 'S' && y != 32)|| \
                     (x == 'D' && (y < 48 || y > 57))|| \
                     (x == 'W' && (y < 48 || y > 122 || \
                     (y > 57 && y <65)||(y > 90 && y< 97)))

/* Charmap for case insensitive search */
extern const uchar charmap[256];

/* Regex mapping
 * 0  = none
 * 1  = \d
 * 2  = \w
 * 3  = \s
 * 4  = \p
 * 5  = \(
 * 6  = \)
 * 7  = \\
 * 8  = \D
 * 9  = \W
 * 10 = \S
 * 11 = \.
 * 12 = \t
 * 13 = \$
 * 14 = |
 * 15 = <
 */
extern const uchar regexmap[][256];

#endif /* __OS_INTERNAL_H */

