/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "string.h"

#ifdef WIN32
#ifdef EVENTCHANNEL_SUPPORT
#define _WIN32_WINNT 0x0600
#endif
#endif

/* Trim CR and/or LF from the last positions of a string */
void os_trimcrlf(char *str)
{
    size_t len;

    len = strlen(str);
    len--;

    while (str[len] == '\n' || str[len] == '\r') {
        str[len] = '\0';
        len--;
    }
}

/* Remove offending char (e.g., double quotes) from source */
char *os_strip_char(const char *source, char remove)
{
    char *clean;
    const char *iterator = source;
    size_t length = 0;
    int i;

    /* Figure out how much memory to allocate */
    for ( ; *iterator; iterator++ ) {
        if ( *iterator != remove ) {
            length++;
        }
    }

    /* Allocate the memory */
    if ( (clean = (char *) malloc( length + 1 )) == NULL ) {
        // Return NULL
        return NULL;
    }
    memset(clean, '\0', length + 1);

    /* Remove the characters */
    iterator = source;
    for ( i = 0; *iterator; iterator++ ) {
        if ( *iterator != remove ) {
            clean[i] = *iterator;
            i++;
        }
    }

    return clean;
}

/* Do a substring */
int os_substr(char *dest, const char *src, size_t position, ssize_t length)
{
    dest[0] = '\0';

    if ( length <= 0  ) {
        /* Unsupported negative length string */
        return -3;
    }
    if ( src == NULL ) {
        return -2;
    }
    if ( position >= strlen(src) ) {
        return -1;
    }

    strncat(dest, (src + position), (size_t) length);

    return 0;
}

/* Escape a set of characters */
char *os_shell_escape(const char *src)
{
    /* Maximum Length of the String is 2 times the current length */
    char shell_escapes[] = { '\\', '"', '\'', ' ', '\t', ';', '`', '>', '<', '|', '#',
                             '*', '[', ']', '{', '}', '&', '$', '!', ':', '(', ')'
                           };

    char *escaped_string;
    size_t length = 0;
    int i = 0;

    if (src == NULL) {
        return NULL;
    }

    /* Determine how long the string will be */
    const char *iterator = src;
    for (; *iterator; iterator++) {
        if ( strchr(shell_escapes, *iterator) ) {
            length++;
        }
        length++;
    }
    /* Allocate memory */
    if ( (escaped_string = (char *) calloc(1, length + 1 )) == NULL ) {
        // Return NULL
        return NULL;
    }

    /* Escape the escapable characters */
    iterator = src;
    for ( i = 0; *iterator; iterator++ ) {
        if ( strchr(shell_escapes, *iterator) ) {
            escaped_string[i] = '\\';
            i++;
        }
        escaped_string[i] = *iterator;
        i++;
    }

    return escaped_string;
}

/* Count the number of repetitions of needle at haystack */
size_t os_strcnt(const char *haystack, char needle) {
    size_t count = 0;
    char *ptr;

    for (ptr = strchr(haystack, needle); ptr; ptr = strchr(ptr + 1, needle))
        count++;

    return count;
}

// Trim whitespaces from string

char * w_strtrim(char * string) {
    char *c;
    char *d;

    string = &string[strspn(string, " ")];
    for (c = string + strcspn(string, " "); *(d = c + strspn(c, " ")); c = d + strcspn(d, " "));
    *c = '\0';
    return string;
}

// Add a dynamic field with object nesting
void W_JSON_AddField(cJSON *root, const char *key, const char *value) {
    cJSON *object;
    char *current;
    char *nest = strchr(key, '.');
    size_t length;

    if (nest) {
        length = nest - key;
        current = malloc(length + 1);
        strncpy(current, key, length);
        current[length] = '\0';

        if (object = cJSON_GetObjectItem(root, current), object) {
            if (cJSON_IsObject(object)) {
                W_JSON_AddField(object, nest + 1, value);
            }
        } else {
            cJSON_AddItemToObject(root, current, object = cJSON_CreateObject());
            W_JSON_AddField(object, nest + 1, value);
        }

        free(current);
    } else if (!cJSON_GetObjectItem(root, key)) {
        cJSON_AddStringToObject(root, key, value);
    }
}

// Searches haystack for needle. Returns 1 if needle is found in haystack.

int w_str_in_array(const char * needle, const char ** haystack) {
    int i;

    if (!(needle && haystack)) {
        return 0;
    }

    for (i = 0; haystack[i]; i++) {
        if (strcmp(needle, haystack[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

/* Filter escape characters */

char* filter_special_chars(const char *string) {
    int i, j = 0;
    int n = strlen(string);
    char *filtered = malloc(n + 1);

    if (!filtered)
        return NULL;

    for (i = 0; i <= n; i++)
        filtered[j++] = (string[i] == '\\') ? string[++i] : string[i];

    return filtered;
}

#ifdef WIN32

char *convert_windows_string(LPCWSTR string)
{
    char *dest = NULL;
    size_t size = 0;
    int result = 0;

    if (string == NULL) {
        return (NULL);
    }

    /* Determine size required */
    size = WideCharToMultiByte(CP_UTF8,
                               WC_ERR_INVALID_CHARS,
                               string,
                               -1,
                               NULL,
                               0,
                               NULL,
                               NULL);

    if (size == 0) {
        mferror(
            "Could not WideCharToMultiByte() when determining size which returned (%lu)",
            GetLastError());
        return (NULL);
    }

    if ((dest = calloc(size, sizeof(char))) == NULL) {
        mferror(
            "Could not calloc() memory for WideCharToMultiByte() which returned [(%d)-(%s)]",
            errno,
            strerror(errno)
        );
        return (NULL);
    }

    result = WideCharToMultiByte(CP_UTF8,
                                 WC_ERR_INVALID_CHARS,
                                 string,
                                 -1,
                                 dest,
                                 size,
                                 NULL,
                                 NULL);

    if (result == 0) {
        mferror(
            "Could not WideCharToMultiByte() which returned (%lu)",
            GetLastError());
        free(dest);
        return (NULL);
    }

    return (dest);
}

#endif
