/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "string.h"
#include "../os_regex/os_regex.h"

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
    char shell_escapes[] = { '\\', '"', '\'', '\t', ';', '`', '>', '<', '|', '#',
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

// Replace substrings

char * wstr_replace(const char * string, const char * search, const char * replace) {
    char * result;
    const char * scur;
    const char * snext;
    size_t wi = 0;
    size_t zcur;

    if (!(string && search && replace)) {
        return NULL;
    }

    const size_t ZSEARCH = strlen(search);
    const size_t ZREPLACE = strlen(replace);

    os_malloc(sizeof(char), result);

    for (scur = string; snext = strstr(scur, search), snext; scur = snext + ZSEARCH) {
        zcur = snext - scur;
        os_realloc(result, wi + zcur + ZREPLACE + 1, result);
        memcpy(result + wi, scur, zcur);
        wi += zcur;
        memcpy(result + wi, replace, ZREPLACE);
        wi += ZREPLACE;
    }

    // Copy last chunk

    zcur = strlen(scur);
    os_realloc(result, wi + zcur + 1, result);
    memcpy(result + wi, scur, zcur);
    wi += zcur;

    result[wi] = '\0';
    return result;
}

// Locate first occurrence of non escaped character in string

char * wstr_chr(char * str, int character) {
    char escaped = 0;

    for (;*str != '\0'; str++) {
        if (!escaped) {
            if (*str == character) {
                return str;
            }
            if (*str == '\\') {
                escaped = 1;
            }
        } else {
            escaped = 0;
        }
    }

    return NULL;
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

// Free string array
void free_strarray(char ** array) {
    int i;

    if (array) {
        for (i = 0; array[i]; ++i) {
            free(array[i]);
        }

        free(array);
    }
}

/* Returns 0 if str is found */
int wstr_find_in_folder(char *path,const char *str,int strip_new_line){
    DIR *dp;
    FILE *fp = NULL;
    char ** files;
    int i;
    int status = -1;

    dp = opendir(path);
    if (!dp) {
        mdebug1("At wstr_find_in_folder(): Opening directory: '%s': %s", path, strerror(errno));
        return status;
    }

    // Try to open directory, avoid TOCTOU hazard
    if (files = wreaddir(path), !files) {
        if (errno != ENOTDIR) {
            mdebug1("Could not open directory '%s'", path);
        }
        closedir(dp);
        return status;
    }

    /* Read directory */
    for (i = 0; files[i]; ++i) {
        char buffer[OS_SIZE_65536 + 1] = {0};
        char file[PATH_MAX + 1] = {0};

        snprintf(file, PATH_MAX + 1, "%s/%s", path, files[i]);
        if (files[i][0] == '.') {
            continue;
        }

        fp = fopen(file,"r");

        if(!fp){
            closedir(dp);
            dp = NULL;
            continue;
        }

        if( fgets (buffer, OS_SIZE_65536, fp)!=NULL ) {

            if(strip_new_line){

                char *endl = strchr(buffer, '\n');

                if (endl) {
                    *endl = '\0';
                }
            }

            /* Found */
            if(strncmp(str,buffer,OS_SIZE_65536) == 0){
                status = 0;
                goto end;
            }
        }
        fclose(fp);
        fp = NULL;
    }

end:
    free_strarray(files);
    if(fp){
        fclose(fp);
    }

    if(dp){
        closedir(dp);
    }
    return status;
}

/* Returns 0 if str is found */
int wstr_find_line_in_file(char *file,const char *str,int strip_new_line){
    FILE *fp = NULL;
    int i = -1;
    char buffer[OS_SIZE_65536 + 1] = {0};

    fp = fopen(file,"r");

    if(!fp){
        return -1;
    }

    while(fgets (buffer, OS_SIZE_65536, fp) != NULL) {

        char *endl = strchr(buffer, '\n');

        if (endl) {
            i++;
        }

        /* Found */
        if(strip_new_line && endl){
            *endl = '\0';
        }

        if(strncmp(str,buffer,OS_SIZE_65536) == 0){
            fclose(fp);
            return i;
            break;
        }
    }
    fclose(fp);

    return -1;
}

char * wstr_delete_repeated_groups(const char * string){
    char **aux;
    char *result = NULL;
    int i, k;

    aux = OS_StrBreak(MULTIGROUP_SEPARATOR, string, MAX_GROUPS_PER_MULTIGROUP);

    for (i=0; aux[i] != NULL; i++) {
        for (k=0; k < i; k++){
            if (!strcmp(aux[k], aux[i])) {
                break;
            }
        }

        // If no duplicate found, append
        if (k == i) {
            wm_strcat(&result, aux[i], MULTIGROUP_SEPARATOR);
        }
    }

    free_strarray(aux);
    return result;
}


// Concatenate strings with optional separator

int wm_strcat(char **str1, const char *str2, char sep) {
    size_t len1;
    size_t len2;

    if (str2) {
        len2 = strlen(str2);

        if (*str1) {
            len1 = strlen(*str1);
            os_realloc(*str1, len1 + len2 + (sep ? 2 : 1), *str1);

            if (sep)
                memcpy(*str1 + (len1++), &sep, 1);
        } else {
            len1 = 0;
            os_malloc(len2 + 1, *str1);
        }

        memcpy(*str1 + len1, str2, len2 + 1);
        return 0;
    } else
        return -1;
}

int wstr_end(char *str, const char *str_end) {
    size_t str_len = strlen(str);
    size_t str_end_len = strlen(str_end);
    return str_end_len <= str_len && !strcmp(str + str_len - str_end_len, str_end);
}
