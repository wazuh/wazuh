/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "string.h"
#include "../os_regex/os_regex.h"
#include "string_op.h"

#ifdef WIN32
#ifdef EVENTCHANNEL_SUPPORT
#define _WIN32_WINNT 0x0600
#endif
#endif

/* Trim CR and/or LF from the last positions of a string */
void os_trimcrlf(char *str)
{
    if (str == NULL) {
        return;
    }

    if (*str == '\0') {
        return;
    }

    size_t len = strlen(str);
    len--;

    while (str[len] == '\n' || str[len] == '\r') {
        str[len] = '\0';

        if (len == 0) {
            break;
        }

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
    char shell_escapes[22] = { '\\', '"', '\'', '\t', ';', '`', '>', '<', '|', '#',
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
        if (strchr(shell_escapes, *iterator)) {
            if ((*iterator == '\\') && *(iterator+1) && strchr(shell_escapes, *(iterator+1))) {
                // avoid scape because it's already scaped
                iterator++;
            }
            length++;
        }
        length++;
    }
    /* Allocate memory */
    if ((escaped_string = (char *) calloc(1, length + 1 )) == NULL) {
        return NULL;
    }

    /* Escape the escapable characters */
    iterator = src;
    for (i = 0; *iterator; iterator++) {
        if (strchr(shell_escapes, *iterator)) {
            if ((*iterator == '\\') && *(iterator+1) && strchr(shell_escapes, *(iterator+1))) {
                // avoid scape because it's already scaped
                escaped_string[i] = *iterator;
                i++;
                iterator++;
            } else {
                escaped_string[i] = '\\';
                i++;
            }
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

    if(string != NULL) {
        string = &string[strspn(string, " ")];
        for (c = string + strcspn(string, " "); *(d = c + strspn(c, " ")); c = d + strcspn(d, " "));
        *c = '\0';
    }
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
        os_malloc(length + 1, current);
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
        const char *jsonErrPtr;
        cJSON * value_json = NULL;

        if (*value == '[' &&
           (value_json = cJSON_ParseWithOpts(value, &jsonErrPtr, 0), value_json) &&
           (*jsonErrPtr == '\0')) {
            cJSON_AddItemToObject(root, key, value_json);
        } else {
            if (value_json) {
                cJSON_Delete(value_json);
            }
            cJSON_AddStringToObject(root, key, value);
        }
    }
}

void csv_list_to_json_str_array(char * const csv_list, char **buffer)
{
    cJSON *array = cJSON_CreateArray();
    char *remaining_str = NULL;
    char *element = strtok_r(csv_list, ",", &remaining_str);

    while (element) {
        cJSON *obj = cJSON_CreateString(element);
        cJSON_AddItemToArray(array, obj);
        element = strtok_r(NULL, ",", &remaining_str);
    }
    *buffer = cJSON_Print(array);
    cJSON_Delete(array);
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

// Locate first occurrence of non '\\' escaped character in string

char * wstr_chr(const char * str, char character) {

    return wstr_chr_escape(str, character, '\\');
}

// Locate first occurrence of non escaped character in string

char * wstr_chr_escape(const char * str, char character, char escape) {
    bool escaped = false;

    for (;*str != '\0'; str++) {
        if (!escaped) {
            if (*str == character) {
                return (char *)str;
            }
            if (*str == escape) {
                escaped = true;
            }
        } else {
            escaped = false;
        }
    }
    return NULL;
}

// Escape a specific character from a character string

ssize_t wstr_escape(char *dststr, size_t dst_size, const char *str, char escape, char match) {

    if (str == NULL || dststr == NULL) {
        return OS_INVALID;
    }

    size_t i = 0;   // Read position
    size_t j = 0;   // Write position
    size_t z;       // Span length

    char charset[3] = {escape, match, '\0'};

    do {
        z = strcspn(str + i, charset);

        if (str[i + z] == '\0' || (j + z) >= (dst_size - 2)) {
            z = (z + j <= dst_size - 1) ? z : (dst_size - j - 1);
            // End of str
            strncpy(dststr + j, str + i, z);
        } else {
            // Reserved character
            strncpy(dststr + j, str + i, z);
            dststr[j + z] = escape;
            if (str[i + z] == escape) {
                dststr[j + z + 1] = escape;
            } else {
                dststr[j + z + 1] = match;
            }
            z++;
            j++;
        }

        j += z;
        i += z;
    } while (str[i] != '\0' && j < (dst_size - 2));

    dststr[j] = '\0';
    return j;
}

// Unescape a specific character from a character string

ssize_t wstr_unescape(char *dststr, size_t dst_size, const char *str, char escape) {

    if (str == NULL || dststr == NULL) {
        return OS_INVALID;
    }

    size_t i = 0;   // Read position
    size_t j = 0;   // Write position
    size_t z;       // Span length

    char charset[2] = {escape, '\0'};

    do {
        z = strcspn(str + i, charset);
        z = (z + j <= dst_size - 1) ? z : (dst_size - j - 1);

        strncpy(dststr + j, str + i, z);
        j += z;
        i += z;

        if (str[i] != '\0' && j < (dst_size - 1)) {

            if (str[i + 1] == escape) {
                dststr[j++] = str[i++];
            }
            else if (str[i + 1] == '\0') {
                dststr[j++] = str[i];
            }
            i++;
        }

    } while (str[i] != '\0' && j < (dst_size - 1));

    dststr[j] = '\0';
    return j;
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

// Get the size of a string array
size_t strarray_size(char ** array) {
    size_t size = 0;

    if (array) {
        while (array[size]) {
            size++;
        }
    }
    return size;
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

void wstr_split(char *str, char *delim, char *replace_delim, int occurrences, char ***splitted_str) {
    char *new_delim = replace_delim ? replace_delim : delim;
    size_t new_delim_size = strlen(replace_delim ? replace_delim : delim);
    int count = 0;
    int splitted_count;
    char *str_cpy, *str_cpy_ref;
    char *str_it;
    char **acc_strs;
    char *saveptr;

    if (occurrences < 1) {
        return;
    }

    os_strdup(str, str_cpy);
    str_cpy_ref = str_cpy;
    str_it = strtok_r(str_cpy, delim, &saveptr);

    os_calloc(occurrences, sizeof(char *), acc_strs);

    for (splitted_count = 0; *splitted_str && (*splitted_str)[splitted_count]; splitted_count++);

    for (; str_it && *str_it; count++) {
        os_strdup(str_it, acc_strs[count]);

        if (count == occurrences - 1) {
            // Add a new term
            size_t term_size;
            char *new_term_it;

            for (count = term_size = 0; count < occurrences; count++) {
                term_size += strlen(acc_strs[count]);
            }

            term_size += (occurrences - 1) * new_delim_size + 1;

            os_realloc(*splitted_str, (splitted_count + 2) * sizeof(char *), *splitted_str);
            os_calloc(term_size, sizeof(char), (*splitted_str)[splitted_count]);
            (*splitted_str)[splitted_count + 1] = NULL;

            for (count = 0, new_term_it = (*splitted_str)[splitted_count]; count < occurrences; count++) {
                if (count) {
                    strncpy(new_term_it, new_delim, term_size);
                    term_size -= new_delim_size;
                    new_term_it += new_delim_size;
                }
                strncpy(new_term_it, acc_strs[count], term_size);
                term_size -= strlen(acc_strs[count]);
                new_term_it += strlen(acc_strs[count]);
                os_free(acc_strs[count]);
            }

            splitted_count++;
            count = -1;
        }
        str_it = strtok_r(NULL, delim, &saveptr);
    }

    // Remove residual terms (they are discarded)
    for (count = 0; acc_strs[count]; count++) {
        free(acc_strs[count]);
    }
    free(acc_strs);
    free(str_cpy_ref);
}

/* Check if the specified string is already in the array */
int w_is_str_in_array(char *const *ar, const char *str)
{
    while (*ar) {
        if (strcmp(*ar, str) == 0) {
            return (1);
        }
        ar++;
    }
    return (0);
}

// Remove zeros from the end of the decimal number
void w_remove_zero_dec(char *str_number) {
    char *base;
    char *number_end;

    if (base = strchr(str_number, '.'), base) {
        for (number_end = base; *number_end; number_end++);
        for (--number_end; base != number_end && *number_end == '0'; number_end--) {
            *number_end = '\0';
        }
    }
}

/* Similar to strtok_r but checks for full delim appearances */
char *w_strtok_r_str_delim(const char *delim, char **remaining_str)
{
    if (!*remaining_str) {
        return NULL;
    }

    if (!delim || *delim == '\0') {
        char *str = *remaining_str;
        *remaining_str = NULL;
        return str;
    }

    char *delim_found = NULL;
    size_t delim_len = strlen(delim);

    while ((delim_found = strstr(*remaining_str, delim))) {
        if (*remaining_str == delim_found) {
            *remaining_str += delim_len;
            continue;
        }
        break;
    }

    if (**remaining_str == '\0') {
        return NULL;
    }

    char *token = *remaining_str;

    if((delim_found = strstr(*remaining_str, delim))) {
        *delim_found = '\0';
        *remaining_str = delim_found + delim_len;
    } else {
        *remaining_str = NULL;
    }

    return token;
}


// Returns the characters number of the string source if, only if, source is included completely in str, 0 in other case.
int w_compare_str(const char * source, const char * str) {
    int matching = 0;
    size_t source_lenght;

    if (!(source && str)) {
        return -1;
    }

    source_lenght = strlen(source);
    if (source_lenght > strlen(str)) {
        return -2;
    }

    // Match if result is 0
    matching = strncmp(source, str, source_lenght);

    return matching == 0 ? source_lenght : 0;
}

const char * find_string_in_array(char * const string_array[], size_t array_len, const char * const str, const size_t str_len)
{
    if (!string_array || !str){
        return NULL;
    }

    size_t i;
    for (i = 0; i < array_len; ++i) {
        if (strncmp(str, string_array[i], str_len) == 0) {
            return string_array[i];
        }
    }

    return NULL;
}

// Parse boolean string

int w_parse_bool(const char * string) {
    return (strcmp(string, "yes") == 0) ? 1 : (strcmp(string, "no") == 0) ? 0 : -1;
}

// Parse positive time string into seconds

long w_parse_time(const char * string) {
    char * end;
    long seconds = strtol(string, &end, 10);

    if (seconds < 0 || (seconds == LONG_MAX && errno == ERANGE)) {
        return -1;
    }

    switch (*end) {
    case '\0':
        break;
    case 'w':
        seconds *= W_WEEK_SECONDS;
        break;
    case 'd':
        seconds *= W_DAY_SECONDS;
        break;
    case 'h':
        seconds *= W_HOUR_SECONDS;
        break;
    case 'm':
        seconds *= W_MINUTE_SECONDS;
        break;
    case 's':
        break;
    default:
        return -1;
    }

    return seconds >= 0 ? seconds : -1;
}

// Parse positive size string into bytes

ssize_t w_parse_size(const char * string) {
    char c;
    ssize_t size;

    switch (sscanf(string, "%zd%c", &size, &c)) {
    case 1:
        break;

    case 2:
        switch (c) {
        case 'G':
        case 'g':
            size *= 1073741824;
            break;
        case 'M':
        case 'm':
            size *= 1048576;
            break;
        case 'K':
        case 'k':
            size *= 1024;
            break;
        case 'B':
        case 'b':
            break;
        default:
            return -1;
        }

        break;

    default:
        return -1;
    }

    return size >= 0 ? size : -1;
}

// Get time unit from seconds

char*  w_seconds_to_time_unit(long seconds, bool long_format) {

    if (seconds < 0) {
        return "invalid";
    }
    else if (seconds >= W_WEEK_SECONDS) {
        return long_format ? W_WEEKS_L : W_WEEKS_S ;
    }
    else if (seconds >= W_DAY_SECONDS) {
        return long_format ? W_DAYS_L : W_DAYS_S ;
    }
    else if (seconds >= W_HOUR_SECONDS) {
        return long_format ? W_HOURS_L : W_HOURS_S ;
    }
    else if (seconds >= W_MINUTE_SECONDS) {
       return long_format ? W_MINUTES_L : W_MINUTES_S ;
    }
    else {
       return long_format ? W_SECONDS_L : W_SECONDS_S ;
    }
}

// Get time value from seconds

long w_seconds_to_time_value(long seconds) {

    if(seconds < 0) {
        return -1;
    }
    else if (seconds >= W_WEEK_SECONDS) {
        return seconds/W_WEEK_SECONDS;
    }
    else if (seconds >= W_DAY_SECONDS) {
        return seconds/W_DAY_SECONDS;
    }
    else if (seconds >= W_HOUR_SECONDS) {
        return seconds/W_HOUR_SECONDS;
    }
    else if (seconds >= W_MINUTE_SECONDS) {
        return seconds/W_MINUTE_SECONDS;
    }
    else {
        return seconds;
    }
}

char* decode_hex_buffer_2_ascii_buffer(const char * const encoded_buffer, const size_t buffer_size)
{
    if (!encoded_buffer) {
        return NULL;
    }

    /* each ASCII character has 2 digits in its HEX form, hence its length must be even */
    if (buffer_size % 2 != 0) {
        return NULL;
    }

    const size_t decoded_len = buffer_size / 2;
    char *decoded_buffer;
    os_calloc(decoded_len + 1, sizeof(char), decoded_buffer);

    size_t i;
    for(i = 0; i < decoded_len; ++i) {
        if (1 != sscanf(encoded_buffer + 2 * i, "%2hhx", decoded_buffer + i)) {
            os_free(decoded_buffer);
            return NULL;
        }
    }

    return decoded_buffer;
}

// Length of the initial segment of s which consists entirely of non-escaped bytes different from reject

size_t strcspn_escaped(const char * s, char reject) {
    char charset[3] = { '\\', reject };

    size_t len = strlen(s);
    size_t spn_len = 0;

    do {
        spn_len += strcspn(s + spn_len, charset);

        if (s[spn_len] == '\\') {
            spn_len += 2;
        } else {
            return spn_len;
        }
    } while (spn_len < len);

    return len;
}

// Escape JSON reserved characters

char * wstr_escape_json(const char * string) {
    const char escape_map[] = {
        ['\b'] = 'b',
        ['\t'] = 't',
        ['\n'] = 'n',
        ['\f'] = 'f',
        ['\r'] = 'r',
        ['\"'] = '\"',
        ['\\'] = '\\'
    };

    size_t i = 0;   // Read position
    size_t j = 0;   // Write position
    size_t z;       // Span length

    char * output;
    os_malloc(1, output);

    do {
        z = strcspn(string + i, "\b\t\n\f\r\"\\");

        if (string[i + z] == '\0') {
            // End of string
            os_realloc(output, j + z + 1, output);
            strncpy(output + j, string + i, z);
        } else {
            // Reserved character
            os_realloc(output, j + z + 3, output);
            strncpy(output + j, string + i, z);
            output[j + z] = '\\';
            output[j + z + 1] = escape_map[(int)string[i + z]];
            z++;
            j++;
        }

        j += z;
        i += z;
    } while (string[i] != '\0');

    output[j] = '\0';
    return output;
}

// Unescape JSON reserved characters

char * wstr_unescape_json(const char * string) {
    const char UNESCAPE_MAP[] = {
        ['b'] = '\b',
        ['t'] = '\t',
        ['n'] = '\n',
        ['f'] = '\f',
        ['r'] = '\r',
        ['\"'] = '\"',
        ['\\'] = '\\'
    };

    size_t i = 0;   // Read position
    size_t j = 0;   // Write position
    size_t z;       // Span length

    char * output;
    os_malloc(1, output);

    do {
        z = strcspn(string + i, "\\");

        // Extend output and copy
        os_realloc(output, j + z + 3, output);
        strncpy(output + j, string + i, z);

        i += z;
        j += z;

        if (string[i] != '\0') {
            // Peek byte following '\'
            switch (string[++i]) {
            case '\0':
                // End of string
                output[j++] = '\\';
                break;

            case 'b':
            case 't':
            case 'n':
            case 'f':
            case 'r':
            case '\"':
            case '\\':
                // Escaped character
                output[j++] = UNESCAPE_MAP[(int)string[i++]];
                break;

            default:
                // Bad escape
                output[j++] = '\\';
                output[j++] = string[i++];
            }
        }
    } while (string[i] != '\0');

    output[j] = '\0';
    return output;
}

// Lowercase a string

char * w_tolower_str(const char *string) {
    char *tolower_str;
    int count;

    if (!string) {
        return NULL;
    }

    os_malloc(1, tolower_str);

    for(count = 0; string[count]; count++) {
        os_realloc(tolower_str, count + 2, tolower_str);
        tolower_str[count] = tolower(string[count]);
    }

    tolower_str[count] = '\0';

    return tolower_str;
}

// Verify the string is not truncated after executing snprintf

int os_snprintf(char *str, size_t size, const char *format, ...) {
    size_t ret;
    va_list args;

    va_start(args, format);
    ret = vsnprintf(str, size, format, args);
    if (ret >= size) {
        mwarn("String may be truncated because it is too long.");
    }
    va_end(args);

    return ret;
}

// Remove a substring from a string

char * w_remove_substr(char *str, const char *sub) {
    char *p, *q, *r;

    if (!str || !sub) {
        return NULL;
    }

    if ((q = r = strstr(str, sub)) != NULL) {
        size_t len = strlen(sub);
        while ((r = strstr(p = r + len, sub)) != NULL) {
            while (p < r)
                *q++ = *p++;
        }
        while ((*q++ = *p++) != '\0')
            continue;
    }
    return str;
}

char * w_strndup(const char * str, size_t n) {

    char * str_cpy = NULL;
    size_t str_len;

    if (str == NULL) {
        return str_cpy;
    }

    if (str_len = strlen(str), str_len > n) {
        str_len = n;
    }

    os_malloc(str_len + 1, str_cpy);
    if (str_len > 0) {
        memcpy(str_cpy, str, str_len);
    }

    str_cpy[str_len] = '\0';

    return str_cpy;
}

char ** w_string_split(const char *string_to_split, const char *delim, int max_array_size) {
    char **paths = NULL;
    char *state;
    char *token;
    int i = 0;
    char *aux;

    os_calloc(1, sizeof(char *), paths);

    if (!string_to_split || !delim) {
        return paths;
    }
    os_strdup(string_to_split, aux);

    for(token = strtok_r(aux, delim, &state); token; token = strtok_r(NULL, delim, &state)){
        os_realloc(paths, (i + 2) * sizeof(char *), paths);
        os_strdup(token, paths[i]);
        paths[i + 1] = NULL;
        i++;
        if (max_array_size && i >= max_array_size) break;
    }
    os_free(aux);

    return paths;
}

// Append two strings

char* w_strcat(char *a, const char *b, size_t n) {
    if (a == NULL) {
        return w_strndup(b, n);
    }

    size_t a_len = strlen(a);
    size_t output_len = a_len + n;

    os_realloc(a, output_len + 1, a);

    memcpy(a + a_len, b, n);
    a[output_len] = '\0';

    return a;
}

// Append a string into the n-th position of a string array

char** w_strarray_append(char **array, char *string, int n) {
    os_realloc(array, sizeof(char *) * (n + 2), array);
    array[n] = string;
    array[n + 1] = NULL;

    return array;
}

// Tokenize string separated by spaces, respecting double-quotes

char** w_strtok(const char *string) {
    bool quoting = false;
    int output_n = 0;
    char *accum = NULL;
    char **output;

    os_calloc(1, sizeof(char*), output);

    const char *i;
    const char *j;

    for (i = string; (j = strpbrk(i, " \"\\")) != NULL; i = j + 1) {
        switch (*j) {
        case ' ':
            if (quoting) {
                accum = w_strcat(accum, i, j - i + 1);
            } else {
                if (j > i) {
                    accum = w_strcat(accum, i, j - i);
                }

                if (accum != NULL) {
                    output = w_strarray_append(output, accum, output_n++);
                    accum = NULL;
                }
            }

            break;

        case '\"':
            if (j > i || quoting) {
                accum = w_strcat(accum, i, j - i);
            }

            quoting = !quoting;
            break;

        case '\\':
            if (j > i) {
                accum = w_strcat(accum, i, j - i);
            }

            if (j[1] != '\0') {
                accum = w_strcat(accum, ++j, 1);
            }
        }
    }

    if (*i != '\0') {
        accum = w_strcat(accum, i, strlen(i));
    }

    if (accum != NULL) {
        output = w_strarray_append(output, accum, output_n);
    }

    return output;
}

char* w_strcat_list(char ** list, char sep_char) {

    char * concatenation = NULL;
    char sep[] = {sep_char, '\0'};

    if (list != NULL) {
        char ** FIRST_ELEMENT = list;
        while (*list != NULL) {
            if (list != FIRST_ELEMENT) {
                concatenation = w_strcat(concatenation, sep, 1);
            }
            concatenation = w_strcat(concatenation, *list, w_strlen(*list));
            list++;
        }
    }

    return concatenation;
}

int print_hex_string(const char *src_buf, unsigned int src_size, char *dst_buf, unsigned int dst_size) {
    if (src_buf && dst_buf) {
        unsigned int i = 0;
        for (; (i < (dst_size-1)/2) && (i < src_size); ++i) {
            sprintf(dst_buf+2*i, "%.2x", src_buf[i]);
        }
        dst_buf[i * 2] = '\0';
        return OS_SUCCESS;
    }
    return OS_INVALID;
}
