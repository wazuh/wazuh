/* Copyright (C) 2015-2019, Wazuh Inc.
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
        char *string_end =  NULL;
        if (*value == '[' &&
           (string_end = memchr(value, '\0', OS_MAXSTR)) &&
           (string_end != NULL) &&
           (']' == *(string_end - 1)))
        {
            const char *jsonErrPtr;
            cJSON_AddItemToObject(root, key, cJSON_ParseWithOpts(value, &jsonErrPtr, 0));
        } else {
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

        if (!fp) {
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
                    strncpy(new_term_it, new_delim, new_delim_size);
                    new_term_it += new_delim_size;
                }
                strncpy(new_term_it, acc_strs[count], strlen(acc_strs[count]));
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
    case 'd':
        seconds *= 86400;
        break;
    case 'h':
        seconds *= 3600;
        break;
    case 'm':
        seconds *= 60;
        break;
    case 's':
        break;
    case 'w':
        seconds *= 604800;
        break;
    default:
        return -1;
    }

    return seconds >= 0 ? seconds : -1;
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
    os_calloc(decoded_len, sizeof(char), decoded_buffer);

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
