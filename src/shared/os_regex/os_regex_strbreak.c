/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "os_regex.h"
#include "os_regex_internal.h"


/* Split a string into multiples pieces, divided by a char "match".
 * Returns a NULL terminated array on success or NULL on error.
 */
char **OS_StrBreak(char match, const char *_str, size_t size)
{
    size_t count = 0;
    size_t i = 0;
    char *dup_str;
    char *str;
    char *tmp_str;
    char **ret;
    char *str_ant = NULL;
    char *aux_str = NULL;

    /* We can't do anything if str is null */
    if (_str == NULL) {
        return (NULL);
    }

    dup_str = strdup(_str);

    if(dup_str == NULL) {
        return (NULL);
    }

    ret = (char **)calloc(size + 1, sizeof(char *));

    if (ret == NULL) {
        /* Memory error. Should provide a better way to detect it */
        free(dup_str);
        return (NULL);
    }

    /* Allocate memory to null */
    while (i <= size) {
        ret[i] = NULL;
        i++;
    }

    tmp_str = str = dup_str;
    i = 0;

    while (*str != '\0') {
        i++;

        /* If before match value exists backslash, skip it. */
        if((count < size - 1) && (*str == match) &&
           (str_ant && *str_ant == '\\')) {

            aux_str = calloc(strlen(tmp_str)+1, sizeof(char));
            if (aux_str == NULL) {
                goto error;
            }
            strncpy(aux_str, tmp_str, i-2);
            strcat(aux_str, str);
            strcpy(tmp_str, aux_str);
            str_ant = tmp_str+i-2;
            str = tmp_str+i-1;
            i--;
            free(aux_str);
            continue;
        }

        if ((count < size - 1) && (*str == match)) {

            ret[count] = (char *)calloc(i, sizeof(char));

            if (ret[count] == NULL) {
                goto error;
            }

            /* Copy the string */
            ret[count][i - 1] = '\0';
            strncpy(ret[count], tmp_str, i - 1);

            tmp_str = str+1;
            count++;
            i = 0;
        }

        str_ant = str;
        str++;
    } /* leave from here when *str == \0 */

    /* Just do it if count < size */
    if (count < size) {
        ret[count] = (char *)calloc(i + 1, sizeof(char));

        if (ret[count] == NULL) {
            goto error;
        }

        /* Copy the string */
        ret[count][i] = '\0';
        strncpy(ret[count], tmp_str, i);

        count++;

        /* Make sure it is null terminated */
        ret[count] = NULL;

        free(dup_str);
        return (ret);
    }

    /* We shouldn't get to this point
     * Just let "error" handle that
     */

error:
    i = 0;

    while (i < count) {
        free(ret[i]);
        i++;
    }

    free(ret);
    free(dup_str);
    return (NULL);

}
