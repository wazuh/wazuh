/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
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
char **OS_StrBreak(char match, const char *str, size_t size)
{
    size_t count = 0;
    size_t i = 0;
    const char *tmp_str = str;
    char **ret;

    /* We can't do anything if str is null */
    if (str == NULL) {
        return (NULL);
    }

    ret = (char **)calloc(size + 1, sizeof(char *));

    if (ret == NULL) {
        /* Memory error. Should provide a better way to detect it */
        return (NULL);
    }

    /* Allocate memory to null */
    while (i <= size) {
        ret[i] = NULL;
        i++;
    }
    i = 0;

    while (*str != '\0') {
        i++;
        if ((count < size - 1) && (*str == match)) {
            ret[count] = (char *)calloc(i, sizeof(char));

            if (ret[count] == NULL) {
                goto error;
            }

            /* Copy the string */
            ret[count][i - 1] = '\0';
            strncpy(ret[count], tmp_str, i - 1);

            tmp_str = ++str;
            count++;
            i = 0;

            continue;
        }
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
    return (NULL);

}

