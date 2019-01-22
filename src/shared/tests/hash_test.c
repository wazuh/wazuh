/* Copyright (C) 2015-2019, Wazuh Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include <stdio.h>
#include <string.h>

#include "hash_op.h"


int main(int argc, char **argv)
{
    int i = 0;
    char *tmp = NULL, *buf_dup = NULL;
    char buf[1024] = {'\0'};
    OSHash *mhash;

    mhash = OSHash_Create();
    if (!mhash) return (1);

    while (1) {
        fgets(buf, 1024, stdin);
        tmp = strchr(buf, '\n');
        if (tmp) {
            *tmp = '\0';
        }

        if (strncmp(buf, "get ", 4) == 0) {
            printf("Getting key: '%s'\n", buf + 4);
            buf_dup = (char *)OSHash_Get(mhash, buf + 4);
            if (buf_dup) {
                printf("Found: '%s'\n", buf_dup);
            } else {
                printf("Key '%s' not stored\n", buf + 4);
            }
        } else {
            buf_dup = strdup(buf);
            if (buf_dup) {
                printf("Adding key: '%s'\n", buf);
                i = OSHash_Add(mhash, buf_dup, buf_dup);
                printf("rc = %d\n", i);
                if (!i) free(buf_dup);
                buf_dup = NULL;
            } else {
                printf("Error adding key\n");
                break;
            }
        }
    }
    
    OSHash_Free(mhash);

    return (0);
}
