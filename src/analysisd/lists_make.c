/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rules.h"
#include "cdb/cdb.h"
#include "cdb/cdb_make.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "lists_make.h"


void Lists_OP_MakeAll(int force)
{
    ListNode *lnode = OS_GetFirstList();
    while (lnode) {
        Lists_OP_MakeCDB(lnode->txt_filename,
                         lnode->cdb_filename,
                         force);
        lnode = lnode->next;
    }
}

void Lists_OP_MakeCDB(const char *txt_filename, const char *cdb_filename, int force)
{
    struct cdb_make cdbm;
    FILE *tmp_fd;
    FILE *txt_fd;
    char *tmp_str;
    char *key, *val;
    char str[OS_MAXSTR + 1];
    char *value_begin;

    str[OS_MAXSTR] = '\0';
    char tmp_filename[OS_MAXSTR];
    tmp_filename[OS_MAXSTR - 2] = '\0';
    snprintf(tmp_filename, OS_MAXSTR - 2, "%s.tmp", txt_filename);

    if (File_DateofChange(txt_filename) > File_DateofChange(cdb_filename) ||
            force) {
        printf(" * File %s needs to be updated\n", cdb_filename);
        if (tmp_fd = fopen(tmp_filename, "w+"), !tmp_fd) {
            merror(FOPEN_ERROR, tmp_filename, errno, strerror(errno));
            return;
        }
        cdb_make_start(&cdbm, tmp_fd);
        if (!(txt_fd = fopen(txt_filename, "r"))) {
            merror(FOPEN_ERROR, txt_filename, errno, strerror(errno));
            return;
        }
        while ((fgets(str, OS_MAXSTR - 1, txt_fd)) != NULL) {
            /* Remove newlines and carriage returns */
            tmp_str = strchr(str, '\r');
            if (tmp_str) {
                *tmp_str = '\0';
            }
            tmp_str = strchr(str, '\n');
            if (tmp_str) {
                *tmp_str = '\0';
            }

            key = NULL;
            /* Check if key is surrounded by double quotes */
            char *key_quotes = NULL;
            if ((key_quotes = strchr(str, '"'))) {

                /* Check if the ':' is after last key quote to make sure this is a key*/
                char *is_key = NULL;
                if((is_key = strchr(str, ':'))){

                    if(is_key > key_quotes) {
                        *key_quotes = '\0';
                        key_quotes++;
                        key = key_quotes;

                        if ((key_quotes = strchr(key_quotes, '"'))) {
                            *key_quotes = '\0';
                            key_quotes++;
                        } else {
                            /* Format error */
                            continue;
                        }
                    } else {
                        key_quotes = NULL;
                    }
                } else {
                    key_quotes = NULL;
                }
            }

            if(key_quotes) {
                value_begin = key_quotes;
            } else {
                value_begin = str;
            }

            if ((val = strchr(value_begin, ':'))) {
                *val = '\0';
                val++;
                value_begin = val;
            } else {
                continue;
            }

            /* Check if value is surrounded by double quotes */
            char *value_quotes = NULL;

            if ((value_quotes = strchr(value_begin, '"'))) {
                *value_quotes = '\0';
                value_quotes++;
                value_begin = value_quotes;

                if ((value_quotes = strchr(value_quotes, '"'))) {
                    *value_quotes = '\0';
                    value_quotes++;
                } else {
                    /* Format error */
                    continue;
                }
            }

            if(value_quotes) {
                val = value_begin;
            }

            if(!key_quotes) {
                key = str;
            }

            cdb_make_add(&cdbm, key, strlen(key), val, strlen(val));
            if (force) {
                print_out("  * adding - key: %s value: %s", key, val);
            }
        }

        fclose(txt_fd);

        cdb_make_finish(&cdbm);
        if (rename(tmp_filename, cdb_filename) == -1) {
            merror(RENAME_ERROR, tmp_filename, cdb_filename, errno, strerror(errno));
            return;
        }
    } else {
        printf(" * File %s does not need to be compiled\n", cdb_filename);
    }
}
