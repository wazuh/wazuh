/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rootcheck.h"


/* Read the file pointer specified (rootkit_files)
 * and check if the configured file is there
 */
void check_rc_files(const char *basedir, FILE *fp)
{
    char buf[OS_SIZE_1024 + 1];
    char file_path[OS_SIZE_1024 + 1];

    char *file;
    char *name;
    char *link;

    int _errors = 0;
    int _total = 0;

    mtdebug1(ARGV0, "Starting on check_rc_files");

    while (fgets(buf, OS_SIZE_1024, fp) != NULL) {
        char *nbuf;

        /* Remove newline at the end */
        nbuf = strchr(buf, '\n');
        if (nbuf) {
            *nbuf = '\0';
        }

        /* Assign buf to be used */
        nbuf = buf;

        /* Skip comments and blank lines */
        while (*nbuf != '\0') {
            if (*nbuf == ' ' || *nbuf == '\t') {
                nbuf++;
                continue;
            } else if (*nbuf == '#') {
                goto newline;
            } else {
                break;
            }
        }

        if (*nbuf == '\0') {
            goto newline;
        }

        /* File now may be valid */
        file = nbuf;
        name = nbuf;

        /* Get the file and the rootkit name */
        while (*nbuf != '\0') {
            if (*nbuf == ' ' || *nbuf == '\t') {
                /* Set the limit for the file */
                *nbuf = '\0';
                nbuf++;
                break;
            } else {
                nbuf++;
            }
        }

        if (*nbuf == '\0') {
            goto newline;
        }

        /* Some ugly code to remove spaces and \t */
        while (*nbuf != '\0') {
            if (*nbuf == '!') {
                nbuf++;
                if (*nbuf == ' ' || *nbuf == '\t') {
                    nbuf++;
                    name = nbuf;

                    break;
                }
            } else if (*nbuf == ' ' || *nbuf == '\t') {
                nbuf++;
                continue;
            } else {
                goto newline;
            }
        }

        /* Get the link (if present) */
        link = strchr(nbuf, ':');
        if (link) {
            *link = '\0';

            link++;
            if (*link == ':') {
                link++;
            }
        }

        /* Clean any space or tab at the end */
        nbuf = strchr(nbuf, ' ');
        if (nbuf) {
            *nbuf = '\0';

            nbuf = strchr(nbuf, '\t');
            if (nbuf) {
                *nbuf = '\0';
            }
        }

        _total++;

        /* Check if it is a file to search everywhere */
        if (*file == '*') {
            /* Maximum number of global files reached */
            if (rk_sys_count >= MAX_RK_SYS) {
                mterror(ARGV0, MAX_RK_MSG, MAX_RK_SYS);
            }

            else {
                /* Remove all slashes from the file */
                file++;
                if (*file == '/') {
                    file++;
                }

                rk_sys_file[rk_sys_count] = strdup(file);
                rk_sys_name[rk_sys_count] = strdup(name);

                if (!rk_sys_name[rk_sys_count] ||
                        !rk_sys_file[rk_sys_count] ) {
                    mterror(ARGV0, MEM_ERROR, errno, strerror(errno));

                    if (rk_sys_file[rk_sys_count]) {
                        free(rk_sys_file[rk_sys_count]);
                    }
                    if (rk_sys_name[rk_sys_count]) {
                        free(rk_sys_name[rk_sys_count]);
                    }

                    rk_sys_file[rk_sys_count] = NULL;
                    rk_sys_name[rk_sys_count] = NULL;
                }

                rk_sys_count++;

                /* Always assign the last as NULL */
                rk_sys_file[rk_sys_count] = NULL;
                rk_sys_name[rk_sys_count] = NULL;
            }
            continue;
        }

        snprintf(file_path, OS_SIZE_1024, "%s/%s", basedir, file);

        if (is_file(file_path)) {
            char op_msg[OS_SIZE_1024 + 1];

            _errors = 1;
            snprintf(op_msg, OS_SIZE_1024, "Rootkit '%s' detected "
                     "by the presence of file '%s'.", name, file_path);

            notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
        }

newline:
        continue;
    }

    if (_errors == 0) {
        char op_msg[OS_SIZE_1024 + 1];
        snprintf(op_msg, OS_SIZE_1024, "No presence of public rootkits detected."
                 " Analyzed %d files.", _total);
        notify_rk(ALERT_OK, op_msg);
    }
}
