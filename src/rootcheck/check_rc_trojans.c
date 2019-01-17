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


/* Read the file pointer specified (rootkit_trojans)
 * and check if any trojan entry is in the configured files
 */
void check_rc_trojans(const char *basedir, FILE *fp)
{
    int i = 0, _errors = 0, _total = 0;
    char buf[OS_SIZE_1024 + 1];
    char file_path[OS_SIZE_1024 + 1];
    char *file;
    char *string_to_look;

#ifndef WIN32
    const char *(all_paths[]) = {"bin", "sbin", "usr/bin", "usr/sbin", NULL};
#else
    const char *(all_paths[]) = {"C:\\Windows\\", "D:\\Windows\\", NULL};
#endif

    mtdebug1(ARGV0, "Starting on check_rc_trojans");

    while (fgets(buf, OS_SIZE_1024, fp) != NULL) {
        char *nbuf;
        char *message = NULL;

        i = 0;
        /* Remove end of line */
        nbuf = strchr(buf, '\n');
        if (nbuf) {
            *nbuf = '\0';
        }

        nbuf = normalize_string(buf);

        if (*nbuf == '\0' || *nbuf == '#') {
            continue;
        }

        /* File now may be valid */
        file = nbuf;

        string_to_look = strchr(file, '!');
        if (!string_to_look) {
            continue;
        }

        *string_to_look = '\0';
        string_to_look++;

        message = strchr(string_to_look, '!');
        if (!message) {
            continue;
        }
        *message = '\0';
        message++;

        string_to_look = normalize_string(string_to_look);
        file = normalize_string(file);
        message = normalize_string(message);

        if (*file == '\0' || *string_to_look == '\0') {
            continue;
        }

        _total++;

        /* Try with all possible paths */
        while (all_paths[i] != NULL) {
            if (*file != '/') {
                snprintf(file_path, OS_SIZE_1024, "%s/%s/%s", basedir,
                         all_paths[i],
                         file);
            } else {
                strncpy(file_path, file, OS_SIZE_1024);
                file_path[OS_SIZE_1024 - 1] = '\0';
            }

            /* Check if entry is found */
            if (is_file(file_path) && os_string(file_path, string_to_look)) {
                char op_msg[OS_SIZE_1024 + 1];
                _errors = 1;

                snprintf(op_msg, OS_SIZE_1024, "Trojaned version of file "
                         "'%s' detected. Signature used: '%s' (%s).",
                         file_path,
                         string_to_look,
                         *message == '\0' ?
                         "Generic" : message);

                notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            }

            if (*file == '/') {
                break;
            }
            i++;
        }
        continue;
    }

    if (_errors == 0) {
        char op_msg[OS_SIZE_1024 + 1];
        snprintf(op_msg, OS_SIZE_1024, "No binaries with any trojan detected. "
                 "Analyzed %d files.", _total);
        notify_rk(ALERT_OK, op_msg);
    }
}
