/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "manage_agents.h"
#include "os_crypto/md5/md5_op.h"
#include "external/cJSON/cJSON.h"
#include <stdlib.h>
#include "config/authd-config.h"

#ifdef WIN32
  #include <wincrypt.h>
#endif

#define DEFAULT_ID   132512

/* Prototypes */
static char *trimwhitespace(char *str);


static char *trimwhitespace(char *str)
{
    char *end;

    /* Null pointer? */
    if (!str)
        return NULL;

    /* Trim leading space */
    while (isspace(*str)) {
        str++;
    }

    if (*str == 0) { /* All spaces? */
        return str;
    }

    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) {
        end--;
    }

    /* Write new null terminator */
    *(end + 1) = 0;

    return str;
}

/* Import a key */
int k_import(const char *cmdimport)
{
    FILE *fp;
    const char *user_input;
    char auth_file[] = KEYS_FILE;
    char *keys_file = basename_ex(auth_file);
    char *b64_dec;

    char *name;
    char *ip;
    char *tmp_key;

    char line_read[FILE_SIZE + 1];
    char tmp_path[PATH_MAX];

    snprintf(tmp_path, sizeof(tmp_path), "%s/%sXXXXXX", TMP_DIR, keys_file);

    /* Parse user argument */
    if (cmdimport) {
        user_input = cmdimport;
    } else {
        printf(IMPORT_KEY);

        user_input = getenv("OSSEC_AGENT_KEY");
        if (user_input == NULL) {
            user_input = read_from_user();
        }
    }

    /* Quit */
    if (strcmp(user_input, QUIT) == 0) {
        return (0);
    }

    b64_dec = decode_base64(user_input);
    if (b64_dec == NULL) {
        printf(NO_KEY);
        printf(PRESS_ENTER);
        read_from_user();
        return (0);
    }

    memset(line_read, '\0', FILE_SIZE + 1);
    strncpy(line_read, b64_dec, FILE_SIZE);

    name = strchr(b64_dec, ' ');
    if (name && strlen(line_read) < FILE_SIZE) {
        *name = '\0';
        name++;
        ip = strchr(name, ' ');
        if (ip) {
            *ip = '\0';
            ip++;

            tmp_key = strchr(ip, ' ');
            if (!tmp_key) {
                printf(NO_KEY);
                free(b64_dec);
                return (0);
            }
            *tmp_key = '\0';

            printf("\n");
            printf(AGENT_INFO, b64_dec, name, ip);

            while (1) {
                printf(ADD_CONFIRM);
                fflush(stdout);

                user_input = getenv("OSSEC_ACTION_CONFIRMED");
                if (user_input == NULL) {
                    user_input = read_from_user();
                }

                if (user_input[0] == 'y' || user_input[0] == 'Y') {
                    if (mkstemp_ex(tmp_path)) {
                        merror_exit(MKSTEMP_ERROR, tmp_path, errno, strerror(errno));
                    }

#ifndef WIN32
                    if (chmod(tmp_path, 0640) == -1) {
                        if (unlink(tmp_path)) {
                            minfo(DELETE_ERROR, tmp_path, errno, strerror(errno));
                        }

                        merror_exit(CHMOD_ERROR, tmp_path, errno, strerror(errno));
                    }
#endif

                    fp = wfopen(tmp_path, "w");
                    if (!fp) {
                        if (unlink(tmp_path)) {
                            minfo(DELETE_ERROR, tmp_path, errno, strerror(errno));
                        }

                        merror_exit(FOPEN_ERROR, tmp_path, errno, strerror(errno));
                    }
                    fprintf(fp, "%s\n", line_read);
                    fclose(fp);

                    if (rename_ex(tmp_path, KEYS_FILE)) {
                        if (unlink(tmp_path)) {
                            minfo(DELETE_ERROR, tmp_path, errno, strerror(errno));
                        }

                        merror_exit(RENAME_ERROR, tmp_path, KEYS_FILE, errno, strerror(errno));
                    }

                    /* Remove sender counter */
                    OS_RemoveCounter("sender");

                    printf(ADDED);
                    free(b64_dec);
                    return (1);
                } else { /* if(user_input[0] == 'n' || user_input[0] == 'N') */
                    printf("%s", ADD_NOT);

                    free(b64_dec);
                    return (0);
                }
            }
        }
    }

    printf(NO_KEY);
    printf(PRESS_ENTER);
    read_from_user();

    free(b64_dec);
    return (0);
}
