/* Copyright (C) 2015-2020, Wazuh Inc.
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
    char auth_file[] = AUTH_FILE;
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

                    fp = fopen(tmp_path, "w");
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

/* Extract base64 for a specific agent */
int k_extract(const char *cmdextract, int json_output)
{
    FILE *fp;
    char *user_input;
    char *b64_enc;
    char line_read[FILE_SIZE + 1];
    char n_id[USER_SIZE + 1];
    cJSON *json_root = NULL;

    if (json_output)
        json_root = cJSON_CreateObject();

    if (cmdextract) {
        os_strdup(cmdextract, user_input);
        FormatID(user_input);

        if (!IDExist(user_input, 1)) {
            if (json_output) {
                char buffer[1024];
                snprintf(buffer, 1023, "Invalid ID '%s' given. ID is not present", user_input);
                cJSON_AddNumberToObject(json_root, "error", 70);
                cJSON_AddStringToObject(json_root, "message", buffer);
                printf("%s", cJSON_PrintUnformatted(json_root));
            } else
                printf(NO_ID, user_input);

            exit(1);
        }
    } else {
        if (!print_agents(0, 0, 0, 0, 0)) {
            printf(NO_AGENT);
            printf(PRESS_ENTER);
            read_from_user();
            return (0);
        }

        while (1) {
            printf(EXTRACT_KEY);
            fflush(stdout);
            user_input = read_from_user();

            /* quit */
            if (strcmp(user_input, QUIT) == 0) {
                return (0);
            }

            FormatID(user_input);

            if (IDExist(user_input, 1)) {
                break;
            } else
                printf(NO_ID, user_input);
        }
    }

    /* Try to open the auth file */
    fp = fopen(AUTH_FILE, "r");
    if (!fp) {
        if (json_output) {
            char buffer[1024];
            snprintf(buffer, 1023, "Could not open file '%s' due to [(%d)-(%s)]", AUTH_FILE, errno, strerror(errno));
            cJSON_AddNumberToObject(json_root, "error", 71);
            cJSON_AddStringToObject(json_root, "message", buffer);
            printf("%s", cJSON_PrintUnformatted(json_root));
            exit(1);
        } else
            merror_exit(FOPEN_ERROR, AUTH_FILE, errno, strerror(errno));
    }

    if (fsetpos(fp, &fp_pos)) {
        if (json_output) {
            cJSON_AddNumberToObject(json_root, "error", 71);
            cJSON_AddStringToObject(json_root, "message", "Can not set fileposition");
            printf("%s", cJSON_PrintUnformatted(json_root));
        } else
            merror("Can not set fileposition.");

        exit(1);
    }

    memset(n_id, '\0', USER_SIZE + 1);
    strncpy(n_id, user_input, USER_SIZE - 1);

    if (fgets(line_read, FILE_SIZE, fp) == NULL) {
        if (json_output) {
            cJSON_AddNumberToObject(json_root, "error", 73);
            cJSON_AddStringToObject(json_root, "message", "Unable to handle keys file");
            printf("%s", cJSON_PrintUnformatted(json_root));
        } else
            printf(ERROR_KEYS);

        fclose(fp);
        exit(1);
    }
    chomp(line_read);

    b64_enc = encode_base64(strlen(line_read), line_read);
    if (b64_enc == NULL) {
        if (json_output) {
            cJSON_AddNumberToObject(json_root, "error", 74);
            cJSON_AddStringToObject(json_root, "message", "Unable to extract agent key");
            printf("%s", cJSON_PrintUnformatted(json_root));
        } else
            printf(EXTRACT_ERROR);

        fclose(fp);
        exit(1);
    }

    if (json_output) {
        cJSON_AddNumberToObject(json_root, "error", 0);
        cJSON_AddStringToObject(json_root, "data", b64_enc);
        printf("%s", cJSON_PrintUnformatted(json_root));
    } else
        printf(EXTRACT_MSG, n_id, b64_enc);

    if (!cmdextract) {
        printf("\n" PRESS_ENTER);
        read_from_user();
    }

    free(b64_enc);
    fclose(fp);

    return (0);
}

/* Bulk generate client keys from file */
int k_bulkload(const char *cmdbulk)
{
    int i = 1;
    int sock;
    FILE *fp, *infp;
    char str1[STR_SIZE + 1];
    char str2[STR_SIZE + 1];

    os_md5 md1;
    os_md5 md2;
    char line[FILE_SIZE + 1];
    char name[FILE_SIZE + 1];
    char id[FILE_SIZE + 1];
    char ip[FILE_SIZE + 1];
    char delims[] = AGENT_FILE_DELIMS;
    char *token = NULL;
    char *save_ptr;

    sock = auth_connect();

    /* Check if we can open the input file */
    printf("Opening: [%s]\n", cmdbulk);
    infp = fopen(cmdbulk, "r");
    if (!infp) {
        perror("Failed.");
        merror_exit(FOPEN_ERROR, cmdbulk, errno, strerror(errno));
    }

    /* Check if we can open the auth_file */
    fp = fopen(AUTH_FILE, "a");
    if (!fp) {
        merror_exit(FOPEN_ERROR, AUTH_FILE, errno, strerror(errno));
    }
    fclose(fp);

    while (fgets(line, FILE_SIZE - 1, infp) != NULL) {
        os_ip c_ip;
        c_ip.ip = NULL;

        if (1 >= strlen(trimwhitespace(line))) {
            continue;
        }

        memset(ip, '\0', FILE_SIZE + 1);
        token = strtok_r(line, delims, &save_ptr);
        strncpy(ip, trimwhitespace(token), FILE_SIZE - 1);

        memset(name, '\0', FILE_SIZE + 1);
        token = strtok_r(NULL, delims, &save_ptr);

        if (!token)
            merror_exit(SYNTAX_ERROR, cmdbulk);

        strncpy(name, trimwhitespace(token), FILE_SIZE - 1);

#ifndef WIN32
        if (chmod(AUTH_FILE, 0640) == -1) {
            merror_exit(CHMOD_ERROR, AUTH_FILE, errno, strerror(errno));
        }
#endif

        /* Set time 2 */
        time2 = time(0);

        rand1 = os_random();

        /* Check the name */
        if (!OS_IsValidName(name)) {
            printf(INVALID_NAME, name);
            continue;
        }

        /* Search for name  -- no duplicates */
        if (sock < 0 && NameExist(name)) {
            printf(ADD_ERROR_NAME, name);
            continue;
        }

        if (!OS_IsValidIP(ip, &c_ip)) {
            printf(IP_ERROR, ip);
            continue;
        }

        char *ip_exist = NULL;
        if (sock < 0 && (ip_exist = IPExist(ip))) {
            os_free(ip_exist);
            printf(IP_ERROR, ip);
            continue;
        }

        if(ip_exist) {
            os_free(ip_exist);
        }

        if (sock < 0) {
            /* Default ID */
            i = DEFAULT_ID;
            snprintf(id, 8, "%03d", i);
            while (sock < 0 && !IDExist(id, 0)) {
                i--;
                snprintf(id, 8, "%03d", i);

                /* No key present, use id 0 */
                if (i <= 0) {
                    i = 0;
                    break;
                }
            }
            snprintf(id, 8, "%03d", i + 1);

            if (!OS_IsValidID(id)) {
                printf(INVALID_ID, id);
                goto cleanup;
            }

            /* Search for ID KEY  -- no duplicates */
            if (sock < 0 && IDExist(id, 0)) {
                printf(NO_DEFAULT, i + 1);
                goto cleanup;
            }

            printf(AGENT_INFO, id, name, ip);
            fflush(stdout);

            time3 = time(0);
            rand2 = os_random();

            fp = fopen(AUTH_FILE, "a");
            if (!fp) {
                merror_exit(FOPEN_ERROR, KEYS_FILE, errno, strerror(errno));
            }
#ifndef WIN32
            if (chmod(AUTH_FILE, 0640) == -1) {
                merror_exit(CHMOD_ERROR, AUTH_FILE, errno, strerror(errno));
            }
#endif

            /* Random 1: Time took to write the agent information
             * Random 2: Time took to choose the action
             * Random 3: All of this + time + pid
             * Random 4: MD5 all of this + the name, key and IP
             * Random 5: Final key
             */

            os_snprintf(str1, STR_SIZE, "%d%s%d", (int)(time3 - time2), name, (int)rand1);
            os_snprintf(str2, STR_SIZE, "%d%s%s%d", (int)(time2 - time1), ip, id, (int)rand2);

            OS_MD5_Str(str1, -1, md1);
            OS_MD5_Str(str2, -1, md2);

            snprintf(str1, STR_SIZE, "%s%d%d%d", md1, (int)getpid(), os_random(), (int)time3);
            OS_MD5_Str(str1, -1, md1);

            fprintf(fp, "%s %s %s %s%s\n", id, name, c_ip.ip, md1, md2);
            fclose(fp);
        } else {
            if (w_request_agent_add_local(sock, id, name, ip, NULL, NULL, -1, 0,NULL,1) < 0) {
                goto cleanup;
            }
        }

        printf(AGENT_ADD, id);

cleanup:
        free(c_ip.ip);
    };

    fclose(infp);

    if (sock >= 0) {
        close(sock);
    }

    return (0);
}
