/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "cJSON.h"
#include "manage_agents.h"
#include "os_crypto/md5/md5_op.h"
#include "os_err.h"
#include "wazuh_db/wdb.h"
#include <time.h>
#ifndef CLIENT
#include "wazuh_db/helpers/wdb_global_helpers.h"
#include "wazuhdb_op.h"
#endif

#define str_startwith(x, y) strncmp(x, y, strlen(y))
#define str_endwith(x, y) (strlen(x) < strlen(y) || strcmp(x + strlen(x) - strlen(y), y))

#ifdef WIN32
    #define fchmod(x,y) 0
    #define mkdir(x,y) 0
    #define link(x,y) 0
    #define difftime(x,y) 0
    #define mkstemp(x) 0
    #define chown(x,y,z) 0
    #define Privsep_GetUser(x) -1
    #define Privsep_GetGroup(x) -1
#endif

int OS_AddNewAgent(keystore *keys, const char *id, const char *name, const char *ip, const char *key)
{
    os_md5 md1;
    os_md5 md2;
    char str1[STR_SIZE + 1];
    char str2[STR_SIZE + 1];
    char _id[12] = { '\0' };
    char buffer[KEYSIZE] = { '\0' };

    if (!id) {
        snprintf(_id,sizeof(_id), "%03d", ++keys->id_counter);
        id = _id;
    }
    else {
        char *endptr;
        int id_number = strtol(id, &endptr, 10);

        if ('\0' == *endptr && id_number > keys->id_counter)
            keys->id_counter = id_number;
    }

    if (!key) {
        snprintf(str1, STR_SIZE, "%d%s%d%s", (int)time(0), name, os_random(), getuname());
        snprintf(str2, STR_SIZE, "%s%s%ld", ip, id, (long int)os_random());
        OS_MD5_Str(str1, -1, md1);
        OS_MD5_Str(str2, -1, md2);
        snprintf(buffer, KEYSIZE, "%s%s", md1, md2);
        key = buffer;
    }

    return OS_AddKey(keys, id, name, ip ? ip : "any", key, time(NULL));
}

int OS_IsValidID(const char *id)
{
    size_t id_len, i;

    /* ID must not be null */
    if (!id) {
        return (0);
    }

    id_len = strlen(id);

    /* Check ID length, it should contain max. 8 characters */
    if (id_len > 8) {
        return (0);
    }

    /* Check ID if it contains only numeric characters [0-9] */
    for (i = 0; i < id_len; i++) {
        if (!(isdigit((int)id[i]))) {
            return (0);
        }
    }

    return (1);
}

/* Validate agent name */
int OS_IsValidName(const char *u_name)
{
    size_t i, uname_length = strlen(u_name);

    /* We must have something in the name */
    if (uname_length < 2 || uname_length > 128) {
        return (0);
    }

    /* Check if it contains any non-alphanumeric characters */
    for (i = 0; i < uname_length; i++) {
        if (!isalnum((int)u_name[i]) && (u_name[i] != '-') &&
                (u_name[i] != '_') && (u_name[i] != '.')) {
            return (0);
        }
    }

    return (1);
}

void OS_ConvertToValidAgentName(char *u_name) {
    size_t i, uname_length = strlen(u_name);
    while((i = strspn(u_name, VALID_AGENT_NAME_CHARS)), i < uname_length )
    {
        // Invalid character detected, delete it
        memmove(u_name + i, u_name + i + 1, uname_length - i);
        uname_length--;
    }
}

/* Print available agents */
int print_agents(int print_status, int active_only, int inactive_only, int csv_output, cJSON *json_output)
{
    int total = 0;
    FILE *fp;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';

    fp = wfopen(KEYS_FILE, "r");
    if (!fp) {
        return (0);
    }

    fseek(fp, 0, SEEK_SET);

    memset(line_read, '\0', FILE_SIZE);

    while (fgets(line_read, FILE_SIZE - 1, fp) != NULL) {
        char *name;

        if (line_read[0] == '#') {
            continue;
        }

        name = strchr(line_read, ' ');
        if (name) {
            char *ip;
            *name = '\0';
            name++;

            /* Removed agent */
            if (*name == '#' || *name == '!') {
                continue;
            }

            ip = strchr(name, ' ');
            if (ip) {
                char *key;
                *ip = '\0';
                ip++;
                key = strchr(ip, ' ');
                if (key) {
                    *key = '\0';
                    if (!total && !print_status) {
                        printf(PRINT_AVAILABLE);
                    }
                    total++;

                    if (print_status) {
                        #ifndef CLIENT //print_status is only available on servers
                        // Within this context, line_read corresponds to the agent ID
                        agent_status_t agt_status = get_agent_status(atoi(line_read));
                        if (active_only && (agt_status != GA_STATUS_ACTIVE)) {
                            continue;
                        }

                        if (inactive_only && agt_status != GA_STATUS_NACTIVE) {
                            continue;
                        }

                        if (csv_output) {
                            printf("%s,%s,%s,%s,\n", line_read, name, ip, print_agent_status(agt_status));
                        } else if (json_output) {
                            cJSON *json_agent = cJSON_CreateObject();

                            if (!json_agent) {
                                fclose(fp);
                                return 0;
                            }

                            cJSON_AddStringToObject(json_agent, "id", line_read);
                            cJSON_AddStringToObject(json_agent, "name", name);
                            cJSON_AddStringToObject(json_agent, "ip", ip);
                            cJSON_AddStringToObject(json_agent, "status", print_agent_status(agt_status));
                            cJSON_AddItemToArray(json_output, json_agent);
                        } else {
                            printf(PRINT_AGENT_STATUS, line_read, name, ip, print_agent_status(agt_status));
                        }
                        #else
                        (void) inactive_only;
                        printf(PRINT_AGENT, line_read, name, ip);
                        #endif
                    } else {
                        printf(PRINT_AGENT, line_read, name, ip);
                    }
                }
            }
        }
    }

    /* Only print agentless for non-active only searches */
    if (!active_only && print_status) {
        const char *aip = NULL;
        DIR *dirp;
        struct dirent *dp = NULL;

        if (!csv_output && !json_output) {
            printf("\nList of agentless devices:\n");
        }

        dirp = wopendir(AGENTLESS_ENTRYDIR);
        if (dirp) {
            while ((dp = readdir(dirp)) != NULL) {
                if (strncmp(dp->d_name, ".", 1) == 0) {
                    continue;
                }

                aip = strchr(dp->d_name, '@');
                if (aip) {
                    aip++;
                } else {
                    aip = "<na>";
                }

                if (csv_output) {
                    printf("na,%s,%s,agentless,\n", dp->d_name, aip);
                } else {
                    printf("   ID: na, Name: %s, IP: %s, agentless\n",
                           dp->d_name, aip);
                }
            }
            closedir(dirp);
        }
    }

    fclose(fp);
    if (total) {
        return (1);
    }

    return (0);
}

void OS_RemoveAgentTimestamp(const char *id)
{
    FILE *fp;
    File file;
    char line[OS_BUFFER_SIZE];
    char * sep;

    fp = wfopen(TIMESTAMP_FILE, "r");

    if (!fp) {
        return;
    }

    if (TempFile(&file, TIMESTAMP_FILE, 0) < 0) {
        merror("Couldn't open timestamp file.");
        fclose(fp);
        return;
    }

    while (fgets(line, OS_BUFFER_SIZE, fp)) {
        if (sep = strchr(line, ' '), sep) {
            *sep = '\0';
        } else {
            continue;
        }

        if (strcmp(id, line) != 0) {
            *sep = ' ';
            fputs(line, file.fp);
        }
    }

    fclose(fp);
    fclose(file.fp);
    OS_MoveFile(file.name, TIMESTAMP_FILE);
    free(file.name);
}
