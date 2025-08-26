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

/* Global variables */
fpos_t fp_pos;

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

#ifndef CLIENT

int OS_RemoveAgent(const char *u_id) {
    FILE *fp;
    File file;
    int id_exist;
    char *name;
    long fp_seek;
    size_t fp_read;
    char *buffer;
    char buf_curline[OS_BUFFER_SIZE];
    struct stat fp_stat;
    char wdbquery[OS_SIZE_128 + 1];
    char *wdboutput;

    id_exist = IDExist(u_id, 1);

    if (!id_exist)
        return 0;

    fp = wfopen(KEYS_FILE, "r");

    if (!fp)
        return 0;

    if (fstat(fileno(fp), &fp_stat) < 0) {
        fclose(fp);
        return 0;
    }

    buffer = malloc(fp_stat.st_size + 1);
    if (!buffer) {
        fclose(fp);
        return 0;
    }

    if (fsetpos(fp, &fp_pos) < 0) {
        fclose(fp);
        free(buffer);
        return 0;
    }

    if ((fp_seek = ftell(fp)) < 0) {
        fclose(fp);
        free(buffer);
        return 0;
    }

    fseek(fp, 0, SEEK_SET);
    fp_read = fread(buffer, sizeof(char), (size_t)fp_seek, fp);

    if (!fgets(buf_curline, OS_BUFFER_SIZE - 2, fp)) {
        free(buffer);
        fclose(fp);
        return 0;
    }

    char *ptr_name = strchr(buf_curline, ' ');

    if (!ptr_name) {
        free(buffer);
        fclose(fp);
        return 0;
    }

    ptr_name++;

    memmove(ptr_name + 1, ptr_name, strlen(ptr_name) + 1);
    *ptr_name = '!';
    size_t curline_len = strlen(buf_curline);
    memcpy(buffer + fp_read, buf_curline, curline_len);
    fp_read += curline_len;

    if (!feof(fp))
        fp_read += fread(buffer + fp_read, sizeof(char), fp_stat.st_size, fp);

    fclose(fp);

    if (TempFile(&file, KEYS_FILE, 0) < 0) {
        free(buffer);
        return 0;
    }

    fwrite(buffer, sizeof(char), fp_read, file.fp);
    fclose(file.fp);
    name = getNameById(u_id);

    if (OS_MoveFile(file.name, KEYS_FILE) < 0) {
        free(file.name);
        free(buffer);
        free(name);
        return 0;
    }

    free(file.name);
    free(buffer);

    if (name) {
        delete_diff(name);
        free(name);
    }

    // Remove DB from wazuh-db
    int sock = -1;
    int error;
    snprintf(wdbquery, OS_SIZE_128, "wazuhdb remove %s", u_id);
    os_calloc(OS_SIZE_6144, sizeof(char), wdboutput);
    if (error = wdbc_query_ex(&sock, wdbquery, wdboutput, OS_SIZE_6144), !error) {
        mdebug1("DB from agent %s was deleted '%s'", u_id, wdboutput);
    } else {
        merror("Could not remove the DB of the agent %s. Error: %d.", u_id, error);
    }

    os_free(wdboutput);

    if (wdb_remove_agent(atoi(u_id), &sock) != OS_SUCCESS) {
        mdebug1("Could not remove the information stored in Wazuh DB of the agent %s.", u_id);
    }

    wdbc_close(&sock);

    /* Remove counter for ID */
    OS_RemoveCounter(u_id);
    OS_RemoveAgentTimestamp(u_id);
    return 1;
}

#endif

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

/* Get agent name of ID */
char *getNameById(const char *id)
{
    FILE *fp;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';

    /* ID must not be null */
    if (!id) {
        return (NULL);
    }

    fp = wfopen(KEYS_FILE, "r");
    if (!fp) {
        return (NULL);
    }

    while (fgets(line_read, FILE_SIZE - 1, fp) != NULL) {
        char *name;
        char *tmp_str;

        if (line_read[0] == '#') {
            continue;
        }

        name = strchr(line_read, ' ');
        if (name) {
            *name = '\0';
            /* Didn't match */
            if (strcmp(line_read, id) != 0) {
                continue;
            }

            name++;

            /* Removed entry */
            if (*name == '#' || *name == '!') {
                continue;
            }

            /* Clean up name */
            tmp_str = strchr(name, ' ');
            if (tmp_str) {
                char *final_str;
                *tmp_str = '\0';

                /* If we reached here, we found the name */
                os_calloc(1, FILE_SIZE, final_str);
                snprintf(final_str, FILE_SIZE - 1, "%s", name);

                fclose(fp);
                return (final_str);
            }
        }
    }

    fclose(fp);
    return (NULL);
}

/* ID Search (is valid ID) */
int IDExist(const char *id, int discard_removed)
{
    FILE *fp;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';

    /* ID must not be null */
    if (!id) {
        return (0);
    }

    fp = wfopen(KEYS_FILE, "r");

    if (!fp) {
        return (0);
    }

    fseek(fp, 0, SEEK_SET);
    fgetpos(fp, &fp_pos);

    while (fgets(line_read, FILE_SIZE - 1, fp) != NULL) {
        char *name;

        if (line_read[0] == '#') {
            fgetpos(fp, &fp_pos);
            continue;
        }

        name = strchr(line_read, ' ');
        if (name) {
            *name = '\0';
            name++;

            if (strcmp(line_read, id) == 0) {
                if (discard_removed && (*name == '!' || *name == '#')) {
                    fgetpos(fp, &fp_pos);
                    continue;
                }

                fclose(fp);
                return (1); /*(fp_pos);*/
            }
        }

        fgetpos(fp, &fp_pos);
    }

    fclose(fp);
    return (0);
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

int NameExist(const char *u_name)
{
    FILE *fp;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';

    if ((!u_name) ||
            (*u_name == '\0') ||
            (*u_name == '\r') ||
            (*u_name == '\n')) {
        return (0);
    }

    fp = wfopen(KEYS_FILE, "r");

    if (!fp) {
        return (0);
    }

    fseek(fp, 0, SEEK_SET);
    fgetpos(fp, &fp_pos);

    while (fgets(line_read, FILE_SIZE - 1, fp) != NULL) {
        char *name;

        if (line_read[0] == '#') {
            continue;
        }

        name = strchr(line_read, ' ');
        if (name) {
            char *ip;
            name++;

            if (*name == '#' || *name == '!') {
                continue;
            }

            ip = strchr(name, ' ');
            if (ip) {
                *ip = '\0';
                if (strcmp(u_name, name) == 0) {
                    fclose(fp);
                    return (1);
                }
            }
        }
        fgetpos(fp, &fp_pos);
    }

    fclose(fp);
    return (0);
}

/* Returns the ID of an agent, or NULL if not found */
char *IPExist(const char *u_ip)
{
    FILE *fp;
    char *name, *ip, *pass;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';

    if (!(u_ip && strncmp(u_ip, "any", 3)) || strchr(u_ip, '/'))
        return NULL;

    fp = wfopen(KEYS_FILE, "r");

    if (!fp)
        return NULL;

    fseek(fp, 0, SEEK_SET);
    fgetpos(fp, &fp_pos);

    while (fgets(line_read, FILE_SIZE - 1, fp) != NULL) {
        if (line_read[0] == '#') {
            continue;
        }

        name = strchr(line_read, ' ');
        if (name) {
            name++;

            if (*name == '#' || *name == '!') {
                continue;
            }

            ip = strchr(name, ' ');
            if (ip) {
                ip++;

                pass = strchr(ip, ' ');
                if (pass) {
                    *pass = '\0';
                    if (strcmp(u_ip, ip) == 0) {
                        fclose(fp);
                        name[-1] = '\0';
                        return strdup(line_read);
                    }
                }
            }
        }

        fgetpos(fp, &fp_pos);
    }

    fclose(fp);
    return NULL;
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

void OS_AddAgentTimestamp(const char *id, const char *name, const char *ip, time_t now)
{
    File file;
    char timestamp[40];
    struct tm tm_result = { .tm_sec = 0 };

    if (TempFile(&file, TIMESTAMP_FILE, 1) < 0) {
        merror("Couldn't open timestamp file.");
        return;
    }

    strftime(timestamp, 40, "%Y-%m-%d %H:%M:%S", localtime_r(&now, &tm_result));
    fprintf(file.fp, "%s %s %s %s\n", id, name, ip, timestamp);
    fclose(file.fp);
    OS_MoveFile(file.name, TIMESTAMP_FILE);
    free(file.name);
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

void FormatID(char *id) {
    int number;
    char *end;

    if (id && *id) {
        number = strtol(id, &end, 10);

        if (!*end)
            sprintf(id, "%03d", number);
    }
}
