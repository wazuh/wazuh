/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <time.h>
#include "manage_agents.h"
#include "os_crypto/md5/md5_op.h"
#include "wazuh_db/wdb.h"

#ifdef WIN32
    #define chmod(x,y) 0
    #define mkdir(x,y) 0
    #define link(x,y) 0
    #define difftime(x,y) 0
#endif

/* Global variables */
fpos_t fp_pos;


char *OS_AddNewAgent(const char *name, const char *ip, const char *id)
{
    FILE *fp;
    os_md5 md1;
    os_md5 md2;
    char str1[STR_SIZE + 1];
    char str2[STR_SIZE + 1];
    char *muname;
    char *finals;
    char nid[9] = { '\0' };

    srandom_init();
    muname = getuname();

    snprintf(str1, STR_SIZE, "%d%s%d%s", (int)time(0), name, (int)random(), muname);
    snprintf(str2, STR_SIZE, "%s%s%ld", ip, id, (long int)random());
    OS_MD5_Str(str1, md1);
    OS_MD5_Str(str2, md2);

    free(muname);

    if (id == NULL) {
#ifdef REUSE_ID
        int i = 1024;
        snprintf(nid, 6, "%d", i);
        while (IDExist(nid)) {
            i++;
            snprintf(nid, 6, "%d", i);
            if (i >= (MAX_AGENTS + 1024))
                return (NULL);
        }
#else
        char nid_p[9] = { '\0' };
        int i = AUTHD_FIRST_ID;
        int j = MAX_AGENTS + AUTHD_FIRST_ID;
        int m = (i + j) / 2;

        snprintf(nid, 8, "%d", m);
        snprintf(nid_p, 8, "%d", m - 1);

        /* Dichotomic search */

        while (1) {
            if (IDExist(nid)) {
                if (m == i)
                    return NULL;

                i = m;
            } else if (!IDExist(nid_p) && m > i )
                j = m;
            else
                break;

            m = (i + j) / 2;
            snprintf(nid, 8, "%d", m);
            snprintf(nid_p, 8, "%d", m - 1);
        }
#endif
        id = nid;
    }

    fp = fopen(AUTH_FILE, "a");
    if (!fp) {
        return (NULL);
    }

    os_calloc(2048, sizeof(char), finals);
    if (ip == NULL) {
        snprintf(finals, 2048, "%s %s any %s%s", id, name, md1, md2);
    } else {
        snprintf(finals, 2048, "%s %s %s %s%s", id, name, ip, md1, md2);
    }
    fprintf(fp, "%s\n", finals);
    fclose(fp);
    OS_AddAgentTimestamp(id, name, ip, time(0));
    wdb_insert_agent(atoi(id), name, ip, finals);
    return (finals);
}

int OS_RemoveAgent(const char *u_id) {
    FILE *fp;
    int id_exist;
    char *full_name;
    long fp_seek;
    size_t fp_read;
    char *buffer;
    char buf_curline[OS_BUFFER_SIZE];
    struct stat fp_stat;

    id_exist = IDExist(u_id);

    if (!id_exist)
        return 0;

    fp = fopen(AUTH_FILE, "r");

    if (!fp)
        return 0;

    if (chmod(AUTH_FILE, 0440) < 0) {
        fclose(fp);
        return 0;
    }

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

    wdb_remove_agent_db(atoi(u_id));

#ifndef REUSE_ID
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

    wdb_disable_agent(atoi(u_id));
#else
    wdb_remove_agent(atoi(u_id));
#endif

    if (!feof(fp))
        fp_read += fread(buffer + fp_read, sizeof(char), fp_stat.st_size, fp);

    fclose(fp);
    fp = fopen(AUTH_FILE, "w");

    if (!fp) {
        free(buffer);
        return 0;
    }

    fwrite(buffer, sizeof(char), fp_read, fp);
    fclose(fp);
    free(buffer);

    if ((full_name = getFullnameById(u_id))) {
        delete_agentinfo(full_name);
        free(full_name);
    }

    /* Remove counter for ID */
    OS_RemoveCounter(u_id);
    OS_RemoveAgentTimestamp(u_id);
    return 1;
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

/* Get full agent name (name + IP) of ID */
char *getFullnameById(const char *id)
{
    FILE *fp;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';

    /* ID must not be null */
    if (!id) {
        return (NULL);
    }

    fp = fopen(AUTH_FILE, "r");
    if (!fp) {
        return (NULL);
    }

    while (fgets(line_read, FILE_SIZE - 1, fp) != NULL) {
        char *name;
        char *ip;
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

            ip = strchr(name, ' ');
            if (ip) {
                *ip = '\0';
                ip++;

                /* Clean up IP */
                tmp_str = strchr(ip, ' ');
                if (tmp_str) {
                    char *final_str;
                    *tmp_str = '\0';
                    tmp_str = strchr(ip, '/');
                    if (tmp_str) {
                        *tmp_str = '\0';
                    }

                    /* If we reached here, we found the IP and name */
                    os_calloc(1, FILE_SIZE, final_str);
                    snprintf(final_str, FILE_SIZE - 1, "%s-%s", name, ip);

                    fclose(fp);
                    return (final_str);
                }
            }
        }
    }

    fclose(fp);
    return (NULL);
}

/* ID Search (is valid ID) */
int IDExist(const char *id)
{
    FILE *fp;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';

    /* ID must not be null */
    if (!id) {
        return (0);
    }

    if (isChroot()) {
        fp = fopen(AUTH_FILE, "r");
    } else {
        fp = fopen(KEYSFILE_PATH, "r");
    }

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

    if (isChroot()) {
        fp = fopen(AUTH_FILE, "r");
    } else {
        fp = fopen(KEYSFILE_PATH, "r");
    }

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

    if (isChroot())
        fp = fopen(AUTH_FILE, "r");
    else
        fp = fopen(KEYSFILE_PATH, "r");

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

/* Returns the number of seconds since last agent connection, or -1 if error. */
double OS_AgentAntiquity(const char *id)
{
    struct stat file_stat;
    char file_name[OS_FLSIZE];
    char *full_name = getFullnameById(id);

    if (!full_name)
        return -1;

    snprintf(file_name, OS_FLSIZE - 1, "%s/%s", AGENTINFO_DIR, full_name);
    free(full_name);

    if (stat(file_name, &file_stat) < 0)
        return -1;

    return difftime(time(NULL), file_stat.st_mtime);
}

/* Print available agents */
int print_agents(int print_status, int active_only, int csv_output, cJSON *json_output)
{
    int total = 0;
    FILE *fp;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';

    fp = fopen(AUTH_FILE, "r");
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
                        int agt_status = get_agent_status(name, ip);
                        if (active_only && (agt_status != GA_STATUS_ACTIVE)) {
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
        struct dirent *dp;

        if (!csv_output && !json_output) {
            printf("\nList of agentless devices:\n");
        }

        dirp = opendir(AGENTLESS_ENTRYDIR);
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

/* Backup agent information before force deleting */
void OS_BackupAgentInfo(const char *id)
{
    char *path_backup;
    char path_src[OS_FLSIZE];
    char path_dst[OS_FLSIZE];
    char *name = getFullnameById(id);
    char *ip;
    time_t timer = time(NULL);
    int status = 0;

    if (!name) {
        merror("%s: ERROR: Agent id %s not found.", ARGV0, id);
        return;
    }

    if (!(ip = strchr(name, '-'))) {
        free(name);
        return;
    }

    *(ip++) = 0;

    path_backup = OS_CreateBackupDir(id, name, ip, timer);

    if (!path_backup) {
        merror("%s: ERROR: Couldn't create backup directory.", ARGV0);
        free(name);
        return;
    }

    /* agent-info */
    snprintf(path_src, OS_FLSIZE, "%s/%s", AGENTINFO_DIR, name);
    snprintf(path_dst, OS_FLSIZE, "%s/agent-info", path_backup);
    status += link(path_src, path_dst);

    /* syscheck */
    snprintf(path_src, OS_FLSIZE, "%s/(%s) %s->syscheck", SYSCHECK_DIR, name, ip);
    snprintf(path_dst, OS_FLSIZE, "%s/syscheck", path_backup);
    status += link(path_src, path_dst);

    snprintf(path_src, OS_FLSIZE, "%s/.(%s) %s->syscheck.cpt", SYSCHECK_DIR, name, ip);
    snprintf(path_dst, OS_FLSIZE, "%s/syscheck.cpt", path_backup);
    status += link(path_src, path_dst);

    snprintf(path_src, OS_FLSIZE, "%s/(%s) %s->syscheck-registry", SYSCHECK_DIR, name, ip);
    snprintf(path_dst, OS_FLSIZE, "%s/syscheck-registry", path_backup);
    status += link(path_src, path_dst);

    snprintf(path_src, OS_FLSIZE, "%s/.(%s) %s->syscheck-registry.cpt", SYSCHECK_DIR, name, ip);
    snprintf(path_dst, OS_FLSIZE, "%s/syscheck-registry.cpt", path_backup);
    status += link(path_src, path_dst);

    /* rootcheck */
    snprintf(path_src, OS_FLSIZE, "%s/(%s) %s->rootcheck", ROOTCHECK_DIR, name, ip);
    snprintf(path_dst, OS_FLSIZE, "%s/rootcheck", path_backup);
    status += link(path_src, path_dst);

    if (status < 0) {
        debug1("%s: Couldn't create some backup files.", ARGV0);

        if (status == -6) {
            debug1("%s: Backup directory empty. Removing %s", ARGV0, path_backup);
            rmdir(path_backup);
        }
    }

    free(name);
    free(path_backup);
}

char* OS_CreateBackupDir(const char *id, const char *name, const char *ip, time_t now) {
    char path[OS_FLSIZE + 1];
    char timestamp[40];

    /* Directory for year ^*/

    strftime(timestamp, 40, "%Y", localtime(&now));
    snprintf(path, OS_FLSIZE, "%s/%s", AGNBACKUP_DIR, timestamp);

    if (IsDir(path) != 0) {
        if (mkdir(path, 0750) < 0) {
            return NULL;
        }
    }

    /* Directory for month */

    strftime(timestamp, 40, "%Y/%b", localtime(&now));
    snprintf(path, OS_FLSIZE, "%s/%s", AGNBACKUP_DIR, timestamp);

    if (IsDir(path) != 0) {
        if (mkdir(path, 0750) < 0) {
            return NULL;
        }
    }

    /* Directory for day */

    strftime(timestamp, 40, "%Y/%b/%d", localtime(&now));
    snprintf(path, OS_FLSIZE, "%s/%s", AGNBACKUP_DIR, timestamp);

    if (IsDir(path) != 0) {
        if (mkdir(path, 0750) < 0) {
            return NULL;
        }
    }

    /* Directory for agent */

    int acount = 1;
    char tag[10] = { 0 };

    while (1) {
        snprintf(path, OS_FLSIZE, "%s/%s/%s %s-%s%s", AGNBACKUP_DIR, timestamp, id, name, ip, tag);

        if (IsDir(path) != 0) {
            if (mkdir(path, 0750) < 0) {
                return NULL;
            } else {
                break;
            }
        } else {
            if (++acount > MAX_TAG_COUNTER) {
                return NULL;
            } else {
                snprintf(tag, 10, " %03d", acount);
            }
        }
    }

    char *retval;
    os_strdup(path, retval);
    return retval;
}

void OS_AddAgentTimestamp(const char *id, const char *name, const char *ip, time_t now)
{
    FILE *fp;
    char timestamp[40];

    fp = fopen(TIMESTAMP_FILE, "a");

    if (!fp) {
        merror("%s: ERROR: Couldn't open timestamp file.", ARGV0);
        return;
    }

    strftime(timestamp, 40, "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(fp, "%s %s %s %s\n", id, name, ip, timestamp);
    fclose(fp);
}

void OS_RemoveAgentTimestamp(const char *id)
{
    FILE *fp;
    char *buffer;
    char line[OS_BUFFER_SIZE];
    int idlen = strlen(id);
    int pos = 0;
    struct stat fp_stat;

    fp = fopen(TIMESTAMP_FILE, "r");

    if (!fp) {
        return;
    }

    if (fstat(fileno(fp), &fp_stat) < 0) {
        fclose(fp);
        return;
    }

    os_calloc(fp_stat.st_size + 1, sizeof(char), buffer);

    while (fgets(line, OS_BUFFER_SIZE, fp)) {
        if (strncmp(id, line, idlen)) {
            strncpy(&buffer[pos], line, fp_stat.st_size - pos);
            pos += strlen(line);
        }
    }

    fclose(fp);
    fp = fopen(TIMESTAMP_FILE, "w");

    if (!fp) {
        merror("%s: ERROR: Couldn't open timetamp file.", ARGV0);
        free(buffer);
        return;
    }

    fprintf(fp, "%s", buffer);
    fclose(fp);
    free(buffer);
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
