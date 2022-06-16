/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "read-agents.h"
#include "os_net/os_net.h"
#include "wazuhdb_op.h"
#include "wazuh_db/helpers/wdb_global_helpers.h"

#ifndef WIN32
static int _do_print_attrs_syscheck(const char *prev_attrs, const char *attrs, int csv_output, cJSON *json_output,
                                    int is_win, int number_of_changes) __attribute__((nonnull(2)));
static int _do_print_file_syscheck(FILE *fp, const char *fname, int update_counter,
                                   int csv_output, cJSON *json_output) __attribute__((nonnull(1)));
static int _do_print_syscheck(FILE *fp, int all_files, int csv_output, cJSON *json_output) __attribute__((nonnull(1)));
static int _get_time_fim_scan(const char* agent_id, agent_info *agt_info) __attribute__((nonnull(1)));
#endif /* !WIN32*/

/* Free the agent list in memory */
void free_agents(char **agent_list)
{
    int i;
    if (!agent_list) {
        return;
    }

    for (i = 0;; i++) {
        if (agent_list[i] == NULL) {
            break;
        }

        free(agent_list[i]);
        agent_list[i] = NULL;
    }

    free(agent_list);
    agent_list = NULL;
}

#ifndef WIN32

/* Print syscheck attributes */
#define sk_strchr(x,y,z) z = strchr(x, y); if(z == NULL) return(0); else { *z = '\0'; z++; }

static int _do_print_attrs_syscheck(const char *prev_attrs, const char *attrs, __attribute__((unused)) int csv_output,
                                    cJSON *json_output, int is_win, int number_of_changes)
{
    const char *p_size, *size;
    char *file_perm;
    char *p_perm, *p_uid, *p_gid, *p_md5, *p_sha1;
    char *perm, *uid, *gid, *md5, *sha1;
    mode_t mode;
    char perm_str[36];

    /* A deleted file has no attributes */
    if (strcmp(attrs, "-1") == 0) {
        if (json_output)
            cJSON_AddStringToObject(json_output, "event", "deleted");
        else
            printf("File deleted.\n");
        return (0);
    }

    /* Set each value */
    size = attrs;
    sk_strchr(size, ':', perm);
    sk_strchr(perm, ':', uid);
    sk_strchr(uid, ':', gid);
    sk_strchr(gid, ':', md5);
    sk_strchr(md5, ':', sha1);

    p_size = size;
    p_perm = perm;
    p_uid = uid;
    p_gid = gid;
    p_md5 = md5;
    p_sha1 = sha1;

    if (prev_attrs && (strcmp(prev_attrs, "-1") == 0)) {
        if (json_output)
            cJSON_AddStringToObject(json_output, "event", "restored");
        else
            printf("File restored. ");
    } else if (prev_attrs) {
        if (json_output)
            cJSON_AddStringToObject(json_output, "event", "modified");
        else
            printf("File changed. ");

        p_size = prev_attrs;
        sk_strchr(p_size, ':', p_perm);
        sk_strchr(p_perm, ':', p_uid);
        sk_strchr(p_uid, ':', p_gid);
        sk_strchr(p_gid, ':', p_md5);
        sk_strchr(p_md5, ':', p_sha1);
    } else {
        if (json_output)
            cJSON_AddStringToObject(json_output, "event", "added");
        else
            printf("File added to the database. ");
    }

    if (!json_output) {
        /* Fix number of changes */
        if (prev_attrs && !number_of_changes) {
            number_of_changes = 1;
        }

        if (number_of_changes) {
            switch (number_of_changes) {
                case 1:
                    printf("- 1st time modified.\n");
                    break;
                case 2:
                    printf("- 2nd time modified.\n");
                    break;
                case 3:
                    printf("- 3rd time modified.\n");
                    break;
                default:
                    printf("- Being ignored (3 or more changes).\n");
                    break;
            }
        } else {
            printf("\n");
        }
    }

    perm_str[35] = '\0';
    /* octal or decimal */
    mode = (mode_t) strtoul(perm, 0, strlen(perm) == 3 ? 8 : 10);
    file_perm = agent_file_perm(mode);
    snprintf(perm_str, 35, "%9.9s", file_perm);
    free(file_perm);

    if (json_output) {
        cJSON_AddStringToObject(json_output, "size", size);
        cJSON_AddNumberToObject(json_output, "mode", is_win ? 0 : mode);
        cJSON_AddStringToObject(json_output, "perm", is_win ? "" : perm_str);
        cJSON_AddStringToObject(json_output, "uid", is_win ? "" : uid);
        cJSON_AddStringToObject(json_output, "gid", is_win ? "" : gid);
        cJSON_AddStringToObject(json_output, "md5", md5);
        cJSON_AddStringToObject(json_output, "sha1", sha1);

    } else{
        printf("Integrity checking values:\n");
        printf("   Size:%s%s\n", (strcmp(size, p_size) == 0) ? " " : " >", size);
        if (!is_win) {
            printf("   Perm:%s%s\n", (strcmp(perm, p_perm) == 0) ? " " : " >", perm_str);
            printf("   Uid: %s%s\n", (strcmp(uid, p_uid) == 0) ? " " : " >", uid);
            printf("   Gid: %s%s\n", (strcmp(gid, p_gid) == 0) ? " " : " >", gid);
        }
        printf("   Md5: %s%s\n", (strcmp(md5, p_md5) == 0) ? " " : " >", md5);
        printf("   Sha1:%s%s\n", (strcmp(sha1, p_sha1) == 0) ? " " : " >", sha1);
    }

    /* Fix entries */
    perm[-1] = ':';
    uid[-1] = ':';
    gid[-1] = ':';
    md5[-1] = ':';
    sha1[-1] = ':';

    return (0);
}

/* Print information about a specific file */
static int _do_print_file_syscheck(FILE *fp, const char *fname, int update_counter,
                                   int csv_output, cJSON *json_output)
{
    int f_found = 0;
    struct tm tm_result = { .tm_sec = 0 };
    char read_day[24 + 1];
    char buf[OS_MAXSTR + 1];
    OSRegex reg;
    OSStore *files_list = NULL;
    fpos_t init_pos;
    cJSON *json_entry = NULL, *json_attrs = NULL;

    buf[OS_MAXSTR] = '\0';
    read_day[24] = '\0';

    /* If the compilation failed, we don't need to free anything */
    if (!OSRegex_Compile(fname, &reg, 0)) {
        if (!(csv_output || json_output))
            printf("\n** ERROR: Invalid file name: '%s'\n", fname);
        return (0);
    }

    /* Create list with files */
    files_list = OSStore_Create();
    if (!files_list) {
        OSRegex_FreePattern(&reg);
        goto cleanup;
    }

    /* Get initial position */
    if (fgetpos(fp, &init_pos) != 0) {
        if (!(csv_output || json_output))
            printf("\n** ERROR: fgetpos failed.\n");
        goto cleanup;
    }

    while (fgets(buf, OS_MAXSTR, fp) != NULL) {
        if (buf[0] == '!' || buf[0] == '#' || buf[0] == '+') {
            int number_changes = 0;
            time_t change_time = 0;
            char *changed_file_name;
            char *changed_attrs;
            char *prev_attrs;

            if (strlen(buf) < 16) {
                fgetpos(fp, &init_pos);
                continue;
            }

            /* Remove newline */
            buf[strlen(buf) - 1] = '\0';

            /* With update counter, we only modify the last entry */
            if (update_counter && buf[0] == '#') {
                fgetpos(fp, &init_pos);
                continue;
            }

            /* Check the number of changes */
            if (buf[1] == '!') {
                number_changes = 2;
                if (buf[2] == '!') {
                    number_changes = 3;
                } else if (buf[2] == '?') {
                    number_changes = 4;
                }
            }

            changed_attrs = buf + 3;

            changed_file_name = strchr(changed_attrs, '!');
            if (!changed_file_name) {
                fgetpos(fp, &init_pos);
                continue;
            }

            /* Get time of change */
            changed_file_name[-1] = '\0';
            changed_file_name++;
            change_time = (time_t)atoi(changed_file_name);

            changed_file_name = strchr(changed_file_name, ' ');
            if (!changed_file_name) {
                if (!(csv_output || json_output))
                    printf("\n** ERROR: Invalid line: '%s'.\n", buf);
                goto cleanup;
            }
            changed_file_name++;

            /* Check if the name should be printed */
            if (!OSRegex_Execute(changed_file_name, &reg)) {
                fgetpos(fp, &init_pos);
                continue;
            }

            f_found = 1;

            /* Reset the values */
            if (update_counter) {
                if (fsetpos(fp, &init_pos) != 0) {
                    if (!(csv_output || json_output))
                        printf("\n** ERROR: fsetpos failed (unable to update "
                               "counter).\n");
                    goto cleanup;
                }

                if (update_counter == 2) {
                    if (fprintf(fp, "!!?") <= 0) {
                        if (!(csv_output || json_output))
                            printf("\n** ERROR: fputs failed (unable to update "
                                   "counter).\n");
                        goto cleanup;
                    }
                }

                else {
                    if (fprintf(fp, "!++") <= 0) {
                        if (!(csv_output || json_output))
                            printf("\n** ERROR: fputs failed (unable to update "
                                   "counter).\n");
                        goto cleanup;
                    }
                }

                if (!(csv_output || json_output))
                    printf("\n**Counter updated for file '%s'\n\n",
                           changed_file_name);
                goto cleanup;
            }

            localtime_r(&change_time, &tm_result);
            strftime(read_day, 23, "%Y %h %d %T", &tm_result);

            if (json_output) {
                json_entry = cJSON_CreateObject();
                json_attrs = cJSON_CreateObject();

                cJSON_AddStringToObject(json_entry, "date", read_day);
                cJSON_AddStringToObject(json_entry, "file", changed_file_name);
                cJSON_AddNumberToObject(json_entry, "changes", number_changes);

            } else if (csv_output)
                printf("%s,%s,%d\n", read_day, changed_file_name,
                       number_changes);
            else
                printf("\n%s,%d - %s\n", read_day, number_changes,
                       changed_file_name);

            prev_attrs = (char *) OSStore_Get(files_list, changed_file_name);

            if (prev_attrs) {
                char *new_attrs;
                os_strdup(changed_attrs, new_attrs);
                _do_print_attrs_syscheck(prev_attrs, changed_attrs,
                                         csv_output, json_attrs,
                                         changed_file_name[0] == '/' ? 0 : 1,
                                         number_changes);

                free(files_list->cur_node->data);
                files_list->cur_node->data = new_attrs;
            } else {
                char *new_attrs;

                os_strdup(changed_attrs, new_attrs);
                OSStore_Put(files_list, changed_file_name, new_attrs);
                _do_print_attrs_syscheck(NULL,
                                         changed_attrs, csv_output, json_attrs,
                                         changed_file_name[0] == '/' ? 0 : 1,
                                         number_changes);
            }

            if (json_output) {
                cJSON_AddItemToObject(json_entry, "attrs", json_attrs);
                cJSON_AddItemToArray(json_output, json_entry);
            }

            fgetpos(fp, &init_pos);
        }
    }

    if (!(f_found || csv_output || json_output)) {
        printf("\n** No entries found.\n");
    }

cleanup:
    OSRegex_FreePattern(&reg);
    if (files_list) {
        OSStore_Free(files_list);
    }

    return (0);
}

/* Print syscheck db (of modified files) */
static int _do_print_syscheck(FILE *fp, __attribute__((unused)) int all_files, int csv_output, cJSON *json_output)
{
    int f_found = 0;
    struct tm tm_result = { .tm_sec = 0 };

    char read_day[24 + 1];
    char saved_read_day[24 + 1];
    char buf[OS_MAXSTR + 1];

    buf[OS_MAXSTR] = '\0';
    read_day[24] = '\0';
    saved_read_day[0] = '\0';
    saved_read_day[24] = '\0';

    while (fgets(buf, OS_MAXSTR, fp) != NULL) {
        if (buf[0] == '!' || buf[0] == '#') {
            int number_changes = 0;
            time_t change_time = 0;
            char *changed_file_name;

            if (strlen(buf) < 16) {
                continue;
            }

            /* Remove newline */
            buf[strlen(buf) - 1] = '\0';

            /* Check the number of changes */
            if (buf[1] == '!') {
                number_changes = 2;
                if (buf[2] == '!') {
                    number_changes = 3;
                } else if (buf[2] == '?') {
                    number_changes = 4;
                }
            }

            changed_file_name = strchr(buf + 3, '!');
            if (!changed_file_name) {
                continue;
            }

            f_found = 1;

            /* Get time of change */
            changed_file_name++;
            change_time = atoi(changed_file_name);

            changed_file_name = strchr(changed_file_name, ' ');
            if (!changed_file_name) {
                if (!(csv_output || json_output))
                    printf("\n** ERROR: Invalid line: '%s'.\n", buf);
                return (-1);
            }
            changed_file_name++;

            localtime_r(&change_time, &tm_result);
            strftime(read_day, 23, "%Y %h %d", &tm_result);
            if (strcmp(read_day, saved_read_day) != 0) {
                if (!(csv_output || json_output)) {
                    printf("\nChanges for %s:\n", read_day);
                }
                snprintf(saved_read_day, sizeof(saved_read_day), "%s", read_day);
            }
            strftime(read_day, 23, "%Y %h %d %T", &tm_result);

            if (json_output) {
                cJSON *entry = cJSON_CreateObject();
                cJSON_AddStringToObject(entry, "date", read_day);
                cJSON_AddStringToObject(entry, "file", changed_file_name);
                cJSON_AddNumberToObject(entry, "changes", number_changes);
                cJSON_AddItemToArray(json_output, entry);
            } else if (csv_output)
                printf("%s,%s,%d\n", read_day, changed_file_name,
                       number_changes);
            else
                printf("%s,%d - %s\n", read_day, number_changes,
                       changed_file_name);
        }
    }

    if (!(f_found || csv_output || json_output)) {
        printf("\n** No entries found.\n");
    }

    return (0);
}

/* Print syscheck db (of modified files) */
int print_syscheck(const char *sk_name, const char *sk_ip, const char *fname,
                   int print_registry, int all_files, int csv_output,
                   cJSON *json_output, int update_counter)
{
    FILE *fp;
    char tmp_file[513];

    tmp_file[512] = '\0';

    if (sk_name == NULL) {
        /* Print database */
        snprintf(tmp_file, 512, "%s/syscheck",
                 SYSCHECK_DIR);

        fp = fopen(tmp_file, "r+");
    }

    else if (sk_ip == NULL) {
        /* Print database */
        snprintf(tmp_file, 512, "%s/%s->syscheck", SYSCHECK_DIR, sk_name);

        fp = fopen(tmp_file, "r+");
    }

    else if (!print_registry) {
        /* Print database */
        snprintf(tmp_file, 512, "%s/(%s) %s->syscheck",
                 SYSCHECK_DIR,
                 sk_name,
                 sk_ip);

        fp = fopen(tmp_file, "r+");
    }

    else {
        /* Print database for the Windows registry */
        snprintf(tmp_file, 512, "%s/(%s) %s->syscheck-registry",
                 SYSCHECK_DIR,
                 sk_name,
                 sk_ip);

        fp = fopen(tmp_file, "r+");
    }

    if (fp) {
        if (!fname) {
            _do_print_syscheck(fp, all_files, csv_output, json_output);
        } else {
            _do_print_file_syscheck(fp, fname, update_counter, csv_output, json_output);
        }
        fclose(fp);
    }

    return (0);
}

#endif

/* Delete syscheck db */
int delete_syscheck(const char *sk_name, const char *sk_ip, int full_delete)
{
    FILE *fp;
    char tmp_file[513];

    tmp_file[512] = '\0';

    /* Delete related files */
    snprintf(tmp_file, 512, "%s/(%s) %s->syscheck",
             SYSCHECK_DIR,
             sk_name,
             sk_ip);

    fp = fopen(tmp_file, "w");
    if (fp) {
        fclose(fp);
    }

    if (full_delete) {
        unlink(tmp_file);
    }

    /* Delete cpt files */
    snprintf(tmp_file, 512, "%s/.(%s) %s->syscheck.cpt",
             SYSCHECK_DIR,
             sk_name,
             sk_ip);

    fp = fopen(tmp_file, "w");
    if (fp) {
        fclose(fp);
    }
    unlink(tmp_file);

    /* Delete registry entries */
    snprintf(tmp_file, 512, "%s/(%s) %s->syscheck-registry",
             SYSCHECK_DIR,
             sk_name,
             sk_ip);

    fp = fopen(tmp_file, "w");
    if (fp) {
        fclose(fp);
    }
    if (full_delete) {
        unlink(tmp_file);
    }

    /* Delete cpt files */
    snprintf(tmp_file, 512, "%s/.(%s) %s->syscheck-registry.cpt",
             SYSCHECK_DIR,
             sk_name,
             sk_ip);

    fp = fopen(tmp_file, "w");
    if (fp) {
        fclose(fp);
    }
    unlink(tmp_file);

    return (1);
}

/* Delete agent SQLite db */
void delete_sqlite(const char *id, const char *name)
{
    char path[512] = { '\0' };

    /* Delete related files */
    snprintf(path, 511, "%s/agents/%s-%s.db", WDB_DIR, id, name);
    unlink(path);

    snprintf(path, 511, "%s/agents/%s-%s.db-wal", WDB_DIR, id, name);
    unlink(path);

    snprintf(path, 511, "%s/agents/%s-%s.db-shm", WDB_DIR, id, name);
    unlink(path);
}

/* Delete diff folders */
void delete_diff(const char *name)
{
    if (!name || *name == '\0') {
        return;
    }

    char tmp_folder[513];
    tmp_folder[512] = '\0';
    snprintf(tmp_folder, 512, "%s/%s",
             DIFF_DIR,
             name);

    rmdir_ex(tmp_folder);
}

/* Delete agent */
int delete_agentinfo(const char *id, const char *name)
{
    const char *sk_name;
    char *sk_ip;

    /* Delete syscheck */
    sk_name = name;
    sk_ip = strrchr(name, '-');
    if (!sk_ip) {
        return (0);
    }

    *sk_ip = '\0';
    sk_ip++;

    /* Delete syscheck */
    delete_syscheck(sk_name, sk_ip, 1);

    /* Delete SQLite database */
    delete_sqlite(id, sk_name);

    /* Delete diff */
    delete_diff(sk_name);

    return (1);
}

/* Print the text representation of the agent status */
const char *print_agent_status(agent_status_t status)
{
    switch (status) {
    case GA_STATUS_ACTIVE:
        return "Active";
    case GA_STATUS_NACTIVE:
        return "Disconnected";
    case GA_STATUS_NEVER:
        return "Never connected";
    case GA_STATUS_PENDING:
        return "Pending";
    case GA_STATUS_UNKNOWN:
        return "Unknown";
    default:
        return "(undefined)";
    }
}

#ifndef WIN32
/* Non-windows functions from now on */

/* Send a message to an agent
 * Returns -1 on error
 */
int send_msg_to_agent(int msocket, const char *msg, const char *agt_id, const char *exec)
{
    char agt_msg[OS_MAXSTR + 1];
    char exec_msg[OS_SIZE_20480 + 1];

    if (!exec) {
        snprintf(agt_msg, OS_MAXSTR,
                 "%s %c%c%c %s %s",
                 "(msg_to_agent) []",
                 (agt_id == NULL) ? ALL_AGENTS_C : NONE_C,
                 NO_AR_C,
                 (agt_id != NULL) ? SPECIFIC_AGENT_C : NONE_C,
                 agt_id != NULL ? agt_id : "(null)",
                 msg);

        if ((OS_SendUnix(msocket, agt_msg, 0)) < 0) {
            merror("Error communicating with remoted queue.");
            return (-1);
        }
    } else {
        int sock = -1;
        int *id_array = NULL;

        if (agt_id == NULL) {
            id_array = wdb_get_all_agents(FALSE, &sock);
            if(!id_array) {
                merror("Unable to get agent's ID array.");
                wdbc_close(&sock);
                return (-1);
            }
        } else {
            os_calloc(2, sizeof(int), id_array);
            id_array[0] = atoi(agt_id);
            id_array[1] = OS_INVALID;
        }

        for (size_t i = 0; id_array[i] != OS_INVALID; i++) {
            cJSON *json_agt_info = NULL;
            cJSON *json_agt_version = NULL;
            char c_agent_id[OS_SIZE_16];
            char *agt_version = NULL;

            memset(agt_msg, 0, OS_MAXSTR + 1);
            memset(exec_msg, 0, OS_SIZE_20480 + 1);

            json_agt_info = wdb_get_agent_info(id_array[i], &sock);
            if (!json_agt_info) {
                merror("Failed to get agent '%d' information from Wazuh DB.", id_array[i]);
                continue;
            }

            json_agt_version = cJSON_GetObjectItem(json_agt_info->child, "version");

            if(cJSON_IsString(json_agt_version) && json_agt_version->valuestring != NULL) {
                agt_version = json_agt_version->valuestring;
            } else {
                mdebug2("Failed to get agent '%d' version.", id_array[i]);
                cJSON_Delete(json_agt_info);
                continue;
            }

            // New AR mechanism is not supported in versions prior to 4.2.0
            char *save_ptr = NULL;
            strtok_r(agt_version, "v", &save_ptr);
            char *major = strtok_r(NULL, ".", &save_ptr);
            char *minor = strtok_r(NULL, ".", &save_ptr);
            if (!major || !minor) {
                merror("Unable to read agent version.");
                cJSON_Delete(json_agt_info);
                continue;
            } else {
                if (atoi(major) < 4 || (atoi(major) == 4 && atoi(minor) < 2)) {
                    snprintf(exec_msg, OS_SIZE_20480,
                             "%s - %s (from_the_server) (no_rule_id)",
                             msg, exec);
                } else {
                    cJSON *json_message = cJSON_CreateObject();
                    cJSON *json_alert = cJSON_CreateObject();
                    cJSON *json_data = cJSON_CreateObject();
                    cJSON *_object = NULL;
                    cJSON *_array = NULL;
                    char *tmp_msg = NULL;

                    // Version
                    cJSON_AddNumberToObject(json_message, "version", 1);

                    // Origin
                    _object = cJSON_CreateObject();
                    cJSON_AddItemToObject(json_message, "origin", _object);

                    cJSON_AddStringToObject(_object, "name", "");
                    cJSON_AddStringToObject(_object, "module", "");

                    // Command
                    cJSON_AddStringToObject(json_message, "command", msg);

                    // Parameters
                    _object = cJSON_CreateObject();
                    cJSON_AddItemToObject(json_message, "parameters", _object);

                    _array = cJSON_CreateArray();
                    cJSON_AddItemToObject(_object, "extra_args", _array);

                    cJSON_AddItemToObject(json_alert, "data", json_data);
                    cJSON_AddStringToObject(json_data, "srcip", exec);
                    cJSON_AddItemToObject(_object, "alert", json_alert);

                    // Message
                    tmp_msg = cJSON_PrintUnformatted(json_message);
                    strncpy(exec_msg, tmp_msg, OS_SIZE_20480);

                    os_free(tmp_msg);
                    cJSON_Delete(json_message);
                }
            }

            cJSON_Delete(json_agt_info);

            snprintf(c_agent_id, OS_SIZE_16, "%.3d", id_array[i]);

            snprintf(agt_msg, OS_MAXSTR,
                     "%s %c%c%c %s %s",
                     "(msg_to_agent) []",
                     NONE_C,
                     NONE_C,
                     SPECIFIC_AGENT_C,
                     c_agent_id,
                     exec_msg);

            if ((OS_SendUnix(msocket, agt_msg, 0)) < 0) {
                merror("Error communicating with remoted queue.");
            }
        }

        os_free(id_array);
        wdbc_close(&sock);
    }

    return (0);
}

/* Connect to remoted to be able to send messages to the agents
 * Returns the socket on success or -1 on failure
 */
int connect_to_remoted()
{
    int arq = -1;

    if ((arq = StartMQ(ARQUEUE, WRITE, 1)) < 0) {
        merror(ARQ_ERROR);
        return (-1);
    }

    return (arq);
}

char *agent_file_perm(mode_t mode)
{
    /* rwxrwxrwx0 -> 10 */
    char *permissions;

    os_calloc(10, sizeof(char), permissions);
    permissions[0] = (mode & S_IRUSR) ? 'r' : '-';
    permissions[1] = (mode & S_IWUSR) ? 'w' : '-';
    permissions[2] = (mode & S_ISUID) ? 's' : (mode & S_IXUSR) ? 'x' : '-';
    permissions[3] = (mode & S_IRGRP) ? 'r' : '-';
    permissions[4] = (mode & S_IWGRP) ? 'w' : '-';
    permissions[5] = (mode & S_ISGID) ? 's' : (mode & S_IXGRP) ? 'x' : '-';
    permissions[6] = (mode & S_IROTH) ? 'r' : '-';
    permissions[7] = (mode & S_IWOTH) ? 'w' : '-';
    permissions[8] = (mode & S_ISVTX) ? 't' : (mode & S_IXOTH) ? 'x' : '-';
    permissions[9] = '\0';

    return permissions;
}


/* Internal function. Extract last time of scan from syscheck. */
static int _get_time_fim_scan(const char* agent_id, agent_info *agt_info)
{
    time_t fim_start;
    time_t fim_end;
    char *timestamp;
    char *tmp_str = NULL;
    char buf_ptr[26];

    fim_start = scantime_fim(agent_id, "start_scan");
    fim_end = scantime_fim(agent_id, "end_scan");
    if (fim_start <= 0) {
        os_strdup("Unknown", agt_info->syscheck_time);
    } else if (fim_start > fim_end){
        os_strdup(w_ctime(&fim_start, buf_ptr, sizeof(buf_ptr)), timestamp);

        /* Remove newline */
        tmp_str = strchr(timestamp, '\n');
        if (tmp_str) {
            *tmp_str = '\0';
        }
        os_calloc(OS_SIZE_128, sizeof(char), agt_info->syscheck_time);
        snprintf(agt_info->syscheck_time, OS_SIZE_128, "%s (Scan in progress)", timestamp);
        os_free(timestamp);
    } else {
        os_strdup(w_ctime(&fim_start, buf_ptr, sizeof(buf_ptr)), agt_info->syscheck_time);

        /* Remove newline */
        tmp_str = strchr(agt_info->syscheck_time, '\n');
        if (tmp_str) {
            *tmp_str = '\0';
        }
    }
    if (fim_end <= 0) {
        os_strdup("Unknown", agt_info->syscheck_endtime);
    } else {
        os_strdup(w_ctime(&fim_end, buf_ptr, sizeof(buf_ptr)), agt_info->syscheck_endtime);
    }

    return (0);
}

/* Get information from an agent */
agent_info *get_agent_info(const char *agent_id){
    cJSON *json_agt_info = NULL;
    cJSON *json_field = NULL;
    agent_info *agt_info = NULL;
    char keepalive_str[OS_SIZE_512] = "";

    /* Getting all the information of the agent */
    json_agt_info = wdb_get_agent_info(atoi(agent_id), NULL);

    if (!json_agt_info) {
        mdebug1("Failed to get agent '%s' information from Wazuh DB.",agent_id);
        return NULL;
    }

    /* Allocate memory for the info structure */
    os_calloc(1, sizeof(agent_info), agt_info);

    json_field = cJSON_GetObjectItem(json_agt_info->child, "os_uname");
    if(cJSON_IsString(json_field) && json_field->valuestring != NULL){
        os_strdup(json_field->valuestring, agt_info->os);
    }

    json_field = cJSON_GetObjectItem(json_agt_info->child, "version");
    if(cJSON_IsString(json_field) && json_field->valuestring != NULL){
        os_strdup(json_field->valuestring, agt_info->version);
    }

    json_field = cJSON_GetObjectItem(json_agt_info->child, "config_sum");
    if(cJSON_IsString(json_field) && json_field->valuestring != NULL){
        os_strdup(json_field->valuestring, agt_info->config_sum);
    }

    json_field = cJSON_GetObjectItem(json_agt_info->child, "merged_sum");
    if(cJSON_IsString(json_field) && json_field->valuestring != NULL){
        os_strdup(json_field->valuestring, agt_info->merged_sum);
    }

    json_field = cJSON_GetObjectItem(json_agt_info->child, "last_keepalive");
    if(cJSON_IsNumber(json_field)){
        snprintf(keepalive_str, sizeof(keepalive_str), "%d", json_field->valueint);
        os_strdup(keepalive_str, agt_info->last_keepalive);
    }

    json_field = cJSON_GetObjectItem(json_agt_info->child, "connection_status");
    if (cJSON_IsString(json_field)) {
        if (0 == strcmp(json_field->valuestring, AGENT_CS_PENDING)) {
            agt_info->connection_status = GA_STATUS_PENDING;
        }
        else if (0 == strcmp(json_field->valuestring, AGENT_CS_ACTIVE)) {
            agt_info->connection_status = GA_STATUS_ACTIVE;
        }
        else if (0 == strcmp(json_field->valuestring, AGENT_CS_DISCONNECTED)) {
            agt_info->connection_status = GA_STATUS_NACTIVE;
        }
        else if (0 == strcmp(json_field->valuestring, AGENT_CS_NEVER_CONNECTED)) {
            agt_info->connection_status = GA_STATUS_NEVER;
        }
        else {
            agt_info->connection_status = GA_STATUS_UNKNOWN;
        }
    }

    _get_time_fim_scan(agent_id, agt_info);

    cJSON_Delete(json_agt_info);
    return (agt_info);
}
#endif

/* Gets the status of an agent, based on the  agent ID*/
agent_status_t get_agent_status(int agent_id){
    cJSON *json_agt_info = NULL;
    cJSON *json_field = NULL;
    agent_status_t status = GA_STATUS_UNKNOWN;

    json_agt_info = wdb_get_agent_info(agent_id, NULL);

    if (!json_agt_info) {
        mdebug1("Failed to get agent '%d' information from Wazuh DB.", agent_id);
        return status;
    }

    json_field = cJSON_GetObjectItem(json_agt_info->child, "connection_status");
    if (cJSON_IsString(json_field)) {
        if (0 == strcmp(json_field->valuestring, AGENT_CS_PENDING)) {
            status = GA_STATUS_PENDING;
        }
        else if (0 == strcmp(json_field->valuestring, AGENT_CS_ACTIVE)) {
            status = GA_STATUS_ACTIVE;
        }
        else if (0 == strcmp(json_field->valuestring, AGENT_CS_DISCONNECTED)) {
            status = GA_STATUS_NACTIVE;
        }
        else if (0 == strcmp(json_field->valuestring, AGENT_CS_NEVER_CONNECTED)) {
            status = GA_STATUS_NEVER;
        }
    }

    cJSON_Delete(json_agt_info);
    return status;
}

/* List available agents */
char **get_agents(int flag){
    size_t array_size = 0;
    char **agents_array = NULL;
    int *id_array = NULL;
    int i = 0;
    cJSON *json_agt_info = NULL;
    cJSON *json_field = NULL;
    cJSON *json_name = NULL;
    cJSON *json_ip = NULL;

    int sock = -1;
    id_array = wdb_get_all_agents(FALSE, &sock);

    if(!id_array){
        mdebug1("Failed getting agent's ID array.");
        wdbc_close(&sock);
        return (NULL);
    }

    for (i = 0; id_array[i] != -1; i++){
        agent_status_t status = GA_STATUS_UNKNOWN;
        char agent_name_ip[OS_SIZE_512] = "";

        json_agt_info = wdb_get_agent_info(id_array[i], &sock);
        if (!json_agt_info) {
            mdebug1("Failed to get agent '%d' information from Wazuh DB.", id_array[i]);
            continue;
        }

        json_name= cJSON_GetObjectItem(json_agt_info->child, "name");
        json_ip = cJSON_GetObjectItem(json_agt_info->child, "register_ip");

        /* Keeping the same name structure than plain text files in AGENTINFO_DIR */
        if(cJSON_IsString(json_name) && json_name->valuestring != NULL &&
            cJSON_IsString(json_ip) && json_ip->valuestring != NULL){
            snprintf(agent_name_ip, sizeof(agent_name_ip), "%s-%s", json_name->valuestring, json_ip->valuestring);
        }

        json_field = cJSON_GetObjectItem(json_agt_info->child, "connection_status");
        if(!cJSON_IsString(json_field)){
            cJSON_Delete(json_agt_info);
            continue;
        }

        status = !strcmp(json_field->valuestring, AGENT_CS_PENDING) ? GA_STATUS_PENDING :
                 !strcmp(json_field->valuestring, AGENT_CS_ACTIVE) ? GA_STATUS_ACTIVE :
                 !strcmp(json_field->valuestring, AGENT_CS_DISCONNECTED) ? GA_STATUS_NACTIVE :
                 !strcmp(json_field->valuestring, AGENT_CS_NEVER_CONNECTED) ? GA_STATUS_NEVER : GA_STATUS_UNKNOWN;
        cJSON_Delete(json_agt_info);

        switch (flag) {
            case GA_ALL:
            case GA_ALL_WSTATUS:
                break;
            case GA_ACTIVE:
                if(status != GA_STATUS_ACTIVE){
                    continue;
                }
                break;
            case GA_NOTACTIVE:
                if(status != GA_STATUS_NACTIVE){
                    continue;
                }
                break;
            default:
                mwarn("Invalid flag '%d' trying to get all agents.", flag);
                wdbc_close(&sock);
                os_free(id_array);
                return NULL;
        }

        os_realloc(agents_array, (array_size + 2) * sizeof(char *), agents_array);

        /* Add agent entry */
        if (flag == GA_ALL_WSTATUS) {
            char agt_stat[1024];
            snprintf(agt_stat, sizeof(agt_stat) - 1, "%s %s", agent_name_ip, print_agent_status(status));
            os_strdup(agt_stat, agents_array[array_size]);
        } else {
            os_strdup(agent_name_ip, agents_array[array_size]);
        }

        agents_array[array_size + 1] = NULL;
        array_size++;
    }

    wdbc_close(&sock);
    os_free(id_array);
    return (agents_array);
}

#ifndef WIN32
time_t scantime_fim (const char *agent_id, const char *scan) {
    char *wazuhdb_query = NULL;
    char *response = NULL;
    char *message;
    time_t ts = -1;
    int wdb_socket = -1;

    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);
    os_calloc(OS_SIZE_6144, sizeof(char), response);

    snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck scan_info_get %s",
            agent_id, scan
    );

    if (wdbc_query_ex(&wdb_socket, wazuhdb_query, response, OS_SIZE_6144) == 0) {
        if (wdbc_parse_result(response, &message) == WDBC_OK) {
            ts = atol(message);
            mdebug2("Agent '%s' FIM '%s' timestamp:'%ld'", agent_id, scan, (long int)ts);
        }
    }

    free(wazuhdb_query);
    free(response);
    return (ts);
}
#endif
