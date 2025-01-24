/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "to_json.h"
#include "json_extended.h"
#include "shared.h"
#include "syscheck_op.h"
#include "rules.h"
#include "mitre.h"
#include "cJSON.h"
#include "config.h"
#include "wazuh_modules/wmodules.h"

#define is_win_permission(x) (strchr(x, '|'))
#define print_before_field(x, y) (x && *x && (!y || strcmp(x, y)))
void add_json_attrs(const char *attrs_str, cJSON *file_diff, char after);

/* Convert Eventinfo to json */
char* Eventinfo_to_jsonstr(const Eventinfo* lf, bool force_full_log, OSList * list_msg)
{
    cJSON* root;
    cJSON* rule = NULL;
    cJSON* file_diff = NULL;
    cJSON* manager;
    cJSON* agent;
    cJSON* predecoder;
    cJSON* data;
    cJSON* cluster;
    char manager_name[512];
    char* out;
    int i;
    char * saveptr;

    extern long int __crt_ftell;

    root = cJSON_CreateObject();

    // Parse timestamp
    W_JSON_AddTimestamp(root, lf);

    if(lf->generated_rule){
        cJSON_AddItemToObject(root, "rule", rule = cJSON_CreateObject());
    }
    cJSON_AddItemToObject(root, "agent", agent = cJSON_CreateObject());
    cJSON_AddItemToObject(root, "manager", manager = cJSON_CreateObject());
    data = cJSON_CreateObject();

    if ( lf->time.tv_sec ) {

        char alert_id[23];
        alert_id[22] = '\0';
        if((snprintf(alert_id, 22, "%ld.%ld", (long int)lf->time.tv_sec, __crt_ftell)) < 0) {
            merror("snprintf failed");
        }

        cJSON_AddStringToObject(root, "id", alert_id);
    }

    // Cluster information
    if (!Config.hide_cluster_info) {
        cJSON_AddItemToObject(root, "cluster", cluster = cJSON_CreateObject());
        if(Config.cluster_name)
            cJSON_AddStringToObject(cluster, "name", Config.cluster_name);
        else
            cJSON_AddStringToObject(cluster, "name", "wazuh");

        if(Config.node_name)
            cJSON_AddStringToObject(cluster, "node", Config.node_name);
    }

	/* Get manager hostname */
    memset(manager_name, '\0', 512);
    if (gethostname(manager_name, 512 - 1) != 0) {
        strncpy(manager_name, "localhost", 32);
    }
	cJSON_AddStringToObject(manager, "name", manager_name);

    if(lf->generated_rule){
        if(lf->generated_rule->level) {
            cJSON_AddNumberToObject(rule, "level", lf->generated_rule->level);
        }
        if(lf->comment) {
            cJSON_AddStringToObject(rule, "description", lf->comment);
        }
        if(lf->generated_rule->sigid) {
            char id[12];
            snprintf(id, 12, "%d", lf->generated_rule->sigid);
            cJSON_AddStringToObject(rule, "id", id);
        }
        if(lf->generated_rule->mitre_technique_id && lf->generated_rule->mitre_tactic_id) {
            cJSON * mitre = NULL;
            cJSON * element = NULL;
            int tactic_array_size;
            technique_data * data_technique = NULL;

            cJSON_AddItemToObject(rule, "mitre", mitre = cJSON_CreateObject());

            /* Creating id array */
            cJSON *mitre_id_array = cJSON_CreateArray();

            /* Creating names array */
            cJSON *mitre_technique_array = cJSON_CreateArray();

            /* Creating tactics array */
            cJSON *mitre_tactic_array = cJSON_CreateArray();

            for (i = 0; lf->generated_rule->mitre_technique_id[i] != NULL; i++) {
                if (data_technique = mitre_get_attack(lf->generated_rule->mitre_technique_id[i]), !data_technique) {
                    smwarn(list_msg, "Mitre Technique ID '%s' not found in database.", lf->generated_rule->mitre_technique_id[i]);
                } else {
                    OSListNode *tactic_node = OSList_GetFirstNode(data_technique->tactics_list);
                    bool tactic_exist = FALSE;
                    bool inarray = FALSE;

                    /* Filling tactic array */
                    while (tactic_node) {
                        tactic_data * data_tactic = (tactic_data *)tactic_node->data;

                        if (strcmp(data_tactic->tactic_id, lf->generated_rule->mitre_tactic_id[i]) == 0) {
                            tactic_exist = TRUE;
                            /* Check if the tactic is already in the array */
                            cJSON_ArrayForEach(element, mitre_tactic_array){
                                if (strcmp(element->valuestring, data_tactic->tactic_name) == 0) {
                                    inarray = TRUE;
                                    break;
                                }
                            }

                            if (!inarray) {
                                cJSON_AddItemToArray(mitre_tactic_array, cJSON_CreateString(data_tactic->tactic_name));
                                break;
                            }
                        }
                        tactic_node = OSList_GetNextNode(data_technique->tactics_list);
                    }

                    inarray = FALSE;
                    if(tactic_exist == TRUE) {
                        /* Check if the technique is already in the array */
                        cJSON_ArrayForEach(element, mitre_technique_array){
                            if (strcmp(element->valuestring, data_technique->technique_name) == 0) {
                                inarray = TRUE;
                            }
                        }
                        if (!inarray) {
                            cJSON_AddItemToArray(mitre_id_array, cJSON_CreateString(data_technique->technique_id));
                            cJSON_AddItemToArray(mitre_technique_array, cJSON_CreateString(data_technique->technique_name));
                        }
                    } else {
                        smwarn(list_msg, "Mitre Tactic ID '%s' is not a tactic of '%s'.",
                            lf->generated_rule->mitre_tactic_id[i],
                            lf->generated_rule->mitre_technique_id[i]);
                    }
                }
            }

            if (tactic_array_size = cJSON_GetArraySize(mitre_tactic_array), tactic_array_size > 0) {
                cJSON_AddItemToObject(mitre, "id", mitre_id_array);
                cJSON_AddItemToObject(mitre, "tactic", mitre_tactic_array);
                cJSON_AddItemToObject(mitre, "technique", mitre_technique_array);
            } else {
                cJSON_Delete(mitre_id_array);
                cJSON_Delete(mitre_tactic_array);
                cJSON_Delete(mitre_technique_array);
                cJSON_DeleteItemFromObject(rule, "mitre");
            }
        } else if(lf->generated_rule->mitre_id) {
            const char **mitre_cpy = (const char**)lf->generated_rule->mitre_id;
            cJSON * mitre = NULL;
            cJSON * element = NULL;
            int tactic_array_size;
            technique_data * data_technique = NULL;

            cJSON_AddItemToObject(rule, "mitre", mitre = cJSON_CreateObject());

            /* Creating id array */
            for (i = 0; lf->generated_rule->mitre_id[i] != NULL; i++);

            cJSON *mitre_id_array = cJSON_CreateStringArray(mitre_cpy, i);
            cJSON_AddItemToObject(mitre, "id", mitre_id_array);

            /* Creating tactics array */
            cJSON *mitre_tactic_array = cJSON_CreateArray();

            /* Creating names array */
            cJSON *mitre_technique_array = cJSON_CreateArray();

            for (i = 0; lf->generated_rule->mitre_id[i] != NULL; i++) {
                if (data_technique = mitre_get_attack(lf->generated_rule->mitre_id[i]), !data_technique) {
                    smwarn(list_msg, "Mitre Technique ID '%s' not found in database.", lf->generated_rule->mitre_id[i]);
                } else {
                    OSListNode *tactic_node = OSList_GetFirstNode(data_technique->tactics_list);

                    /* Filling tactic array */
                    while (tactic_node) {
                        bool inarray = FALSE;
                        tactic_data * data_tactic = (tactic_data *)tactic_node->data;

                        /* Check if the element is already in the array */
                        cJSON_ArrayForEach(element, mitre_tactic_array){
                            if (strcmp(element->valuestring, data_tactic->tactic_name) == 0) {
                                inarray = TRUE;
                            }
                        }
                        if (!inarray) {
                            cJSON_AddItemToArray(mitre_tactic_array, cJSON_CreateString(data_tactic->tactic_name));
                        }

                        tactic_node = OSList_GetNextNode(data_technique->tactics_list);
                    }

                    /* Filling technique array */
                    cJSON_AddItemToArray(mitre_technique_array, cJSON_CreateString(data_technique->technique_name));
                }
            }

            if (tactic_array_size = cJSON_GetArraySize(mitre_tactic_array), tactic_array_size > 0) {
                cJSON_AddItemToObject(mitre, "tactic", mitre_tactic_array);
                cJSON_AddItemToObject(mitre, "technique", mitre_technique_array);
            } else {
                cJSON_Delete(mitre_tactic_array);
                cJSON_Delete(mitre_technique_array);
                cJSON_DeleteItemFromObject(rule, "mitre");
            }
        }
        if(lf->generated_rule->cve) {
            cJSON_AddStringToObject(rule, "cve", lf->generated_rule->cve);
        }
        if(lf->generated_rule->info) {
            cJSON_AddStringToObject(rule, "info", lf->generated_rule->info);
        }
        if(lf->generated_rule->event_search){
            cJSON_AddNumberToObject(rule, "frequency", lf->generated_rule->frequency + 2);
        }
        if(lf->r_firedtimes != -1 && !(lf->generated_rule->alert_opts & NO_COUNTER)) {
            cJSON_AddNumberToObject(rule, "firedtimes", lf->r_firedtimes);
        }
        cJSON_AddItemToObject(rule, "mail", cJSON_CreateBool(lf->generated_rule->alert_opts & DO_MAILALERT));

        char *previous_events = NULL;
        if (lf->last_events && lf->last_events[0]) {
            char **lasts = lf->last_events;
            while (*lasts) {
                wm_strcat(&previous_events, *lasts, '\n');
                lasts++;
            }
        }

        if (lf->last_events && lf->last_events[0] && lf->last_events[1] && *lf->last_events[1] != '\0' && (lf->generated_rule && lf->generated_rule->alert_opts & NO_PREVIOUS_OUTPUT)) {
            cJSON_AddStringToObject(root, "previous_output", previous_events);
        }
        os_free(previous_events);
    }

    if(lf->protocol) {
        cJSON_AddStringToObject(data, "protocol", lf->protocol);
    }
    if(lf->action) {
        cJSON_AddStringToObject(data, "action", lf->action);
    }
    if(lf->srcip) {
        cJSON_AddStringToObject(data, "srcip", lf->srcip);
    }
    #ifdef LIBGEOIP_ENABLED
    if (lf->srcgeoip && Config.geoip_jsonout) {
        cJSON_AddStringToObject(root, "srcgeoip", lf->srcgeoip);
    }
    #endif
    if (lf->srcport) {
        cJSON_AddStringToObject(data, "srcport", lf->srcport);
    }
    if(lf->srcuser) {
        cJSON_AddStringToObject(data, "srcuser", lf->srcuser);
    }
    if(lf->dstip) {
        cJSON_AddStringToObject(data, "dstip", lf->dstip);
    }
    #ifdef LIBGEOIP_ENABLED
    if (lf->dstgeoip && Config.geoip_jsonout) {
        cJSON_AddStringToObject(root, "dstgeoip", lf->dstgeoip);
    }
    #endif
    if (lf->dstport) {
        cJSON_AddStringToObject(data, "dstport", lf->dstport);
    }
    if(lf->dstuser) {
        cJSON_AddStringToObject(data, "dstuser", lf->dstuser);
    }
    if(lf->full_log && (force_full_log || !(lf->generated_rule && lf->generated_rule->alert_opts & NO_FULL_LOG))) {
        cJSON_AddStringToObject(root, "full_log", lf->full_log);
    }
    if (lf->agent_id) {
        cJSON_AddStringToObject(agent, "id", lf->agent_id);
    }

    if (lf->decoder_info->name != NULL && strncmp(lf->decoder_info->name, "syscheck_", 9) == 0) {
        char mtime[25];
        struct tm tm_result = { .tm_sec = 0 };
        long aux_time;

        file_diff = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "syscheck", file_diff);
        cJSON_AddStringToObject(file_diff, "path", lf->fields[FIM_FILE].value);

        if (lf->fields[FIM_HARD_LINKS].value && *lf->fields[FIM_HARD_LINKS].value) {
            cJSON_AddItemToObject(file_diff, "hard_links", cJSON_Parse(lf->fields[FIM_HARD_LINKS].value));
        }

        if (lf->fields[FIM_MODE].value) {
            cJSON_AddStringToObject(file_diff, "mode", lf->fields[FIM_MODE].value);
        }

        if (lf->fields[FIM_SYM_PATH].value && *lf->fields[FIM_SYM_PATH].value) {
            cJSON_AddStringToObject(file_diff, "symbolic_path", lf->fields[FIM_SYM_PATH].value);
        }

        if (lf->fields[FIM_REGISTRY_ARCH].value) {
            cJSON_AddStringToObject(file_diff, "arch", lf->fields[FIM_REGISTRY_ARCH].value);
        }

        if (lf->fields[FIM_REGISTRY_VALUE_NAME].value) {
            cJSON_AddStringToObject(file_diff, "value_name", lf->fields[FIM_REGISTRY_VALUE_NAME].value);
        }

        if (lf->fields[FIM_REGISTRY_VALUE_TYPE].value) {
            cJSON_AddStringToObject(file_diff, "value_type", lf->fields[FIM_REGISTRY_VALUE_TYPE].value);
        }

        if (print_before_field(lf->fields[FIM_SIZE_BEFORE].value, lf->fields[FIM_SIZE].value)) {
            cJSON_AddStringToObject(file_diff, "size_before", lf->fields[FIM_SIZE_BEFORE].value);
        }
        if (lf->fields[FIM_SIZE].value && *lf->fields[FIM_SIZE].value) {
            cJSON_AddStringToObject(file_diff, "size_after", lf->fields[FIM_SIZE].value);
        }

        if (print_before_field(lf->fields[FIM_PERM_BEFORE].value, lf->fields[FIM_PERM].value)) {
            if (is_win_permission(lf->fields[FIM_PERM_BEFORE].value)) {
                cJSON *old_perm;
                if (old_perm = win_perm_to_json(lf->fields[FIM_PERM_BEFORE].value), old_perm) {
                    cJSON_AddItemToObject(file_diff, "win_perm_before", old_perm);
                } else {
                    smwarn(list_msg, "The old permissions of the Windows event could not be added to the JSON alert.");
                }
            } else {
                cJSON_AddStringToObject(file_diff, "perm_before", lf->fields[FIM_PERM_BEFORE].value);
            }
        }
        if (lf->fields[FIM_PERM].value && *lf->fields[FIM_PERM].value) {
            if (is_win_permission(lf->fields[FIM_PERM].value)) {
                cJSON *new_perm;
                if (new_perm = win_perm_to_json(lf->fields[FIM_PERM].value), new_perm) {
                    cJSON_AddItemToObject(file_diff, "win_perm_after", new_perm);
                } else {
                   smerror(list_msg, "The new permissions could not be added to the JSON alert.");
                }
            } else {
                cJSON_AddStringToObject(file_diff, "perm_after", lf->fields[FIM_PERM].value);
            }
        }

        if (print_before_field(lf->fields[FIM_UID_BEFORE].value, lf->fields[FIM_UID].value)) {
            cJSON_AddStringToObject(file_diff, "uid_before", lf->fields[FIM_UID_BEFORE].value);
        }
        if (lf->fields[FIM_UID].value && *lf->fields[FIM_UID].value) {
            cJSON_AddStringToObject(file_diff, "uid_after", lf->fields[FIM_UID].value);
        }

        if (print_before_field(lf->fields[FIM_GID_BEFORE].value, lf->fields[FIM_GID].value)) {
            cJSON_AddStringToObject(file_diff, "gid_before", lf->fields[FIM_GID_BEFORE].value);
        }
        if (lf->fields[FIM_GID].value && *lf->fields[FIM_GID].value) {
            cJSON_AddStringToObject(file_diff, "gid_after", lf->fields[FIM_GID].value);
        }

        if (print_before_field(lf->fields[FIM_MD5_BEFORE].value, lf->fields[FIM_MD5].value)) {
            cJSON_AddStringToObject(file_diff, "md5_before", lf->fields[FIM_MD5_BEFORE].value);
        }
        if (lf->fields[FIM_MD5].value && *lf->fields[FIM_MD5].value) {
            cJSON_AddStringToObject(file_diff, "md5_after", lf->fields[FIM_MD5].value);
        }

        if (print_before_field(lf->fields[FIM_SHA1_BEFORE].value, lf->fields[FIM_SHA1].value)) {
            cJSON_AddStringToObject(file_diff, "sha1_before", lf->fields[FIM_SHA1_BEFORE].value);
        }
        if (lf->fields[FIM_SHA1].value && *lf->fields[FIM_SHA1].value) {
            cJSON_AddStringToObject(file_diff, "sha1_after", lf->fields[FIM_SHA1].value);
        }

        if (print_before_field(lf->fields[FIM_SHA256_BEFORE].value, lf->fields[FIM_SHA256].value)) {
            cJSON_AddStringToObject(file_diff, "sha256_before", lf->fields[FIM_SHA256_BEFORE].value);
        }
        if (lf->fields[FIM_SHA256].value && *lf->fields[FIM_SHA256].value) {
            cJSON_AddStringToObject(file_diff, "sha256_after", lf->fields[FIM_SHA256].value);
        }

        if (print_before_field(lf->fields[FIM_ATTRS_BEFORE].value, lf->fields[FIM_ATTRS].value)) {
            add_json_attrs(lf->fields[FIM_ATTRS_BEFORE].value, file_diff, 0);
        }
        if (lf->fields[FIM_ATTRS].value) {
            add_json_attrs(lf->fields[FIM_ATTRS].value, file_diff, 1);
        }

        if (print_before_field(lf->fields[FIM_UNAME_BEFORE].value, lf->fields[FIM_UNAME].value)) {
            cJSON_AddStringToObject(file_diff, "uname_before", lf->fields[FIM_UNAME_BEFORE].value);
        }
        if (lf->fields[FIM_UNAME].value && *lf->fields[FIM_UNAME].value) {
            cJSON_AddStringToObject(file_diff, "uname_after", lf->fields[FIM_UNAME].value);
        }

        if (print_before_field(lf->fields[FIM_GNAME_BEFORE].value, lf->fields[FIM_GNAME].value)) {
            cJSON_AddStringToObject(file_diff, "gname_before", lf->fields[FIM_GNAME_BEFORE].value);
        }
        if(lf->fields[FIM_GNAME].value && *lf->fields[FIM_GNAME].value) {
            cJSON_AddStringToObject(file_diff, "gname_after", lf->fields[FIM_GNAME].value);
        }

        if (print_before_field(lf->fields[FIM_MTIME_BEFORE].value, lf->fields[FIM_MTIME].value)) {
            aux_time = atol(lf->fields[FIM_MTIME_BEFORE].value);
            strftime(mtime, 20, "%FT%T%z", localtime_r(&aux_time, &tm_result));
            cJSON_AddStringToObject(file_diff, "mtime_before", mtime);
        }
        if (lf->fields[FIM_MTIME].value && *lf->fields[FIM_MTIME].value) {
            aux_time = atol(lf->fields[FIM_MTIME].value);
            strftime(mtime, 20, "%FT%T%z", localtime_r(&aux_time, &tm_result));
            cJSON_AddStringToObject(file_diff, "mtime_after", mtime);
        }

        if (print_before_field(lf->fields[FIM_INODE_BEFORE].value, lf->fields[FIM_INODE].value)) {
            cJSON_AddNumberToObject(file_diff, "inode_before", atoi(lf->fields[FIM_INODE_BEFORE].value));
        }
        if (lf->fields[FIM_INODE].value && atoi(lf->fields[FIM_INODE].value)) {
            cJSON_AddNumberToObject(file_diff, "inode_after", atoi(lf->fields[FIM_INODE].value));
        }

        if(Config.decoder_order_size > FIM_DIFF && lf->fields[FIM_DIFF].value && strcmp(lf->fields[FIM_DIFF].value, "0")) {
            cJSON_AddStringToObject(file_diff, "diff", lf->fields[FIM_DIFF].value);
        }

        if(lf->fields[FIM_TAG].value && *lf->fields[FIM_TAG].value != '\0') {
            cJSON *tags = cJSON_CreateArray();
            cJSON_AddItemToObject(file_diff, "tags", tags);
            char * tag;
            char * aux_tags;
            os_strdup(lf->fields[FIM_TAG].value, aux_tags);
            tag = strtok_r(aux_tags, ",", &saveptr);
            while (tag != NULL) {
                cJSON_AddItemToArray(tags, cJSON_CreateString(tag));
                tag = strtok_r(NULL, ",", &saveptr);
            }
            free(aux_tags);
        }

        if (lf->fields[FIM_CHFIELDS].value && strcmp(lf->fields[FIM_CHFIELDS].value, "") != 0) {
            cJSON *changed_attributes = cJSON_CreateArray();
            cJSON_AddItemToObject(file_diff, "changed_attributes", changed_attributes);
            char * changed;
            char * aux_cha;
            os_strdup(lf->fields[FIM_CHFIELDS].value, aux_cha);
            changed = strtok_r(aux_cha, ",", &saveptr);
            while (changed != NULL) {
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString(changed));
                changed = strtok_r(NULL, ",", &saveptr);
            }

            free(aux_cha);
        }

        cJSON_AddStringToObject(file_diff, "event", lf->fields[FIM_EVENT_TYPE].value);
    }

    if (lf->program_name || lf->dec_timestamp) {
        cJSON_AddItemToObject(root, "predecoder", predecoder = cJSON_CreateObject());

        if (lf->program_name) {
            cJSON_AddStringToObject(predecoder, "program_name", lf->program_name);
        }

        if (lf->dec_timestamp) {
            cJSON_AddStringToObject(predecoder, "timestamp", lf->dec_timestamp);
        }
    }

    if(lf->id)
        cJSON_AddStringToObject(data, "id", lf->id);

    if(lf->status)
        cJSON_AddStringToObject(data, "status", lf->status);

    if(lf->url)
        cJSON_AddStringToObject(data, "url", lf->url);

    if(lf->data)
        cJSON_AddStringToObject(data, "data", lf->data);

    if(lf->extra_data)
        cJSON_AddStringToObject(data, "extra_data", lf->extra_data);

    if(lf->systemname)
        cJSON_AddStringToObject(data, "system_name", lf->systemname);

    // Whodata fields
    if (file_diff) {
        cJSON* audit_sect = NULL;
        cJSON* process_sect = NULL;
        cJSON* user_sect = NULL;
        cJSON* group_sect = NULL;
        cJSON* auser_sect = NULL;
        cJSON* euser_sect = NULL;

        // User section
        add_json_field(user_sect, "id", lf->fields[FIM_USER_ID].value, "");
        add_json_field(user_sect, "name", lf->fields[FIM_USER_NAME].value, "");

        // Group sect
        add_json_field(group_sect, "id", lf->fields[FIM_GROUP_ID].value, "");
        add_json_field(group_sect, "name", lf->fields[FIM_GROUP_NAME].value, "");

        // Process section
        add_json_field(process_sect, "id", lf->fields[FIM_PROC_ID].value, "");
        add_json_field(process_sect, "name", lf->fields[FIM_PROC_NAME].value, "");
        add_json_field(process_sect, "cwd", lf->fields[FIM_AUDIT_CWD].value, "");
        add_json_field(process_sect, "parent_name", lf->fields[FIM_PROC_PNAME].value, "");
        add_json_field(process_sect, "parent_cwd", lf->fields[FIM_AUDIT_PCWD].value, "");
        add_json_field(process_sect, "ppid", lf->fields[FIM_PPID].value, "");

        // Auser sect
        add_json_field(auser_sect, "id", lf->fields[FIM_AUDIT_ID].value, "");
        add_json_field(auser_sect, "name", lf->fields[FIM_AUDIT_NAME].value, "");

        // Effective user
        add_json_field(euser_sect, "id", lf->fields[FIM_EFFECTIVE_UID].value, "");
        add_json_field(euser_sect, "name", lf->fields[FIM_EFFECTIVE_NAME].value, "");

        if (user_sect || process_sect || group_sect || auser_sect || euser_sect) {
            audit_sect = cJSON_CreateObject();
            if (user_sect) {
                cJSON_AddItemToObject(audit_sect, "user", user_sect);
            }
            if (process_sect) {
                cJSON_AddItemToObject(audit_sect, "process", process_sect);
            }
            if (group_sect) {
                cJSON_AddItemToObject(audit_sect, "group", group_sect);
            }
            if (auser_sect) {
                cJSON_AddItemToObject(audit_sect, "login_user", auser_sect);
            }
            if (euser_sect) {
                cJSON_AddItemToObject(audit_sect, "effective_user", euser_sect);
            }
            cJSON_AddItemToObject(file_diff, "audit", audit_sect);
        }
    }

    // DecoderInfo
    if(lf->decoder_info) {

        cJSON* decoder;

        // Dynamic fields, except for syscheck events
        if (lf->decoder_info->name != NULL && strncmp(lf->decoder_info->name, "syscheck_", 9) != 0) {
            for (i = 0; i < lf->nfields; i++) {
                if (lf->fields[i].value != NULL && *lf->fields[i].value != '\0') {
                    W_JSON_AddField(data, lf->fields[i].key, lf->fields[i].value);
                }
            }
        }

        cJSON_AddItemToObject(root, "decoder", decoder = cJSON_CreateObject());

        if(lf->decoder_info->accumulate)
            cJSON_AddNumberToObject(decoder, "accumulate", lf->decoder_info->accumulate);

        if(lf->decoder_info->parent)
            cJSON_AddStringToObject(decoder, "parent", lf->decoder_info->parent);

        if(lf->decoder_info->name)
            cJSON_AddStringToObject(decoder, "name", lf->decoder_info->name);

        if(lf->decoder_info->ftscomment)
            cJSON_AddStringToObject(decoder, "ftscomment", lf->decoder_info->ftscomment);
    }

    if (lf->previous)
        cJSON_AddStringToObject(root, "previous_log", lf->previous);

    // Insert data object only if it has children

    if (data->child) {
        cJSON_AddItemToObject(root, "data", data);
    } else {
        cJSON_Delete(data);
    }

    W_ParseJSON(root, lf);
    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

void add_json_attrs(const char *attrs_str, cJSON *file_diff, char after) {
    if (!attrs_str || !*attrs_str) {
        return;
    }

    cJSON *attrs = attrs_to_json(attrs_str);
    if (attrs) {
        cJSON_AddItemToObject(file_diff,
                                after ? "attrs_after" : "attrs_before",
                                attrs);
    } else {
        merror("The %s file attributes could not be added to the JSON alert.",
                after ? "new" : "before");
    }
}
