/*
 * Shared functions for Rootcheck events decoding
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysinfo_utils.h"
#include "sym_load.h"

bool w_sysinfo_init(w_sysinfo_helpers_t * sysinfo) {

    bool result = false;
    if (sysinfo != NULL) {
        sysinfo->module = so_get_module_handle("sysinfo");
        if (sysinfo->module != NULL) {
            sysinfo->processes = so_get_function_sym(sysinfo->module, "sysinfo_processes");
            sysinfo->os = so_get_function_sym(sysinfo->module, "sysinfo_os");
            sysinfo->free_result = so_get_function_sym(sysinfo->module, "sysinfo_free_result");
            if (sysinfo->processes != NULL && sysinfo->os != NULL && sysinfo->free_result != NULL) {
                result = true;
            } else {
                w_sysinfo_deinit(sysinfo);
            }
        }
    }

    return result;
}

bool w_sysinfo_deinit(w_sysinfo_helpers_t * sysinfo) {

    bool result = false;
    if (sysinfo != NULL) {
        so_free_library(sysinfo->module);
        sysinfo->module = NULL;
        sysinfo->processes = NULL;
        sysinfo->free_result = NULL;
        sysinfo->os = NULL;
        return true;
    }
    return result;
}

cJSON * w_sysinfo_get_processes(w_sysinfo_helpers_t * sysinfo) {

    cJSON * processes = NULL;

    if (sysinfo != NULL && sysinfo->processes != NULL) {
        sysinfo->processes(&processes);
    }
    return processes;
}

cJSON * w_sysinfo_get_os(w_sysinfo_helpers_t * sysinfo) {

    cJSON * os_info = NULL;

    if (sysinfo != NULL && sysinfo->os != NULL) {
        sysinfo->os(&os_info);
    }
    return os_info;
}

pid_t * w_get_process_childs(w_sysinfo_helpers_t * sysinfo, pid_t parent_pid, unsigned int max_count) {

    const unsigned int CHILDS_CHUNKS = 5;
    unsigned int childs_count = 0;
    cJSON * processes = NULL;
    cJSON * process = NULL;
    char * process_pid_str = NULL;
    pid_t * childs_list = NULL;
    pid_t process_pid = 0;
    processes = w_sysinfo_get_processes(sysinfo);
    if (processes != NULL) {
        cJSON_ArrayForEach(process, processes) {
            cJSON * ppid_object = cJSON_GetObjectItem(process, "ppid");
            if (cJSON_IsNumber(ppid_object) && (pid_t) ppid_object->valuedouble == parent_pid) {
                process_pid_str = cJSON_GetStringValue(cJSON_GetObjectItem(process, "pid"));
                if (process_pid_str != NULL) {
                    if (process_pid = (pid_t) strtol(process_pid_str, NULL, 10), process_pid > 0) {
                        if (childs_count % CHILDS_CHUNKS == 0) {
                            os_realloc(childs_list, sizeof(pid_t) * (childs_count + CHILDS_CHUNKS + 1), childs_list);
                            memset(childs_list + childs_count, 0, sizeof(pid_t) * (CHILDS_CHUNKS + 1));
                        }
                        childs_list[childs_count++] = process_pid;
                        if (max_count > 0 && childs_count == max_count) {
                            break;
                        }
                    }
                }
            }
        }
        sysinfo->free_result(&processes);
    }

    return childs_list;
}

char * w_get_os_codename(w_sysinfo_helpers_t * sysinfo) {

    char * codename = NULL;
    cJSON * os_info = NULL;

    os_info = w_sysinfo_get_os(sysinfo);

    if (os_info != NULL) {
        w_strdup(cJSON_GetStringValue(cJSON_GetObjectItem(os_info, "os_codename")), codename);
        sysinfo->free_result(&os_info);
    }

    return codename;
}
