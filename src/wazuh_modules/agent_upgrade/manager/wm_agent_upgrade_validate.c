/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 20, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#include "wazuh_db/wdb.h"
#include "wazuh_modules/wmodules.h"
#include "wm_agent_upgrade_validate.h"

#ifdef WAZUH_UNIT_TESTING
// Redefine ossec_version
#undef __ossec_version
#define __ossec_version "v3.13.0"
#endif

// Mutex needed to download a WPK file
pthread_mutex_t download_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Check if agent version is valid to upgrade to a non-customized version
 * @param agent_version Wazuh version of agent to validate
 * @param agent_info pointer to agent_info struture
 * @param task pointer to wm_upgrade_task with the params
 * @param manager_configs manager configuration parameters
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT
 * @retval WM_UPGRADE_NEW_VERSION_GREATER_MASTER
 * @retval WM_UPGRADE_GLOBAL_DB_FAILURE
 * */
STATIC int wm_agent_upgrade_validate_non_custom_version(const char *agent_version, const wm_agent_info *agent_info, wm_upgrade_task *task, const wm_manager_configs* manager_configs) __attribute__((nonnull));

/**
 * Check if WPK exists for this agent
 * @param platform platform of agent to validate
 * @param os_major OS major version of agent to validate
 * @param os_minor OS minor version of agent to validate
 * @param arch architecture of agent to validate
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_SYSTEM_NOT_SUPPORTED
 * @retval WM_UPGRADE_GLOBAL_DB_FAILURE
 * */
STATIC int wm_agent_upgrade_validate_system(const char *platform, const char *os_major, const char *os_minor, const char *arch);

/**
 * Check if a WPK exist for the upgrade version
 * @param agent_info structure with the agent information
 * @param task structure with the task information
 * @param wpk_version version to validate
 * @param wpk_repository_config char pointer with the repository url set in module config
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_URL_NOT_FOUND
 * @retval WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST
 * */
STATIC int wm_agent_upgrade_validate_wpk_version(const wm_agent_info *agent_info, wm_upgrade_task *task, char *wpk_version, const char *wpk_repository_config) __attribute__((nonnull(1, 2, 3)));

static const char* invalid_platforms[] = {
    "darwin",
    "solaris",
    "aix",
    "hpux",
    "bsd"
};

int wm_agent_upgrade_validate_id(int agent_id) {
    int return_code = WM_UPGRADE_SUCCESS;

    if (agent_id == MANAGER_ID) {
        return_code = WM_UPGRADE_INVALID_ACTION_FOR_MANAGER;
    }

    return return_code;
}

int wm_agent_upgrade_validate_status(int last_keep_alive) {
    int return_code = WM_UPGRADE_SUCCESS;

    if (last_keep_alive < 0 || last_keep_alive < (time(0) - DISCON_TIME)) {
        return_code = WM_UPGRADE_AGENT_IS_NOT_ACTIVE;
    }

    return return_code;
}

int wm_agent_upgrade_validate_version(const wm_agent_info *agent_info, void *task, wm_upgrade_command command, const wm_manager_configs* manager_configs) {
    char *tmp_agent_version = NULL;
    int return_code = WM_UPGRADE_GLOBAL_DB_FAILURE;

    if (agent_info->wazuh_version) {
        if (tmp_agent_version = strchr(agent_info->wazuh_version, 'v'), tmp_agent_version) {
            return_code = WM_UPGRADE_SUCCESS;

            if (wm_agent_upgrade_compare_versions(tmp_agent_version, WM_UPGRADE_MINIMAL_VERSION_SUPPORT) < 0) {
                return_code = WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED;
            } else if (WM_UPGRADE_UPGRADE == command) {
                return_code = wm_agent_upgrade_validate_non_custom_version(tmp_agent_version, agent_info, (wm_upgrade_task *)task, manager_configs);
            }
        }
    }

    return return_code;
}

int wm_agent_upgrade_validate_wpk(const wm_upgrade_task *task) {
    int return_code = WM_UPGRADE_SUCCESS;
    FILE *wpk_file = NULL;
    int exist = 0;
    int attempts = 0;
    int req = 0;
    char *file_url = NULL;
    char *file_path = NULL;
    os_sha1 file_sha1;

    if (task && task->wpk_repository && task->wpk_file && task->wpk_sha1) {

        // Take mutex to avoid downloading many times the same WPK
        w_mutex_lock(&download_mutex);

        os_calloc(OS_SIZE_4096, sizeof(char), file_url);
        os_calloc(OS_SIZE_4096, sizeof(char), file_path);

        snprintf(file_url, OS_SIZE_4096, "%s%s", task->wpk_repository, task->wpk_file);
        snprintf(file_path, OS_SIZE_4096, "%s%s", WM_UPGRADE_WPK_DEFAULT_PATH, task->wpk_file);

        if (wpk_file = fopen(file_path, "rb"), wpk_file) {
            if (!OS_SHA1_File(file_path, file_sha1, OS_BINARY) && !strcasecmp(file_sha1, task->wpk_sha1)) {
                // WPK already downloaded
                exist = 1;
            }
            fclose(wpk_file);
        }

        if (!exist) {
            mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_DOWNLOADING_WPK, file_url);

            // Download WPK file
            while (attempts++ < WM_UPGRADE_WPK_DOWNLOAD_ATTEMPTS) {
                if (req = wurl_request(file_url, file_path, NULL, NULL, WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT), !req) {
                    if (OS_SHA1_File(file_path, file_sha1, OS_BINARY) || strcasecmp(file_sha1, task->wpk_sha1)) {
                        return_code = WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH;
                    }
                    break;
                } else if (attempts == WM_UPGRADE_WPK_DOWNLOAD_ATTEMPTS) {
                    return_code = WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST;
                    break;
                }
                sleep(attempts);
            }
        }

        os_free(file_url);
        os_free(file_path);

        // Release download mutex
        w_mutex_unlock(&download_mutex);

    } else {
        return_code = WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST;
    }

    return return_code;
}

int wm_agent_upgrade_validate_wpk_custom(const wm_upgrade_custom_task *task) {
    int return_code = WM_UPGRADE_SUCCESS;
    FILE *wpk_file = NULL;

    if (task && task->custom_file_path) {
        if (wpk_file = fopen(task->custom_file_path, "rb"), !wpk_file) {
            return_code = WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST;
        } else {
            // WPK file exists
            fclose(wpk_file);
        }
    } else {
        return_code = WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST;
    }

    return return_code;
}

STATIC int wm_agent_upgrade_validate_non_custom_version(const char *agent_version, const wm_agent_info *agent_info, wm_upgrade_task *task, const wm_manager_configs* manager_configs) {
    char *manager_version = NULL;
    int return_code = WM_UPGRADE_GLOBAL_DB_FAILURE;

    return_code = wm_agent_upgrade_validate_system(agent_info->platform, agent_info->major_version, agent_info->minor_version, agent_info->architecture);

    if (WM_UPGRADE_SUCCESS == return_code) {
        if (manager_version = strchr(__ossec_version, 'v'), manager_version) {
            char *wpk_version = task->custom_version ? task->custom_version : manager_version;

            // Check if a WPK package exist for the upgrade version
            return_code = wm_agent_upgrade_validate_wpk_version(agent_info, task, wpk_version, manager_configs->wpk_repository);

            if (WM_UPGRADE_SUCCESS == return_code && !task->force_upgrade) {
                if (wm_agent_upgrade_compare_versions(agent_version, wpk_version) >= 0) {
                    return_code = WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT;
                } else if (wm_agent_upgrade_compare_versions(wpk_version, manager_version) > 0) {
                    return_code = WM_UPGRADE_NEW_VERSION_GREATER_MASTER;
                }
            }
        }
    }

    return return_code;
}

STATIC int wm_agent_upgrade_validate_system(const char *platform, const char *os_major, const char *os_minor, const char *arch) {
    int invalid_platforms_len = 0;
    int invalid_platforms_it = 0;
    int return_code = WM_UPGRADE_GLOBAL_DB_FAILURE;

    if (platform) {
        if (!strcmp(platform, "windows") || (os_major && arch && (strcmp(platform, "ubuntu") || os_minor))) {
            return_code = WM_UPGRADE_SUCCESS;
            invalid_platforms_len = sizeof(invalid_platforms) / sizeof(invalid_platforms[0]);

            for(invalid_platforms_it = 0; invalid_platforms_it < invalid_platforms_len; ++invalid_platforms_it) {
                if(!strcmp(invalid_platforms[invalid_platforms_it], platform)) {
                    return_code = WM_UPGRADE_SYSTEM_NOT_SUPPORTED;
                    break;
                }
            }

            if (WM_UPGRADE_SUCCESS == return_code) {
                if ((!strcmp(platform, "sles") && !strcmp(os_major, "11")) ||
                    (!strcmp(platform, "rhel") && !strcmp(os_major, "5")) ||
                    (!strcmp(platform, "centos") && !strcmp(os_major, "5"))) {
                    return_code = WM_UPGRADE_SYSTEM_NOT_SUPPORTED;
                }
            }
        }
    }

    return return_code;
}

STATIC int wm_agent_upgrade_validate_wpk_version(const wm_agent_info *agent_info, wm_upgrade_task *task, char *wpk_version, const char *wpk_repository_config) {
    const char *http_tag = "http://";
    const char *https_tag = "https://";
    char *repository_url = NULL;
    char *path_url = NULL;
    char *file_url = NULL;
    char *versions_url = NULL;
    char *versions = NULL;
    int return_code = WM_UPGRADE_SUCCESS;

    os_calloc(OS_SIZE_1024, sizeof(char), repository_url);
    os_calloc(OS_SIZE_2048, sizeof(char), path_url);
    os_calloc(OS_SIZE_2048, sizeof(char), file_url);
    os_calloc(OS_SIZE_4096, sizeof(char), versions_url);

    if (!task->wpk_repository) {
        if (wpk_repository_config) {
            os_strdup(wpk_repository_config, task->wpk_repository);
        } else if (wm_agent_upgrade_compare_versions(wpk_version, "v4.0.0") < 0) {
            os_strdup(WM_UPGRADE_WPK_REPO_URL_3_X, task->wpk_repository);
        } else {
            os_strdup(WM_UPGRADE_WPK_REPO_URL_4_X, task->wpk_repository);
        }
    }

    // Set protocol
    if (!strstr(task->wpk_repository, http_tag) && !strstr(task->wpk_repository, https_tag)) {
        if (task->use_http) {
            strcat(repository_url, http_tag);
        } else {
            strcat(repository_url, https_tag);
        }
    }

    // Set repository
    strncat(repository_url, task->wpk_repository, OS_SIZE_512);
    if (task->wpk_repository[strlen(task->wpk_repository) - 1] != '/') {
        strcat(repository_url, "/");
    }

    // Set URL path
    if (!strcmp(agent_info->platform, "windows")) {
        snprintf(path_url, OS_SIZE_2048, "%swindows/",
                 repository_url);
        snprintf(file_url, OS_SIZE_2048, "wazuh_agent_%s_windows.wpk",
                 wpk_version);
    } else {
        if (wm_agent_upgrade_compare_versions(wpk_version, WM_UPGRADE_NEW_VERSION_REPOSITORY) >= 0) {
            snprintf(path_url, OS_SIZE_2048, "%slinux/%s/",
                     repository_url, agent_info->architecture);
            snprintf(file_url, OS_SIZE_2048, "wazuh_agent_%s_linux_%s.wpk",
                     wpk_version, agent_info->architecture);
        } else if (!strcmp(agent_info->platform, "ubuntu")) {
            snprintf(path_url, OS_SIZE_2048, "%s%s/%s.%s/%s/",
                     repository_url, agent_info->platform, agent_info->major_version, agent_info->minor_version, agent_info->architecture);
            snprintf(file_url, OS_SIZE_2048, "wazuh_agent_%s_%s_%s.%s_%s.wpk",
                     wpk_version, agent_info->platform, agent_info->major_version, agent_info->minor_version, agent_info->architecture);
        } else {
            snprintf(path_url, OS_SIZE_2048, "%s%s/%s/%s/",
                     repository_url, agent_info->platform, agent_info->major_version, agent_info->architecture);
            snprintf(file_url, OS_SIZE_2048, "wazuh_agent_%s_%s_%s_%s.wpk",
                     wpk_version, agent_info->platform, agent_info->major_version, agent_info->architecture);
        }
    }

    // Set versions respository
    snprintf(versions_url, OS_SIZE_4096, "%sversions", path_url);

    versions = wurl_http_get(versions_url);

    if (versions) {
        char *version = versions;
        char *sha1 = NULL;
        char *next_line = NULL;

        while (version) {
            if (next_line = strchr(version, '\n'), next_line) {
                *next_line = '\0';
                if (sha1 = strchr(version, ' '), sha1) {
                    *sha1 = '\0';
                    if (wm_agent_upgrade_compare_versions(wpk_version, version) == 0) {
                        // Save WPK url, file name and sha1
                        os_strdup(sha1 + 1, task->wpk_sha1);
                        os_strdup(file_url, task->wpk_file);
                        os_free(task->wpk_repository);
                        os_strdup(path_url, task->wpk_repository);
                        break;
                    }
                }
                version = next_line + 1;
            } else {
                break;
            }
        }
        if (version) {
            if (sha1 = strchr(version, ' '), sha1) {
                *sha1 = '\0';
                if (wm_agent_upgrade_compare_versions(wpk_version, version) == 0) {
                    // Save WPK url, file name and sha1
                    os_strdup(sha1 + 1, task->wpk_sha1);
                    os_strdup(file_url, task->wpk_file);
                    os_free(task->wpk_repository);
                    os_strdup(path_url, task->wpk_repository);
                }
            }
        }
        if (!task->wpk_repository || !task->wpk_file || !task->wpk_sha1) {
            return_code = WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST;
        }
    } else {
        return_code = WM_UPGRADE_URL_NOT_FOUND;
    }

    os_free(repository_url);
    os_free(path_url);
    os_free(file_url);
    os_free(versions_url);
    os_free(versions);

    return return_code;
}

int wm_agent_upgrade_compare_versions(const char *version1, const char *version2) {
    char ver1[10];
    char ver2[10];
    char *tmp_v1 = NULL;
    char *tmp_v2 = NULL;
    char *token = NULL;
    int patch1 = 0;
    int major1 = 0;
    int minor1 = 0;
    int patch2 = 0;
    int major2 = 0;
    int minor2 = 0;
    int result = 0;

    if (version1) {
        strncpy(ver1, version1, 9);

        if (tmp_v1 = strchr(ver1, 'v'), tmp_v1) {
            tmp_v1++;
        } else {
            tmp_v1 = ver1;
        }

        if (token = strtok(tmp_v1, "."), token) {
            major1 = atoi(token);

            if (token = strtok(NULL, "."), token) {
                minor1 = atoi(token);

                if (token = strtok(NULL, "."), token) {
                    patch1 = atoi(token);
                }
            }
        }
    }

    if (version2) {
        strncpy(ver2, version2, 9);

        if (tmp_v2 = strchr(ver2, 'v'), tmp_v2) {
            tmp_v2++;
        } else {
            tmp_v2 = ver2;
        }

        if (token = strtok(tmp_v2, "."), token) {
            major2 = atoi(token);

            if (token = strtok(NULL, "."), token) {
                minor2 = atoi(token);

                if (token = strtok(NULL, "."), token) {
                    patch2 = atoi(token);
                }
            }
        }
    }

    if (major1 > major2) {
        result = 1;
    } else if (major1 < major2){
        result = -1;
    } else {
        if(minor1 > minor2) {
            result = 1;
        } else if (minor1 < minor2) {
            result = -1;
        } else {
            if (patch1 > patch2) {
                result = 1;
            } else if (patch1 < patch2) {
                result = -1;
            } else {
                result = 0;
            }
        }
    }

    return result;
}

bool wm_agent_upgrade_validate_task_status_message(const cJSON *input_json, char **status, int *agent_id) {
    if (input_json) {
        cJSON *error_object = cJSON_GetObjectItem(input_json, task_manager_json_keys[WM_TASK_ERROR]);
        cJSON *data_object = cJSON_GetObjectItem(input_json, task_manager_json_keys[WM_TASK_ERROR_MESSAGE]);
        cJSON *status_object = cJSON_GetObjectItem(input_json, task_manager_json_keys[WM_TASK_STATUS]);
        cJSON *agent_json = cJSON_GetObjectItem(input_json, task_manager_json_keys[WM_TASK_AGENT_ID]);
        
        if (error_object && (error_object->type == cJSON_Number) && data_object && (data_object->type == cJSON_String) && agent_json
            && (agent_json->type == cJSON_Number)) {
            
            if (agent_id) {
                *agent_id = agent_json->valueint;
            }
            
            if (error_object->valueint == WM_UPGRADE_SUCCESS) {
                if (status && status_object && status_object->type == cJSON_String) {
                    os_strdup(status_object->valuestring, *status);
                }
                return true;
            } else {
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_TASK_UPDATE_ERROR, error_object->valueint, data_object->valuestring);
            }
        } else {
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_REQUIRED_PARAMETERS);
        }
    }
    return false;
}

bool wm_agent_upgrade_validate_task_ids_message(const cJSON *input_json, int *agent_id, int *task_id, char** data) {
    if (input_json) {
        cJSON *agent_json = cJSON_GetObjectItem(input_json, task_manager_json_keys[WM_TASK_AGENT_ID]);
        cJSON *data_json = cJSON_GetObjectItem(input_json, task_manager_json_keys[WM_TASK_ERROR_MESSAGE]);
        cJSON *task_json = cJSON_GetObjectItem(input_json, task_manager_json_keys[WM_TASK_TASK_ID]);

        if (agent_id && agent_json && (agent_json->type == cJSON_Number)) {
            *agent_id = agent_json->valueint;
        } else {
            return false;
        }

        if (data && data_json && (data_json->type == cJSON_String)) {
            os_strdup(data_json->valuestring, *data);
        } else {
            return false;
        }

        if (task_id && task_json && (task_json->type == cJSON_Number)) {
            *task_id = task_json->valueint;
        }
        return true;
    }
    return false;
}
