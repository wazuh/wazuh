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

#include "wazuh_db/wdb.h"
#include "wazuh_modules/wmodules.h"

/**
 * Check if agent version is valid to upgrade to a non-customized version
 * @param agent_version Wazuh version of agent to validate
 * @param agent_info pointer to agent_info struture
 * @param task pointer to wm_upgrade_task with the params
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_VERSION_SAME_MANAGER
 * @retval WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT
 * @retval WM_UPGRADE_NEW_VERSION_GREATER_MASTER)
 * @retval WM_UPGRADE_GLOBAL_DB_FAILURE
 * */
static int wm_agent_upgrade_validate_non_custom_version(const char *agent_version, const wm_agent_info *agent_info, wm_upgrade_task *task);

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
static int wm_agent_upgrade_validate_system(const char *platform, const char *os_major, const char *os_minor, const char *arch);

/**
 * Check if a WPK exist for the upgrade version
 * @param agent_info structure with the agent information
 * @param task structure with the task information
 * @param wpk_version version to validate
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_URL_NOT_FOUND
 * @retval WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST
 * */
static int wm_agent_upgrade_validate_wpk_version(const wm_agent_info *agent_info, wm_upgrade_task *task, char *wpk_version);

/**
 * Compare two versions with format v4.0.0
 * @param version1 char * with the string version
 * @param version2 char * with the string version
 * @return return_code
 * @retval 0 equals
 * @retval 1 version1 > version2
 * @retval -1 version1 < version2
 * */
static int wm_agent_upgrade_compare_versions(const char *version1, const char *version2);

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

int wm_agent_upgrade_validate_version(const wm_agent_info *agent_info, void *task, wm_upgrade_command command) {
    char *tmp_agent_version = NULL;
    int return_code = WM_UPGRADE_GLOBAL_DB_FAILURE;

    if (agent_info->wazuh_version) {
        if (tmp_agent_version = strchr(agent_info->wazuh_version, 'v'), tmp_agent_version) {
            return_code = WM_UPGRADE_SUCCESS;

            if (wm_agent_upgrade_compare_versions(tmp_agent_version, WM_UPGRADE_MINIMAL_VERSION_SUPPORT) < 0) {
                return_code = WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED;
            } else if (WM_UPGRADE_UPGRADE == command) {
                task = (wm_upgrade_task *)task;
                return_code = wm_agent_upgrade_validate_non_custom_version(tmp_agent_version, agent_info, task);
            }
        }
    }

    return return_code;
}

int wm_agent_upgrade_validate_wpk(const void *task, wm_upgrade_command command) {
    int return_code = WM_UPGRADE_SUCCESS;
    wm_upgrade_task *upgrade = NULL;
    wm_upgrade_custom_task *upgrade_custom = NULL;
    FILE *wpk_file = NULL;

    switch (command) {
    case WM_UPGRADE_UPGRADE:
        upgrade = (wm_upgrade_task*)task;
        int exist = 0;
        int attempts = 0;
        int req = 0;
        char *file_url = NULL;
        char *file_path = NULL;
        os_sha1 sha1;

        if (upgrade->wpk_repository && upgrade->wpk_file) {
            os_calloc(OS_SIZE_4096, sizeof(char), file_url);
            os_calloc(OS_SIZE_4096, sizeof(char), file_path);

            snprintf(file_url, OS_SIZE_4096, "%s%s", upgrade->wpk_repository, upgrade->wpk_file);
            snprintf(file_path, OS_SIZE_4096, "%s%s", WM_UPGRADE_WPK_DEFAULT_PATH, upgrade->wpk_file);

            if (wpk_file = fopen(file_path, "rb"), wpk_file) {
                if (!OS_SHA1_File(file_path, sha1, OS_BINARY) && !strcasecmp(sha1, upgrade->wpk_sha1)) {
                    // WPK already downloaded
                    exist = 1;
                }
                fclose(wpk_file);
            }

            if (!exist) {
                mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_DOWNLOADING_WPK, file_url);

                // Download WPK file
                for (attempts = 0;; attempts++) {
                    if (req = wurl_request(file_url, file_path, NULL, NULL, WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT), !req) {
                        if (OS_SHA1_File(file_path, sha1, OS_BINARY) || strcasecmp(sha1, upgrade->wpk_sha1)) {
                            return_code = WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH;
                        }
                        break;
                    } else if (attempts == WM_UPGRADE_WPK_DOWNLOAD_ATTEMPTS) {
                        return_code = WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST;
                    }
                    sleep(attempts);
                }
            }

            os_free(file_url);
            os_free(file_path);

        } else {
            return_code = WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST;
        }

        break;
    case WM_UPGRADE_UPGRADE_CUSTOM:
        upgrade_custom = (wm_upgrade_custom_task*)task;

        if (upgrade_custom->custom_file_path) {
            if (wpk_file = fopen(upgrade_custom->custom_file_path, "rb"), !wpk_file) {
                return_code = WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST;
            } else {
                // WPK file exists
                fclose(wpk_file);
            }
        } else {
            return_code = WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST;
        }

        break;
    default:
        return_code = WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST;
        break;
    }

    return return_code;
}

int wm_agent_upgrade_validate_non_custom_version(const char *agent_version, const wm_agent_info *agent_info, wm_upgrade_task *task) {
    char *manager_version = NULL;
    char *tmp_manager_version = NULL;
    int return_code = WM_UPGRADE_GLOBAL_DB_FAILURE;

    return_code = wm_agent_upgrade_validate_system(agent_info->platform, agent_info->major_version, agent_info->minor_version, agent_info->architecture);

    if (WM_UPGRADE_SUCCESS == return_code) {
        if (manager_version = wdb_agent_version(MANAGER_ID), manager_version) {
            if (tmp_manager_version = strchr(manager_version, 'v'), tmp_manager_version) {
                char *wpk_version = task->custom_version ? task->custom_version : tmp_manager_version;

                // Check if a WPK package exist for the upgrade version
                return_code = wm_agent_upgrade_validate_wpk_version(agent_info, task, wpk_version);

                if (WM_UPGRADE_SUCCESS == return_code) {
                    if (wm_agent_upgrade_compare_versions(agent_version, wpk_version) >= 0 && task->force_upgrade == false) {
                        return_code = WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT;
                    } else if (wm_agent_upgrade_compare_versions(wpk_version, tmp_manager_version) > 0 && task->force_upgrade == false) {
                        return_code = WM_UPGRADE_NEW_VERSION_GREATER_MASTER;
                    } else if (wm_agent_upgrade_compare_versions(agent_version, tmp_manager_version) == 0 && task->force_upgrade == false) {
                        return_code = WM_UPGRADE_VERSION_SAME_MANAGER;
                    }
                }
            }

            os_free(manager_version);
        }
    }

    return return_code;
}

int wm_agent_upgrade_validate_system(const char *platform, const char *os_major, const char *os_minor, const char *arch) {
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

int wm_agent_upgrade_validate_wpk_version(const wm_agent_info *agent_info, wm_upgrade_task *task, char *wpk_version) {
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
        os_strdup(WM_UPGRADE_WPK_REPO_URL, task->wpk_repository);
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
    strncat(repository_url, task->wpk_repository, OS_SIZE_1024);
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

    if (versions = wurl_http_get(versions_url), versions) {
        char *version = versions;
        char *sha1 = NULL;
        char *next_line = NULL;

        while (next_line = strchr(version, '\n'), next_line) {
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
    int patch1;
    int major1;
    int minor1;
    int patch2;
    int major2;
    int minor2;
    int result = 0;

    strcpy(ver1, version1);
    strcpy(ver2, version2);

    tmp_v1 = strchr(ver1, 'v');
    tmp_v2 = strchr(ver2, 'v');
    tmp_v1++;
    tmp_v2++;

    major1 = atoi(strtok(tmp_v1, "."));
    minor1 = atoi(strtok(NULL, "."));
    patch1 = atoi(strtok(NULL, "."));

    major2 = atoi(strtok(tmp_v2, "."));
    minor2 = atoi(strtok(NULL, "."));
    patch2 = atoi(strtok(NULL, "."));
    
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
