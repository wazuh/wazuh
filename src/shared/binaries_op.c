/* Copyright (C) 2015, Wazuh Inc.
 * May, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"


#ifdef WAZUH_UNIT_TESTING
#ifdef WIN32
#define getenv wrap_getenv
#endif
#endif

int get_binary_path(const char *binary, char **validated_comm) {
#ifdef WIN32
    const char sep[2] = ";";
#else
    const char sep[2] = ":";
#endif
    char *path;
    char *full_path;
    char *validated = NULL;
    char *env_path = NULL;
    char *env_path_copy = NULL;
    char *save_ptr = NULL;

    if (isabspath(binary)) {
        // Check binary full path
        if (IsFile(binary) == -1) {
            if (validated_comm) {
                *validated_comm = strdup(binary);
            }
            return OS_INVALID;
        }
        validated = strdup(binary);

    } else {

        env_path = getenv("PATH");

        if (!env_path) {
            if (validated_comm) {
                *validated_comm = strdup(binary);
            }
            return OS_INVALID;
        }
        os_strdup(env_path, env_path_copy);
        path = strtok_r(env_path_copy, sep, &save_ptr);

        while (path != NULL) {
            os_calloc(strlen(path) + strlen(binary) + 2, sizeof(char), full_path);
#ifdef WIN32
            snprintf(full_path, strlen(path) + strlen(binary) + 2, "%s\\%s", path, binary);
#else
            snprintf(full_path, strlen(path) + strlen(binary) + 2, "%s/%s", path, binary);
#endif
            if (IsFile(full_path) == 0) {
                validated = strdup(full_path);
                os_free(full_path);
                break;
            }
            os_free(full_path);
            path = strtok_r(NULL, sep, &save_ptr);
        }

        // Check binary found
        if (validated == NULL) {
            if (validated_comm) {
                *validated_comm = strdup(binary);
            }
            os_free(env_path_copy);
            return OS_INVALID;
        }
    }

    if (validated_comm) {
        *validated_comm = strdup(validated);
    }
    os_free(validated);
    os_free(env_path_copy);
    return OS_SUCCESS;
}
