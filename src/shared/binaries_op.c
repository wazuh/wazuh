/* Copyright (C) 2015, Wazuh Inc.
 * May, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

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
    char *save_ptr = NULL;

#ifdef WIN32
    if (IsFile(binary) == 0) {
#else
    if (binary[0] == '/') {
        // Check binary full path
        if (IsFile(binary) == -1) {
            return OS_INVALID;
        }
#endif
        validated = strdup(binary);

    } else {

        env_path = getenv("PATH");
        path = strtok_r(env_path, sep, &save_ptr);

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
            os_free(env_path);
            return OS_INVALID;
        }
    }

    if (validated_comm) {
        *validated_comm = strdup(validated);
    }

    os_free(validated);
    os_free(env_path);
    return OS_SUCCESS;
}
