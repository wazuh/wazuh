/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include "registry.h"
#include "shared.h"
#include "../syscheck.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#include <openssl/evp.h>

#ifdef WAZUH_UNIT_TESTING
#include "unit_tests/wrappers/windows/winreg_wrappers.h"
#endif

/* Default values */
#define MAX_KEY_LENGTH 260
#define MAX_KEY 2048
#define MAX_VALUE_NAME 16383

/* Global variables */
static int _base_line = 0;

/* Check if the registry entry is valid */
int fim_set_root_key(HKEY *root_key_handle, const char *full_key, const char **sub_key) {
    int root_key_length;

    if (root_key_handle == NULL || full_key == NULL || sub_key == NULL) {
        return -1;
    }

    /* Verify valid root tree */
    if (strncmp(full_key, "HKEY_LOCAL_MACHINE", 18) == 0) {
        *root_key_handle = HKEY_LOCAL_MACHINE;
        root_key_length = 18;
    } else if (strncmp(full_key, "HKEY_CLASSES_ROOT", 17) == 0) {
        *root_key_handle = HKEY_CLASSES_ROOT;
        root_key_length = 17;
    } else if (strncmp(full_key, "HKEY_CURRENT_CONFIG", 19) == 0) {
        *root_key_handle = HKEY_CURRENT_CONFIG;
        root_key_length = 19;
    } else if (strncmp(full_key, "HKEY_USERS", 10) == 0) {
        *root_key_handle = HKEY_USERS;
        root_key_length = 10;
    } else {
        return -1;
    }

    if (full_key[root_key_length] != '\\') {
        root_key_handle = NULL;
        return -1;
    }

    *sub_key = &full_key[root_key_length + 1];
    return 0;
}

registry *fim_registry_configuration(const char *key, int arch) {
    int it = 0;
    int top = 0;
    int match;
    registry *ret = NULL;

    for (it = 0; syscheck.registry[it].entry; it++) {
        if (arch != syscheck.registry[it].arch) {
            continue;
        }

        match = w_compare_str(syscheck.registry[it].entry, key);

        if (top < match) {
            ret = &syscheck.registry[it];
            top = match;
        }
    }

    if (ret == NULL) {
        mdebug2(FIM_CONFIGURATION_NOTFOUND, "registry", key);
    }

    return ret;
}

fim_registry_key *fim_registry_get_key_data(HKEY key_handle, const char *path, const registry *configuration) {
    return NULL;
}


int fim_registry_validate_path(const char *entry_path, const registry *configuration) {
    int ign_it;
    const char *pos;
    int depth = -1;
    unsigned int parent_path_size;

    if (entry_path == NULL || configuration == NULL) {
        return -1;
    }

    /* Verify recursion level */
    parent_path_size = strlen(configuration->entry);

    if (parent_path_size > strlen(entry_path)) {
        return -1;
    }

    pos = entry_path + parent_path_size;
    while (pos = strchr(pos, PATH_SEP), pos) {
        depth++;
        pos++;
    }

    if (depth > configuration->recursion_level) {
        return -1;
    }

    /* Registry ignore list */
    if (syscheck.registry_ignore) {
        for (ign_it = 0; syscheck.registry_ignore[ign_it].entry; ign_it++) {
            if (syscheck.registry_ignore[ign_it].arch != configuration->arch) {
                continue;
            }

            if (strcasecmp(syscheck.registry_ignore[ign_it].entry, entry_path) == 0) {
                mdebug2(FIM_IGNORE_ENTRY, "registry", entry_path, syscheck.registry_ignore[ign_it].entry);
                return -1;
            }
        }
    }

    if (syscheck.registry_ignore_regex) {
        for (ign_it = 0; syscheck.registry_ignore_regex[ign_it].regex; ign_it++) {
            if (syscheck.registry_ignore_regex[ign_it].arch != configuration->arch) {
                continue;
            }

            if (OSMatch_Execute(entry_path, strlen(entry_path), syscheck.registry_ignore_regex[ign_it].regex)) {
                mdebug2(FIM_IGNORE_SREGEX, "registry", entry_path, syscheck.registry_ignore_regex[ign_it].regex->raw);
                return -1;
            }
        }
    }

    return 0;
}

void fim_registry_process_unscanned_entries() {
    fim_tmp_file *file;

    if (fim_db_get_registry_keys_not_scanned(syscheck.database, &file, syscheck.database_store)) {
        mwarn("Failed to get unscanned registry keys");
    }


}

/* Query the key and get all its values */
void fim_read_values(HKEY key_handle, fim_entry *new, fim_entry *saved, const registry *configuration, DWORD value_count) {
    DWORD i;

    /* Variables for RegEnumValue */
    TCHAR value_buffer[MAX_VALUE_NAME + 1];
    BYTE data_buffer[MAX_VALUE_NAME + 1];
    DWORD value_size;
    DWORD data_size;

    /* Data type for RegEnumValue */
    DWORD data_type = 0;

    fim_registry_value_data value_data;

    // char *mt_data;

    // EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    // EVP_DigestInit(ctx, EVP_sha1());

    /* Clear the values for value_size and data_size */
    value_buffer[MAX_VALUE_NAME] = '\0';
    data_buffer[MAX_VALUE_NAME] = '\0';

    new->registry_entry.value = &value_data;

    for (i = 0; i < value_count; i++) {
        char *diff = NULL;
        char value_path[MAX_KEY + 2];
        registry *value_configuration;
        cJSON *json_event;

        value_size = MAX_VALUE_NAME;
        data_size = MAX_VALUE_NAME;

        value_buffer[0] = '\0';
        data_buffer[0] = '\0';

        /* No more values available */
        if (RegEnumValue(key_handle, i, value_buffer, &value_size, NULL, &data_type, data_buffer, &data_size) != ERROR_SUCCESS) {
            break;
        }

        /* Check if no value name is specified */
        if (value_buffer[0] == '\0') {
            value_buffer[0] = '@';
            value_buffer[1] = '\0';
        }

        snprintf(value_path, MAX_KEY, "%s\\%s", new->registry_entry.key->path, value_buffer);

        value_configuration = fim_registry_configuration(value_path, configuration->arch);
        if (value_configuration == NULL) {
            mwarn("No configuration found for '%s'", value_path);
            continue;
        }

        if (fim_registry_validate_path(value_path, configuration)) {
            continue;
        }

        if (fim_check_restrict(value_path, configuration->filerestrict)) {
            continue;
        }

        new->registry_entry.value->name = value_buffer;
        new->registry_entry.value->type = data_type;
        new->registry_entry.value->size = data_size;
        new->registry_entry.value->mode = FIM_SCHEDULED;

        saved->registry_entry.value =
        fim_db_get_registry_data(syscheck.database, new->registry_entry.key->id, new->registry_entry.value->name);

        if (value_configuration->opts | CHECK_SEECHANGES) {
            diff = fim_registry_value_diff(new->registry_entry.key->path, new->registry_entry.value->name, data_buffer, data_type);
        }

        json_event = fim_registry_event(new, saved, value_configuration, FIM_SCHEDULED,
                                        saved->registry_entry.value == NULL ? FIM_ADD : FIM_MODIFIED, NULL, diff);

        os_free(diff);

        fim_db_set_registry_data_scanned(syscheck.database, new->registry_entry.value->name, new->registry_entry.key->id);

        if (json_event) {
            if (fim_db_insert_registry(syscheck.database, new) != 0) {
                mwarn("Couldn't insert into DB");
            }

            if (_base_line) {
                char *json_formated = cJSON_PrintUnformatted(json_event);
                send_syscheck_msg(json_formated);
                os_free(json_formated);
            }

            cJSON_Delete(json_event);
        }

        /* Write value name and data in the file (for checksum later) */
        // EVP_DigestUpdate(ctx, value_buffer, strlen(value_buffer));
        // switch (data_type) {
        // case REG_SZ:
        // case REG_EXPAND_SZ:
        //     EVP_DigestUpdate(ctx, data_buffer, strlen(data_buffer));
        //     break;
        // case REG_MULTI_SZ:
        //     /* Print multiple strings */
        //     mt_data = data_buffer;

        //     while (*mt_data) {
        //         EVP_DigestUpdate(ctx, mt_data, strlen(mt_data));
        //         mt_data += strlen(mt_data) + 1;
        //     }
        //     break;
        // case REG_DWORD:
        //     snprintf(buffer, OS_SIZE_2048, "%08x", *((unsigned int *)data_buffer));
        //     EVP_DigestUpdate(ctx, buffer, strlen(buffer));
        //     buffer[0] = '\0';
        //     break;
        // default:
        //     for (j = 0; j < data_size; j++) {
        //         snprintf(buffer, 3, "%02x", (unsigned int)data_buffer[j] & 0xFF);
        //         EVP_DigestUpdate(ctx, buffer, strlen(buffer));
        //         buffer[0] = '\0';
        //     }
        //     break;
        // }

        // free_entry_data(data);
    }
}

/* Open the registry key */
void fim_open_key(HKEY root_key_handle, const char *full_key, const char *sub_key, const registry *configuration) {
    HKEY current_key_handle = NULL;
    REGSAM access_rights;
    DWORD sub_key_count = 0;
    DWORD value_count;
    FILETIME file_time = { 0 };
    DWORD i;
    fim_entry new, saved;

    if (root_key_handle == NULL || full_key == NULL || sub_key == NULL || configuration == NULL) {
        return;
    }

    // Check ignore and recursion level restrictions.
    if (fim_registry_validate_path(full_key, configuration)) {
        return;
    }

    access_rights = KEY_READ | (configuration->arch == ARCH_32BIT ? KEY_WOW64_32KEY : KEY_WOW64_64KEY);

    if (RegOpenKeyEx(root_key_handle, sub_key, 0, access_rights, &current_key_handle) != ERROR_SUCCESS) {
        mdebug1(FIM_REG_OPEN, sub_key, configuration->arch == ARCH_32BIT ? "[x32]" : "[x64]");
        return;
    }

    /* We use the class_name, sub_key_count and the value count */
    if (RegQueryInfoKey(current_key_handle, NULL, NULL, NULL, &sub_key_count, NULL, NULL, &value_count, NULL, NULL,
                        NULL, &file_time) != ERROR_SUCCESS) {
        return;
    }

    /* Query each sub_key and call open_key */
    for (i = 0; i < sub_key_count; i++) {
        char new_full_key[MAX_KEY + 2];
        char *new_sub_key;
        registry *new_configuration;
        TCHAR sub_key_name_b[MAX_KEY_LENGTH + 1];
        DWORD sub_key_name_s = MAX_KEY_LENGTH;

        if (RegEnumKeyEx(current_key_handle, i, sub_key_name_b, &sub_key_name_s, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            continue;
        }

        snprintf(new_full_key, MAX_KEY, "%s\\%s", full_key, sub_key_name_b);

        new_configuration = fim_registry_configuration(new_full_key, configuration->arch);
        if (new_configuration == NULL) {
            mwarn("No configuration found for '%s'", new_full_key);
            continue;
        }

        if (new_sub_key = strchr(new_full_key, '\\'), new_sub_key) {
            new_sub_key++;
        }

        /* Open sub_key */
        fim_open_key(root_key_handle, new_full_key, new_sub_key, new_configuration);
    }

    // Done scanning sub_keys, trigger an alert on the current key if required.
    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = fim_registry_get_key_data(current_key_handle, full_key, configuration);
    new.registry_entry.value = NULL;

    saved.type = FIM_TYPE_REGISTRY;
    saved.registry_entry.key = fim_db_get_registry_key(syscheck.database, full_key);
    saved.registry_entry.value = NULL;

    if (!fim_check_restrict(full_key, configuration->filerestrict)) {
        cJSON *json_event = fim_registry_event(&new, &saved, configuration, FIM_SCHEDULED,
                                               saved.registry_entry.key == NULL ? FIM_ADD : FIM_MODIFIED, NULL, NULL);

        fim_db_set_registry_key_scanned(syscheck.database, full_key);

        if (json_event) {
            if (fim_db_insert_registry(syscheck.database, &new) != 0) {
                mwarn("Couldn't insert into DB");
            }

            if (_base_line) {
                char *json_formated = cJSON_PrintUnformatted(json_event);
                send_syscheck_msg(json_formated);
                os_free(json_formated);
            }

            cJSON_Delete(json_event);
        }
    }

    if (value_count) {
        fim_read_values(current_key_handle, &new, &saved, configuration, value_count);
    }

    RegCloseKey(current_key_handle);
    return;
}

void fim_registry_scan() {
    HKEY root_key_handle = NULL;
    const char *sub_key = NULL;
    int i = 0;

    /* Debug entries */
    mdebug1(FIM_WINREGISTRY_START);

    fim_db_set_all_registry_data_unscanned(syscheck.database);
    fim_db_set_all_registry_key_unscanned(syscheck.database);

    /* Get sub class and a valid registry entry */
    for (i = 0; syscheck.registry[i].entry; i++) {
        /* Ignored entries are zeroed */
        if (*syscheck.registry[i].entry == '\0') {
            continue;
        }

        /* Read syscheck registry entry */
        mdebug2(FIM_READING_REGISTRY, syscheck.registry[i].arch == ARCH_64BIT ? "[x64] " : "[x32] ",
                syscheck.registry[i].entry);

        if (fim_set_root_key(&root_key_handle, syscheck.registry[i].entry, &sub_key) != 0) {
            mdebug1(FIM_INV_REG, syscheck.registry[i].entry, syscheck.registry[i].arch == ARCH_64BIT ? "[x64] " : "[x32]");
            *syscheck.registry[i].entry = '\0';
            continue;
        }

        fim_open_key(root_key_handle, syscheck.registry[i].entry, sub_key, &syscheck.registry[i]);
    }

    fim_registry_process_unscanned_entries();

    mdebug1(FIM_WINREGISTRY_ENDED);

    if (_base_line == 0) {
        _base_line = 1;
    }

    return;
}
