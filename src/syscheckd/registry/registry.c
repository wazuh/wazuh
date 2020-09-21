/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include "registry.h"
#include "shared.h"
#include "../syscheck.h"
#include "../db/fim_db.h"
#include "../db/fim_db_registries.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#include <openssl/evp.h>

#ifdef WAZUH_UNIT_TESTING
#include "unit_tests/wrappers/windows/winreg_wrappers.h"

// Remove static qualifier when unit testing
#define static
#endif

/* Default values */
#define MAX_KEY_LENGTH 260
#define MAX_KEY 2048
#define MAX_VALUE_NAME 16383

/* Global variables */
static int _base_line = 0;

/**
 * @brief Set the root key and subkey associated with a given key.
 *
 * @param root_key_handle A pointer to a handle which will hold the root key handle on success, NULL on failure.
 * @param full_key A string holding the full path to a registry key.
 * @param sub_key A pointer to a pointer which will point to the byte where the first sub key of full_key starts,
 * unchanged on error.
 * @return 0 if the root key is properly set, -1 otherwise.
 */
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
        *root_key_handle = NULL;
        return -1;
    }

    if (full_key[root_key_length] != '\\') {
        *root_key_handle = NULL;
        return -1;
    }

    *sub_key = &full_key[root_key_length + 1];
    return 0;
}

/**
 * @brief Retrieves the configuration associated with a given registry element.
 *
 * @param key A string holding the full path to the registry element.
 * @param arch An integer specifying the bit count of the register element, must be ARCH_32BIT or ARCH_64BIT.
 * @return A pointer to the associated registry configuration, NULL on error or if no valid configuration was found.
 */
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

/**
 * @brief Validates a registry path against recursion level and ignore restrictions.
 *
 * @param entry_path A string holding the full path to be validated.
 * @param configuration The configuration associated with the registry entry.
 * @return 0 if the path is valid, -1 if the path is to be excluded.
 */
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
        mdebug2(FIM_MAX_RECURSION_LEVEL, depth, configuration->recursion_level, entry_path);
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

/**
 * @brief Gets all information from a given registry key.
 *
 * @param key_handle A handle to the key whose information we want.
 * @param path A string holding the full path to the key we want to query.
 * @param configuration The confguration associated with the key.
 * @return A fim_registry_key object holding the information from the queried key, NULL on error.
 */
fim_registry_key *fim_registry_get_key_data(HKEY key_handle, const char *path, const registry *configuration) {
    fim_registry_key *key;

    os_calloc(1, sizeof(fim_registry_key), key);

    if (configuration->opts & CHECK_OWNER) {
        key->user_name = get_user(path, &key->uid, key_handle, FIM_TYPE_REGISTRY);
    }

    if (configuration->opts & CHECK_GROUP) {
        key->group_name = get_registry_group(path, &key->gid, key_handle);
    }

    return key;
}

/**
 * @brief Free all memory associated with a registry key.
 *
 * @param data A fim_registry_key object to be free'd.
 */
void fim_registry_free_key(fim_registry_key *key) {
    if (key) {
        os_free(key->path);
        os_free(key->perm);
        os_free(key->uid);
        os_free(key->gid);
        os_free(key->user_name);
        os_free(key->group_name);
        free(key);
    }
}

/**
 * @brief Free all memory associated with a registry value.
 *
 * @param data A fim_registry_value_data object to be free'd.
 */
void fim_registry_free_value_data(fim_registry_value_data *data) {
    if (data) {
        os_free(data->name);
        free(data);
    }
}

/**
 * @brief Process and trigger delete events for a given registry value.
 *
 * @param fim_sql An object holding all information corresponding to the FIM DB.
 * @param data A fim_entry object holding the deleted value information retrieved from the FIM DB.
 * @param mutex A mutex to be locked before operating on the registry tables from the FIM DB.
 * @param _alert A pointer to an integer specifying if an alert should be generated.
 * @param _ev_mode A value specifying if the event has been triggered in scheduled, realtime or whodata mode.
 * @param _w_evt A whodata object holding information corresponding to the event.
 */
void fim_registry_process_value_delete_event(fdb_t *fim_sql,
                                             fim_entry *data,
                                             __attribute__((unused)) pthread_mutex_t *mutex,
                                             void *_alert,
                                             void *_ev_mode,
                                             __attribute__((unused)) void *_w_evt) {
    int alert = *(int *)_alert;
    fim_event_mode event_mode = *(fim_event_mode *)_ev_mode;
    registry *configuration;
    char full_path[MAX_KEY];

    snprintf(full_path, MAX_KEY, "%s\\%s", data->registry_entry.key->path, data->registry_entry.value->name);

    configuration = fim_registry_configuration(full_path, data->registry_entry.key->arch);
    if (configuration == NULL) {
        return;
    }

    if (alert) {
        cJSON *json_event = fim_registry_event(data, NULL, configuration, event_mode, FIM_DELETE, NULL, NULL);

        if (json_event) {
            char *json_formated = cJSON_PrintUnformatted(json_event);
            send_syscheck_msg(json_formated);
            os_free(json_formated);

            cJSON_Delete(json_event);
        }
    }

    fim_db_remove_registry_value_data(fim_sql, data->registry_entry.value);

    if (configuration->opts | CHECK_SEECHANGES) {
        fim_diff_process_delete_value(data->registry_entry.key->path, data->registry_entry.value->name,
                                      data->registry_entry.key->arch);
    }
}

/**
 * @brief Process and trigger delete events for a given registry key.
 *
 * @param fim_sql An object holding all information corresponding to the FIM DB.
 * @param data A fim_entry object holding the deleted key information retrieved from the FIM DB.
 * @param mutex A mutex to be locked before operating on the registry tables from the FIM DB.
 * @param _alert A pointer to an integer specifying if an alert should be generated.
 * @param _ev_mode A value specifying if the event has been triggered in scheduled, realtime or whodata mode.
 * @param _w_evt A whodata object holding information corresponding to the event.
 */
void fim_registry_process_key_delete_event(fdb_t *fim_sql,
                                           fim_entry *data,
                                           pthread_mutex_t *mutex,
                                           void *_alert,
                                           void *_ev_mode,
                                           void *_w_evt) {
    int alert = *(int *)_alert;
    fim_event_mode event_mode = *(fim_event_mode *)_ev_mode;
    fim_tmp_file *file;
    registry *configuration;

    configuration = fim_registry_configuration(data->registry_entry.key->path, data->registry_entry.key->arch);
    if (configuration == NULL) {
        return;
    }

    if (alert) {
        cJSON *json_event = fim_registry_event(data, NULL, configuration, event_mode, FIM_DELETE, NULL, NULL);

        if (json_event) {
            char *json_formated = cJSON_PrintUnformatted(json_event);
            send_syscheck_msg(json_formated);
            os_free(json_formated);

            cJSON_Delete(json_event);
        }
    }

    if (fim_db_get_values_from_registry_key(fim_sql, &file, FIM_DB_DISK, data->registry_entry.key->id) == FIMDB_OK) {
        if (file && file->elements) {
            fim_db_process_read_registry_data_file(fim_sql, file, mutex, fim_registry_process_value_delete_event,
                                                   FIM_DB_DISK, _alert, _ev_mode, _w_evt);
        }
    }

    fim_db_remove_registry_key(fim_sql, data);

    if (configuration->opts | CHECK_SEECHANGES) {
        fim_diff_process_delete_registry(data->registry_entry.key->path, data->registry_entry.key->arch);
    }
}

/**
 * @brief Process and trigger delete events for all unscanned registry elements.
 */
void fim_registry_process_unscanned_entries() {
    fim_tmp_file *file;
    fim_event_mode event_mode = FIM_SCHEDULED;

    if (fim_db_get_registry_keys_not_scanned(syscheck.database, &file, FIM_DB_DISK) == FIMDB_OK) {
        if (file && file->elements) {
            fim_db_process_read_file(syscheck.database, file, FIM_TYPE_REGISTRY, &syscheck.fim_registry_mutex,
                                     fim_registry_process_key_delete_event, FIM_DB_DISK, &_base_line, &event_mode,
                                     NULL);
        }
    } else {
        mwarn(FIM_REGISTRY_UNSCANNED_KEYS_FAIL);
    }

    if (fim_db_get_registry_data_not_scanned(syscheck.database, &file, FIM_DB_DISK) == FIMDB_OK) {
        if (file && file->elements) {
            fim_db_process_read_registry_data_file(syscheck.database, file, &syscheck.fim_registry_mutex,
                                                   fim_registry_process_value_delete_event, FIM_DB_DISK, &_base_line,
                                                   &event_mode, NULL);
        }
    } else {
        mwarn(FIM_REGISTRY_UNSCANNED_VALUE_FAIL);
    }
}

/**
 * @brief Generate and send value event
 *
 * @param new A fim_entry object holding the information gathered from the key and value.
 * @param saved A fim_entry object holding the information from the key and value retrieved from the database.
 * @param arch An integer specifying the bit count of the register to scan, must be ARCH_32BIT or ARCH_64BIT.
 * @param mode A value specifying if the event has been triggered in scheduled, realtime or whodata mode.
 * @param data_buffer A pointer to the raw data buffer contained in the value.
 */
void fim_registry_process_value_event(fim_entry *new,
                                      fim_entry *saved,
                                      int arch,
                                      fim_event_mode mode,
                                      BYTE *data_buffer) {
    char value_path[MAX_KEY + 2];
    registry *configuration;
    cJSON *json_event;
    char *diff = NULL;

    snprintf(value_path, MAX_KEY, "%s\\%s", new->registry_entry.key->path, new->registry_entry.value->name);

    configuration = fim_registry_configuration(value_path, arch);
    if (configuration == NULL) {
        return;
    }

    if (fim_registry_validate_path(value_path, configuration)) {
        return;
    }

    if (fim_check_restrict(value_path, configuration->filerestrict)) {
        return;
    }

    saved->registry_entry.value = fim_db_get_registry_data(syscheck.database, new->registry_entry.key->id,
                                                           new->registry_entry.value->name);

    if (configuration->opts | CHECK_SEECHANGES) {
        diff = fim_registry_value_diff(new->registry_entry.key->path, new->registry_entry.value->name,
                                       (char *)data_buffer, new->registry_entry.value->type, configuration);
    }

    json_event = fim_registry_event(new, saved, configuration, mode,
                                    saved->registry_entry.value == NULL ? FIM_ADD : FIM_MODIFIED, NULL, diff);

    if (json_event) {
        if (fim_db_insert_registry_data(syscheck.database, new->registry_entry.value, new->registry_entry.key->id) !=
            FIMDB_OK) {
            mwarn(FIM_REGISTRY_FAIL_TO_INSERT_VALUE, new->registry_entry.key->arch == ARCH_32BIT ? "[x32]" : "[x64]",
                  new->registry_entry.key->path, new->registry_entry.value->name);
        }

        if (_base_line) {
            char *json_formated = cJSON_PrintUnformatted(json_event);
            send_syscheck_msg(json_formated);
            os_free(json_formated);
        }

        cJSON_Delete(json_event);
    }
    fim_db_set_registry_data_scanned(syscheck.database, new->registry_entry.value->name, new->registry_entry.key->id);

    fim_registry_free_value_data(saved->registry_entry.value);
    os_free(diff);
}

/**
 * @brief Query the values belonging to a key.
 *
 * @param key_handle A handle to the key holding the values to query.
 * @param new A fim_entry object holding the information gathered from the key.
 * @param saved A fim_entry object holding the information from the key retrieved from the database.
 * @param arch An integer specifying the bit count of the register to scan, must be ARCH_32BIT or ARCH_64BIT.
 * @param value_count An integer holding the amount of values stored in the queried key.
 * @param mode A value specifying if the event has been triggered in scheduled, realtime or whodata mode.
 */
void fim_read_values(HKEY key_handle,
                     fim_entry *new,
                     fim_entry *saved,
                     int arch,
                     DWORD value_count,
                     fim_event_mode mode) {
    fim_registry_value_data value_data;
    TCHAR value_buffer[MAX_VALUE_NAME + 1];
    DWORD value_size;
    BYTE data_buffer[MAX_VALUE_NAME + 1];
    DWORD data_size;
    DWORD data_type = 0;
    DWORD i;

    if (new->registry_entry.key->id == 0) {
        if (fim_db_get_registry_key_rowid(syscheck.database, new->registry_entry.key->path,
                                          &new->registry_entry.key->id) != FIMDB_OK) {
            mwarn(FIM_REGISTRY_FAIL_TO_GET_KEY_ID, new->registry_entry.key->arch == ARCH_32BIT ? "[x32]" : "[x64]",
                  new->registry_entry.key->path);
            return;
        }
    }

    value_data.id = new->registry_entry.key->id;
    new->registry_entry.value = &value_data;

    for (i = 0; i < value_count; i++) {
        value_size = MAX_VALUE_NAME;
        data_size = MAX_VALUE_NAME;

        if (RegEnumValue(key_handle, i, value_buffer, &value_size, NULL, &data_type, data_buffer, &data_size) !=
            ERROR_SUCCESS) {
            break;
        }

        /* Check if no value name is specified */
        if (value_buffer[0] == '\0') {
            value_buffer[0] = '@';
            value_buffer[1] = '\0';
        }

        new->registry_entry.value->name = value_buffer;
        new->registry_entry.value->type = data_type;
        new->registry_entry.value->size = data_size;

        fim_registry_process_value_event(new, saved, arch, mode, data_buffer);
    }
}

/**
 * @brief Open a registry key and scan its contents.
 *
 * @param root_key_handle A handle to the root key to which the key to be scanned belongs.
 * @param full_key A string holding the full path to the key to scan.
 * @param sub_key A string holding the path to the key to scan, excluding the root key part of the path.
 * @param arch An integer specifying the bit count of the register to scan, must be ARCH_32BIT or ARCH_64BIT.
 * @param mode A value specifying if the event has been triggered in scheduled, realtime or whodata mode.
 */
void fim_open_key(HKEY root_key_handle, const char *full_key, const char *sub_key, int arch, fim_event_mode mode) {
    HKEY current_key_handle = NULL;
    REGSAM access_rights;
    DWORD sub_key_count = 0;
    DWORD value_count;
    FILETIME file_time = { 0 };
    DWORD i;
    fim_entry new, saved;
    registry *configuration;

    if (root_key_handle == NULL || full_key == NULL || sub_key == NULL) {
        return;
    }

    configuration = fim_registry_configuration(full_key, arch);
    if (configuration == NULL) {
        return;
    }

    // Check ignore and recursion level restrictions.
    if (fim_registry_validate_path(full_key, configuration)) {
        return;
    }

    access_rights = KEY_READ | (arch == ARCH_32BIT ? KEY_WOW64_32KEY : KEY_WOW64_64KEY);

    if (RegOpenKeyEx(root_key_handle, sub_key, 0, access_rights, &current_key_handle) != ERROR_SUCCESS) {
        mdebug1(FIM_REG_OPEN, sub_key, arch == ARCH_32BIT ? "[x32]" : "[x64]");
        return;
    }

    /* We use the class_name, sub_key_count and the value count */
    if (RegQueryInfoKey(current_key_handle, NULL, NULL, NULL, &sub_key_count, NULL, NULL, &value_count, NULL, NULL,
                        NULL, &file_time) != ERROR_SUCCESS) {
        RegCloseKey(current_key_handle);
        return;
    }

    /* Query each sub_key and call open_key */
    for (i = 0; i < sub_key_count; i++) {
        char new_full_key[MAX_KEY + 2];
        char *new_sub_key;
        TCHAR sub_key_name_b[MAX_KEY_LENGTH + 1];
        DWORD sub_key_name_s = MAX_KEY_LENGTH;

        if (RegEnumKeyEx(current_key_handle, i, sub_key_name_b, &sub_key_name_s, NULL, NULL, NULL, NULL) !=
            ERROR_SUCCESS) {
            continue;
        }

        snprintf(new_full_key, MAX_KEY, "%s\\%s", full_key, sub_key_name_b);

        if (new_sub_key = strchr(new_full_key, '\\'), new_sub_key) {
            new_sub_key++;
        }

        /* Open sub_key */
        fim_open_key(root_key_handle, new_full_key, new_sub_key, arch, mode);
    }

    // Done scanning sub_keys, trigger an alert on the current key if required.
    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = fim_registry_get_key_data(current_key_handle, full_key, configuration);
    new.registry_entry.value = NULL;

    saved.type = FIM_TYPE_REGISTRY;
    saved.registry_entry.key = fim_db_get_registry_key(syscheck.database, full_key);
    saved.registry_entry.value = NULL;

    if (saved.registry_entry.key != NULL) {
        new.registry_entry.key->id = saved.registry_entry.key->id;
    }

    if (!fim_check_restrict(full_key, configuration->filerestrict)) {
        cJSON *json_event =
        fim_registry_event(&new, &saved, configuration, mode,
                           saved.registry_entry.key == NULL ? FIM_ADD : FIM_MODIFICATION, NULL, NULL);

        if (json_event) {
            if (fim_db_insert_registry_key(syscheck.database, new.registry_entry.key, new.registry_entry.key->id) !=
                FIMDB_OK) {
                mwarn("Couldn't insert into DB");
            }

            if (_base_line) {
                char *json_formated = cJSON_PrintUnformatted(json_event);
                send_syscheck_msg(json_formated);
                os_free(json_formated);
            }

            cJSON_Delete(json_event);
        }

        fim_db_set_registry_key_scanned(syscheck.database, full_key);
    }

    if (value_count) {
        fim_read_values(current_key_handle, &new, &saved, arch, value_count, mode);
    }

    fim_registry_free_key(new.registry_entry.key);
    fim_registry_free_key(saved.registry_entry.key);
    RegCloseKey(current_key_handle);
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
            mdebug1(FIM_INV_REG, syscheck.registry[i].entry,
                    syscheck.registry[i].arch == ARCH_64BIT ? "[x64] " : "[x32]");
            *syscheck.registry[i].entry = '\0';
            continue;
        }
        fim_open_key(root_key_handle, syscheck.registry[i].entry, sub_key, syscheck.registry[i].arch, FIM_SCHEDULED);
    }

    fim_registry_process_unscanned_entries();

    mdebug1(FIM_WINREGISTRY_ENDED);

    if (_base_line == 0) {
        _base_line = 1;
    }
}

#endif
