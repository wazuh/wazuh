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
#include <openssl/md5.h>
#include <openssl/sha.h>

#ifdef WAZUH_UNIT_TESTING
#include "unit_tests/wrappers/windows/winreg_wrappers.h"
extern int _base_line;
#else
static int _base_line = 0;
#endif

/* Default values */
#define MAX_KEY_LENGTH 260
#define MAX_VALUE_NAME 16383

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
 * @brief Validates the recursion level of a registry key.
 *
 * @param key_path Path of the key
 * @param configuration The configuration associated with the registry entry.
 * @return 0 if the path is valid, -1 if the path is to be excluded.
 */
int fim_registry_validate_recursion_level(const char *key_path, const registry *configuration) {
    const char *pos;
    int depth = 0;
    unsigned int parent_path_size;

    if (key_path == NULL || configuration == NULL) {
        return -1;
    }

    /* Verify recursion level */
    parent_path_size = strlen(configuration->entry);
    // Recursion level only for registry keys
    if (parent_path_size > strlen(key_path)) {
        return -1;
    }

    pos = key_path + parent_path_size;
    while (pos = strchr(pos, PATH_SEP), pos) {
        depth++;
        pos++;
    }

    if (depth > configuration->recursion_level) {
        mdebug2(FIM_MAX_RECURSION_LEVEL, depth, configuration->recursion_level, key_path);
        return -1;
    }

    return 0;
}

/**
 * @brief Validates ignore restrictions of registry entry.
 *
 * @param entry A string holding the full path of the key or the name of the value to be validated.
 * @param configuration The configuration associated with the registry entry.
 * @param key 1 if the entry is a key, 0 if the entry is a value.
 * @return 0 if the path is valid, -1 if the path is to be excluded.
 */
int fim_registry_validate_ignore(const char *entry, const registry *configuration, int key) {
    int ign_it;
    registry_ignore **ignore_list;
    registry_ignore_regex **ignore_list_regex;

    if (entry == NULL || configuration == NULL) {
        return -1;
    }

    if (key) {
        ignore_list = &syscheck.key_ignore;
        ignore_list_regex = &syscheck.key_ignore_regex;
    } else {
        ignore_list = &syscheck.value_ignore;
        ignore_list_regex = &syscheck.value_ignore_regex;
    }

    if (*ignore_list) {
        for (ign_it = 0; (*ignore_list)[ign_it].entry; ign_it++) {
            if ((*ignore_list)[ign_it].arch != configuration->arch) {
                continue;
            }
            if (strncasecmp((*ignore_list)[ign_it].entry, entry, strlen((*ignore_list)[ign_it].entry)) == 0) {
                mdebug2(FIM_REG_IGNORE_ENTRY, key ? "registry" : "value",
                        (*ignore_list)[ign_it].arch == ARCH_32BIT ? "[x32]" : "[x64]", entry,
                        (*ignore_list)[ign_it].entry);
                return -1;
            }
        }
    }
    if (*ignore_list_regex) {
        for (ign_it = 0; (*ignore_list_regex)[ign_it].regex; ign_it++) {
            if ((*ignore_list_regex)[ign_it].arch != configuration->arch) {
                continue;

            }
            if (OSMatch_Execute(entry, strlen(entry), (*ignore_list_regex)[ign_it].regex)) {
                mdebug2(FIM_REG_IGNORE_SREGEX, key ? "registry" : "value",
                        (*ignore_list_regex)[ign_it].arch == ARCH_32BIT ? "[x32]" : "[x64]", entry,
                        (*ignore_list_regex)[ign_it].regex->raw);
                return -1;
            }
        }
    }
    return 0;
}
/**
 * @brief Compute checksum of a registry key
 *
 * @param data FIM registry key whose checksum will be computed
 */
void fim_registry_get_checksum_key(fim_registry_key *data) {
    char *checksum = NULL;
    int size;

    size = snprintf(0,
            0,
            "%s:%s:%s:%s:%s:%u",
            data->perm ? data->perm : "",
            data->uid ? data->uid : "",
            data->user_name ? data->user_name : "",
            data->gid ? data->gid : "",
            data->group_name ? data->group_name : "",
            data->mtime);

    os_calloc(size + 1, sizeof(char), checksum);
    snprintf(checksum,
            size + 1,
            "%s:%s:%s:%s:%s:%u:%d",
            data->perm ? data->perm : "",
            data->uid ? data->uid : "",
            data->gid ? data->gid : "",
            data->user_name ? data->user_name : "",
            data->group_name ? data->group_name : "",
            data->mtime,
            data->arch);

    OS_SHA1_Str(checksum, -1, data->checksum);
    free(checksum);
}

/**
 * @brief Compute checksum of a registry value
 *
 * @param data FIM registry value whose checksum will be computed
 */
void fim_registry_get_checksum_value(fim_registry_value_data *data) {
    char *checksum = NULL;
    int size;

    size = snprintf(0,
            0,
            "%u:%u:%s:%s:%s",
            data->type,
            data->size,
            data->hash_md5 ,
            data->hash_sha1,
            data->hash_sha256);

    os_calloc(size + 1, sizeof(char), checksum);
    snprintf(checksum,
            size + 1,
            "%u:%u:%s:%s:%s",
            data->type,
            data->size,
            data->hash_md5 ,
            data->hash_sha1,
            data->hash_sha256);

    OS_SHA1_Str(checksum, -1, data->checksum);
    free(checksum);
}

/**
 * @brief Initialize digest context according to a provided configuration
 *
 * @param opts An integer holding the registry configuration.
 * @param md5_ctx An uninitialized md5 context.
 * @param sha1_ctx An uninitialized sha1 context.
 * @param sha256_ctx An uninitialized sha256 context.
 */
void fim_registry_init_digests(int opts, MD5_CTX *md5_ctx, SHA_CTX *sha1_ctx, SHA256_CTX *sha256_ctx) {
    if (opts & CHECK_MD5SUM) {
        MD5_Init(md5_ctx);
    }

    if (opts & CHECK_SHA1SUM) {
        SHA1_Init(sha1_ctx);
    }

    if (opts & CHECK_SHA256SUM) {
        SHA256_Init(sha256_ctx);
    }
}

/**
 * @brief Update digests from a provided buffer.
 *
 * @param buffer A raw data buffer used to update digests.
 * @param length An integer holding the length of buffer.
 * @param opts An integer holding the registry configuration.
 * @param md5_ctx An MD5 CTX to be updated with the contents of buffer.
 * @param sha1_ctx An SHA1 CTX to be updated with the contents of buffer.
 * @param sha256_ctx An SHA256 CTX to be updated with the contents of buffer.
 */
void fim_registry_update_digests(const BYTE *buffer,
                                 size_t length,
                                 int opts,
                                 MD5_CTX *md5_ctx,
                                 SHA_CTX *sha1_ctx,
                                 SHA256_CTX *sha256_ctx) {
    if (opts & CHECK_MD5SUM) {
        MD5_Update(md5_ctx, buffer, length);
    }

    if (opts & CHECK_SHA1SUM) {
        SHA1_Update(sha1_ctx, buffer, length);
    }

    if (opts & CHECK_SHA256SUM) {
        SHA256_Update(sha256_ctx, buffer, length);
    }
}

/**
 * @brief Prints out hashes from the provided contexts, destryoing them in the process.
 *
 * @param opts An integer holding the registry configuration.
 * @param md5_ctx An MD5 CTX used to print the corresponding hash.
 * @param sha1_ctx An SHA1 CTX used to print the corresponding hash.
 * @param sha256_ctx An SHA256 CTX used to print the corresponding hash.
 * @param md5_output A buffer holding the MD5 hash on exit.
 * @param sha1_output A buffer holding the SHA1 hash on exit.
 * @param sha256_output A buffer holding the SHA256 hash on exit.
 */
void fim_registry_final_digests(int opts,
                                MD5_CTX *md5_ctx,
                                SHA_CTX *sha1_ctx,
                                SHA256_CTX *sha256_ctx,
                                os_md5 md5_output,
                                os_sha1 sha1_output,
                                os_sha256 sha256_output) {
    unsigned char md5_digest[MD5_DIGEST_LENGTH];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    int n;

    if (opts & CHECK_MD5SUM) {
        MD5_Final(md5_digest, md5_ctx);
        for (n = 0; n < MD5_DIGEST_LENGTH; n++) {
            snprintf(md5_output, 3, "%02x", md5_digest[n]);
            md5_output += 2;
        }
    }

    if (opts & CHECK_SHA1SUM) {
        SHA1_Final(sha1_digest, sha1_ctx);
        for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
            snprintf(sha1_output, 3, "%02x", sha1_digest[n]);
            sha1_output += 2;
        }
    }

    if (opts & CHECK_SHA256SUM) {
        SHA256_Final(sha256_digest, sha256_ctx);
        for (n = 0; n < SHA256_DIGEST_LENGTH; n++) {
            snprintf(sha256_output, 3, "%02x", sha256_digest[n]);
            sha256_output += 2;
        }
    }
}

/**
 * @brief Calculate and store value hashes.
 *
 * @param entry FIM entry holding information from a value.
 * @param configuration The confguration associated with the value.
 * @param data_buffer Raw buffer holding the value's contents.
 */
void fim_registry_calculate_hashes(fim_entry *entry, registry *configuration, BYTE *data_buffer) {
    MD5_CTX md5_ctx;
    SHA_CTX sha1_ctx;
    SHA256_CTX sha256_ctx;

    char *string_it;
    BYTE buffer[OS_SIZE_2048];
    size_t length;

    entry->registry_entry.value->hash_md5[0] = '\0';
    entry->registry_entry.value->hash_sha1[0] = '\0';
    entry->registry_entry.value->hash_sha256[0] = '\0';

    if ((configuration->opts & (CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM)) == 0) {
        return;
    }

    /* Initialize configured hashes */
    fim_registry_init_digests(configuration->opts, &md5_ctx, &sha1_ctx, &sha256_ctx);

    switch (entry->registry_entry.value->type) {
    case REG_SZ:
    case REG_EXPAND_SZ:
        fim_registry_update_digests(data_buffer, strlen((char *)data_buffer), configuration->opts, &md5_ctx, &sha1_ctx,
                                    &sha256_ctx);
        break;
    case REG_MULTI_SZ:
        /* Print multiple strings */
        for (string_it = (char *)data_buffer; *string_it; string_it += strlen(string_it) + 1) {
            fim_registry_update_digests((BYTE *)string_it, strlen(string_it), configuration->opts, &md5_ctx, &sha1_ctx,
                                        &sha256_ctx);
        }
        break;
    case REG_DWORD:
        length = snprintf((char *)buffer, OS_SIZE_2048, "%08x", *((unsigned int *)data_buffer));
        fim_registry_update_digests(buffer, length, configuration->opts, &md5_ctx, &sha1_ctx, &sha256_ctx);
        break;
    default:
        for (unsigned int i = 0; i < entry->registry_entry.value->size; i++) {
            length = snprintf((char *)buffer, 3, "%02x", (unsigned int)data_buffer[i] & 0xFF);
            fim_registry_update_digests(buffer, length, configuration->opts, &md5_ctx, &sha1_ctx, &sha256_ctx);
        }
        break;
    }

    fim_registry_final_digests(configuration->opts, &md5_ctx, &sha1_ctx, &sha256_ctx,
                               entry->registry_entry.value->hash_md5, entry->registry_entry.value->hash_sha1,
                               entry->registry_entry.value->hash_sha256);
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

    os_strdup(path, key->path);

    key->arch = configuration->arch;

     if (configuration->opts & CHECK_OWNER) {
        key->user_name = get_registry_user(path, &key->uid, key_handle);
    }

    if (configuration->opts & CHECK_GROUP) {
        key->group_name = get_registry_group(&key->gid, key_handle);
    }

    if (configuration->opts & CHECK_PERM) {
        char permissions[OS_SIZE_6144 + 1];
        int retval = 0;

        retval = get_registry_permissions(key_handle, permissions);

        if (retval != ERROR_SUCCESS) {
            mwarn(FIM_EXTRACT_PERM_FAIL, path, retval);
            os_strdup("", key->perm);
        } else {
            key->perm = decode_win_permissions(permissions);
        }
    }

    if (configuration->opts & CHECK_MTIME) {
        key->mtime = get_registry_mtime(key_handle);
    }

    key->last_event = time(NULL);

    fim_registry_get_checksum_key(key);

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

void fim_registry_free_entry(fim_entry *entry) {
    if (entry) {
        fim_registry_free_key(entry->registry_entry.key);
        fim_registry_free_value_data(entry->registry_entry.value);
        free(entry);
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

    fim_db_remove_registry_value_data(fim_sql, data->registry_entry.value);

    if (configuration->opts & CHECK_SEECHANGES) {
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
    int result;

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

    w_mutex_lock(mutex);
    result = fim_db_get_values_from_registry_key(fim_sql, &file, syscheck.database_store, data->registry_entry.key->id);
    w_mutex_unlock(mutex);

    if (result == FIMDB_OK && file && file->elements) {
        fim_db_process_read_registry_data_file(fim_sql, file, mutex, fim_registry_process_value_delete_event,
                                               syscheck.database_store, _alert, _ev_mode, _w_evt);
    }

    w_mutex_lock(mutex);
    fim_db_remove_registry_key(fim_sql, data);
    w_mutex_unlock(mutex);

    if (configuration->opts & CHECK_SEECHANGES) {
        fim_diff_process_delete_registry(data->registry_entry.key->path, data->registry_entry.key->arch);
    }
}

/**
 * @brief Process and trigger delete events for all unscanned registry elements.
 */
void fim_registry_process_unscanned_entries() {
    fim_tmp_file *file;
    fim_event_mode event_mode = FIM_SCHEDULED;
    int result;

    w_mutex_lock(&syscheck.fim_entry_mutex);
    result = fim_db_get_registry_keys_not_scanned(syscheck.database, &file, syscheck.database_store);
    w_mutex_unlock(&syscheck.fim_entry_mutex);

    if (result != FIMDB_OK) {
        mwarn(FIM_REGISTRY_UNSCANNED_KEYS_FAIL);
    } else if (file && file->elements) {
        fim_db_process_read_file(syscheck.database, file, FIM_TYPE_REGISTRY, &syscheck.fim_entry_mutex,
                                 fim_registry_process_key_delete_event, syscheck.database_store, &_base_line,
                                 &event_mode, NULL);
    }

    w_mutex_lock(&syscheck.fim_entry_mutex);
    result = fim_db_get_registry_data_not_scanned(syscheck.database, &file, syscheck.database_store);
    w_mutex_unlock(&syscheck.fim_entry_mutex);

    if (result != FIMDB_OK) {
        mwarn(FIM_REGISTRY_UNSCANNED_VALUE_FAIL);
    } else if (file && file->elements) {
        fim_db_process_read_registry_data_file(syscheck.database, file, &syscheck.fim_entry_mutex,
                                               fim_registry_process_value_delete_event, syscheck.database_store,
                                               &_base_line, &event_mode, NULL);
    }
}

/**
 * @brief Generate and send value event
 *
 * @param new A fim_entry object holding the information gathered from the key and value.
 * @param saved A fim_entry object holding the information from the key and value retrieved from the database.
 * @param mode A value specifying if the event has been triggered in scheduled, realtime or whodata mode.
 * @param data_buffer A pointer to the raw data buffer contained in the value.
 */
void fim_registry_process_value_event(fim_entry *new,
                                      fim_entry *saved,
                                      fim_event_mode mode,
                                      BYTE *data_buffer) {
    char *value_path;
    size_t value_path_length;
    registry *configuration;
    cJSON *json_event;
    char *diff = NULL;

    configuration = fim_registry_configuration(new->registry_entry.key->path, new->registry_entry.key->arch);
    if (configuration == NULL) {
        return;
    }

    value_path_length = strlen(new->registry_entry.key->path) + strlen(new->registry_entry.value->name) + 2;

    os_malloc(value_path_length, value_path);
    snprintf(value_path, value_path_length, "%s\\%s", new->registry_entry.key->path, new->registry_entry.value->name);

    if (fim_registry_validate_ignore(value_path, configuration, 0)) {
        os_free(value_path);
        return;
    }
    os_free(value_path);

    if (fim_check_restrict(new->registry_entry.value->name, configuration->restrict_value)) {
        return;
    }

    fim_registry_calculate_hashes(new, configuration, data_buffer);

    fim_registry_get_checksum_value(new->registry_entry.value);

    saved->registry_entry.value = fim_db_get_registry_data(syscheck.database, new->registry_entry.key->id,
                                                           new->registry_entry.value->name);

    if (configuration->opts & CHECK_SEECHANGES) {
        diff = fim_registry_value_diff(new->registry_entry.key->path, new->registry_entry.value->name,
                                       (char *)data_buffer, new->registry_entry.value->type, configuration);
    }

    json_event = fim_registry_event(new, saved, configuration, mode,
                                    saved->registry_entry.value == NULL ? FIM_ADD : FIM_MODIFICATION, NULL, diff);

    os_free(diff);

    if (json_event) {
        if (fim_db_insert_registry_data(syscheck.database, new->registry_entry.value, new->registry_entry.key->id,
                                        saved->registry_entry.value == NULL ? FIM_ADD : FIM_MODIFICATION) != FIMDB_OK) {
            // Something went wrong or the DB is full, either way we need to stop.
            mdebug2(FIM_REGISTRY_FAIL_TO_INSERT_VALUE, new->registry_entry.key->arch == ARCH_32BIT ? "[x32]" : "[x64]",
                    new->registry_entry.key->path, new->registry_entry.value->name);
            cJSON_Delete(json_event);
            fim_registry_free_value_data(saved->registry_entry.value);
            return;
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
}

/**
 * @brief Query the values belonging to a key.
 *
 * @param key_handle A handle to the key holding the values to query.
 * @param new A fim_entry object holding the information gathered from the key.
 * @param saved A fim_entry object holding the information from the key retrieved from the database.
 * @param value_count An integer holding the amount of values stored in the queried key.
 * @param max_value_length The size of longest value name contained in the key in unicode characters.
 * @param max_value_data_length The size of the biggest data contained in of the keys values in bytes.
 * @param mode A value specifying if the event has been triggered in scheduled, realtime or whodata mode.
 */
void fim_read_values(HKEY key_handle,
                     fim_entry *new,
                     fim_entry *saved,
                     DWORD value_count,
                     DWORD max_value_length,
                     DWORD max_value_data_length,
                     fim_event_mode mode) {
    fim_registry_value_data value_data;
    TCHAR *value_buffer;
    BYTE *data_buffer;
    DWORD i;

    if (new->registry_entry.key->id == 0) {
        if (fim_db_get_registry_key_rowid(syscheck.database, new->registry_entry.key->path,
                                          new->registry_entry.key->arch, &new->registry_entry.key->id) != FIMDB_OK) {
            mwarn(FIM_REGISTRY_FAIL_TO_GET_KEY_ID, new->registry_entry.key->arch == ARCH_32BIT ? "[x32]" : "[x64]",
                  new->registry_entry.key->path);
            return;
        }
    }

    value_data.id = new->registry_entry.key->id;
    new->registry_entry.value = &value_data;

    os_calloc(max_value_length + 1, sizeof(TCHAR), value_buffer);
    os_calloc(max_value_data_length, sizeof(BYTE), data_buffer);

    for (i = 0; i < value_count; i++) {
        DWORD value_size = max_value_length + 1;
        DWORD data_size = max_value_data_length;
        DWORD data_type = 0;

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
        new->registry_entry.value->last_event = time(NULL);

        fim_registry_process_value_event(new, saved, mode, data_buffer);
    }

    os_free(value_buffer);
    os_free(data_buffer);
}

/**
 * @brief Open a registry key and scan its contents.
 *
 * @param root_key_handle A handle to the root key to which the key to be scanned belongs.
 * @param full_key A string holding the full path to the key to scan.
 * @param sub_key A string holding the path to the key to scan, excluding the root key part of the path.
 * @param arch An integer specifying the bit count of the register to scan, must be ARCH_32BIT or ARCH_64BIT.
 * @param mode A value specifying if the event has been triggered in scheduled, realtime or whodata mode.
 * @param parent_configuration A pointer to the configuration of this key's "parent".
 */
void fim_open_key(HKEY root_key_handle,
                  const char *full_key,
                  const char *sub_key,
                  int arch,
                  fim_event_mode mode,
                  registry *parent_configuration) {
    HKEY current_key_handle = NULL;
    REGSAM access_rights;
    DWORD sub_key_count = 0;
    DWORD value_count;
    DWORD max_value_length;
    DWORD max_value_data_length;
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

    if (mode == FIM_SCHEDULED && parent_configuration != NULL && parent_configuration != configuration) {
        // If a more specific configuration is available in scheduled mode, we will scan this registry later.
        return;
    }

    // Recursion level restrictions.
    if (fim_registry_validate_recursion_level(full_key, configuration)) {
        return;
    }
    // Ignore restriction
    if (fim_registry_validate_ignore(full_key, configuration, 1)) {
        return;
    }

    access_rights = KEY_READ | (arch == ARCH_32BIT ? KEY_WOW64_32KEY : KEY_WOW64_64KEY);

    if (RegOpenKeyEx(root_key_handle, sub_key, 0, access_rights, &current_key_handle) != ERROR_SUCCESS) {
        mdebug1(FIM_REG_OPEN, sub_key, arch == ARCH_32BIT ? "[x32]" : "[x64]");
        return;
    }

    /* We use the class_name, sub_key_count and the value count */
    if (RegQueryInfoKey(current_key_handle, NULL, NULL, NULL, &sub_key_count, NULL, NULL, &value_count,
                        &max_value_length, &max_value_data_length, NULL, &file_time) != ERROR_SUCCESS) {
        RegCloseKey(current_key_handle);
        return;
    }

    /* Query each sub_key and call open_key */
    for (i = 0; i < sub_key_count; i++) {
        char *new_full_key;
        char *new_sub_key;
        size_t new_full_key_length;
        TCHAR sub_key_name_b[MAX_KEY_LENGTH + 1];
        DWORD sub_key_name_s = MAX_KEY_LENGTH;

        if (RegEnumKeyEx(current_key_handle, i, sub_key_name_b, &sub_key_name_s, NULL, NULL, NULL, NULL) !=
            ERROR_SUCCESS) {
            continue;
        }

        new_full_key_length = strlen(full_key) + sub_key_name_s + 2;

        os_malloc(new_full_key_length, new_full_key);

        snprintf(new_full_key, new_full_key_length, "%s\\%s", full_key, sub_key_name_b);

        if (new_sub_key = strchr(new_full_key, '\\'), new_sub_key) {
            new_sub_key++;
        }

        /* Open sub_key */
        fim_open_key(root_key_handle, new_full_key, new_sub_key, arch, mode, configuration);

        os_free(new_full_key);
    }
    // Done scanning sub_keys, trigger an alert on the current key if required.
    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = fim_registry_get_key_data(current_key_handle, full_key, configuration);
    new.registry_entry.value = NULL;

    if (new.registry_entry.key == NULL) {
        return;
    }

    w_mutex_lock(&syscheck.fim_entry_mutex);

    saved.type = FIM_TYPE_REGISTRY;
    saved.registry_entry.key = fim_db_get_registry_key(syscheck.database, full_key, arch);
    saved.registry_entry.value = NULL;

    if (saved.registry_entry.key != NULL) {
        new.registry_entry.key->id = saved.registry_entry.key->id;
    }
    // Ignore all the values of the ignored key.
    if (!fim_check_restrict(full_key, configuration->restrict_key)) {
        cJSON *json_event =
        fim_registry_event(&new, &saved, configuration, mode,
                           saved.registry_entry.key == NULL ? FIM_ADD : FIM_MODIFICATION, NULL, NULL);

        if (json_event) {
            if (fim_db_insert_registry_key(syscheck.database, new.registry_entry.key, new.registry_entry.key->id) !=
                FIMDB_OK) {
                // Something went wrong or the DB is full, either way we need to stop scanning.
                w_mutex_unlock(&syscheck.fim_entry_mutex);
                cJSON_Delete(json_event);
                fim_registry_free_key(new.registry_entry.key);
                fim_registry_free_key(saved.registry_entry.key);
                RegCloseKey(current_key_handle);
                return;
            }

            if (_base_line) {
                char *json_formated = cJSON_PrintUnformatted(json_event);
                send_syscheck_msg(json_formated);
                os_free(json_formated);
            }

            cJSON_Delete(json_event);
        }

        fim_db_set_registry_key_scanned(syscheck.database, full_key, arch);

        if (value_count) {
            fim_read_values(current_key_handle, &new, &saved, value_count, max_value_length, max_value_data_length,
                            mode);
        }
    }

    w_mutex_unlock(&syscheck.fim_entry_mutex);

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
        fim_open_key(root_key_handle, syscheck.registry[i].entry, sub_key, syscheck.registry[i].arch, FIM_SCHEDULED,
                     NULL);
    }

    fim_registry_process_unscanned_entries();

    mdebug1(FIM_WINREGISTRY_ENDED);

    if (_base_line == 0) {
        _base_line = 1;
    }
}

#endif
