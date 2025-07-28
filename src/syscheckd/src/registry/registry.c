/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include <cJSON.h>
#include "registry.h"
#include "shared.h"
#include "../../include/syscheck.h"
#include "../../config/syscheck-config.h"
#include "../db/include/db.h"
#include "../os_crypto/md5/md5_op.h"
#include "../os_crypto/sha1/sha1_op.h"
#include "../os_crypto/md5_sha1/md5_sha1_op.h"
#include <openssl/md5.h>
#include <openssl/sha.h>

#ifdef WAZUH_UNIT_TESTING
#include "../../../unit_tests/wrappers/windows/winreg_wrappers.h"
extern int _base_line;
// Remove static qualifier when unit testing
#define STATIC
#else
static int _base_line = 0;
#define STATIC static
#endif

/* Default values */
#define MAX_KEY_LENGTH 260
#define MAX_VALUE_NAME 16383

static const char *FIM_EVENT_TYPE_ARRAY[] = {
    "added",
    "deleted",
    "modified"
};

static const char *FIM_EVENT_MODE[] = {
    "scheduled",
    "realtime",
    "whodata"
};

// DBSync Callbacks

/**
 * @brief Registry key callback.
 *
 * @param resultType Action performed by DBSync (INSERTED|MODIFIED|DELETED|MAXROWS)
 * @param result_json Data returned by dbsync in JSON format.
 * @param user_data Registry key transaction context.
 */
STATIC void registry_key_transaction_callback(ReturnTypeCallback resultType,
                                              const cJSON* result_json,
                                              void* user_data) {

    cJSON *json_event = NULL;
    cJSON *json_path = NULL;
    cJSON *json_arch = NULL;
    cJSON *old_data = NULL;
    cJSON *old_attributes = NULL;
    cJSON *changed_attributes = NULL;
    char *path = NULL;
    int arch = -1;
    char iso_time[32];

    fim_key_txn_context_t *event_data = (fim_key_txn_context_t *) user_data;

    // In case of deletions, key is NULL, so we need to get the path and arch from the json event
    if (event_data->key == NULL) {
        if (json_path = cJSON_GetObjectItem(result_json, "path"), json_path == NULL) {
            goto end;
        }
        if (json_arch = cJSON_GetObjectItem(result_json, "architecture"), json_arch == NULL) {
            goto end;
        }
        path = cJSON_GetStringValue(json_path);
        arch = (strcmp(cJSON_GetStringValue(json_arch), "[x32]") == 0) ? ARCH_32BIT: ARCH_64BIT;

    } else {
        path = event_data->key->path;
        arch = event_data->key->architecture;
    }

    if (event_data->config == NULL) {
        event_data->config = fim_registry_configuration(path, arch);
        if (event_data->config == NULL) {
            goto end;
        }
    }

    switch (resultType) {
        case INSERTED:
            event_data->evt_data->type = FIM_ADD;
            break;

        case MODIFIED:
            event_data->evt_data->type = FIM_MODIFICATION;
            break;

        case DELETED:
            event_data->evt_data->type = FIM_DELETE;
            break;

        case MAX_ROWS:
            mdebug1("Couldn't insert '%s' entry into DB. The DB is full, please check your configuration.", path);

        // Fallthrough
        default:
            goto end;
            break;
    }

    // Do not process if it's the first scan
    if (_base_line == 0) {
        return;
    }

    // Do not process if report_event is false
    if (event_data->evt_data->report_event == false) {
        goto end;
    }

    json_event = cJSON_CreateObject();
    if (json_event == NULL) {
        return;
    }

    cJSON_AddStringToObject(json_event, "collector", "registry_key");
    cJSON_AddStringToObject(json_event, "module", "fim");

    cJSON* data = cJSON_CreateObject();
    cJSON_AddItemToObject(json_event, "data", data);

    cJSON* event = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "event", event);

    get_iso8601_utc_time(iso_time, sizeof(iso_time));
    cJSON_AddStringToObject(event, "created", iso_time);
    cJSON_AddStringToObject(event, "type", FIM_EVENT_TYPE_ARRAY[event_data->evt_data->type]);

    cJSON* registry = fim_registry_key_attributes_json(result_json, event_data->key, event_data->config);
    cJSON_AddItemToObject(data, "registry", registry);

    cJSON_AddStringToObject(registry, "path", path);
    cJSON_AddStringToObject(registry, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");
    cJSON_AddStringToObject(registry, "mode", FIM_EVENT_MODE[event_data->evt_data->mode]);

    old_data = cJSON_GetObjectItem(result_json, "old");
    if (old_data != NULL) {
        old_attributes = cJSON_CreateObject();
        changed_attributes = cJSON_CreateArray();
        cJSON_AddItemToObject(registry, "previous", old_attributes);
        cJSON_AddItemToObject(event, "changed_fields", changed_attributes);

        fim_calculate_dbsync_difference_key(event_data->key,
                                            event_data->config,
                                            old_data,
                                            changed_attributes,
                                            old_attributes);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            mdebug2(FIM_EMPTY_CHANGED_ATTRIBUTES, path);
            goto end;
        }
    }

    if (event_data->config->tag != NULL) {
        cJSON_AddStringToObject(registry, "tags", event_data->config->tag);
    }

    send_syscheck_msg(json_event);

end:
    cJSON_Delete(json_event);
}

/**
 * @brief Registry value callback.
 *
 * @param resultType Action performed by DBSync (INSERTED|MODIFIED|DELETED|MAXROWS)
 * @param result_json Data returned by dbsync in JSON format.
 * @param user_data Registry value transaction context.
 */
STATIC void registry_value_transaction_callback(ReturnTypeCallback resultType,
                                                const cJSON* result_json,
                                                void* user_data) {

    cJSON *json_event = NULL;
    cJSON *json_path = NULL;
    cJSON *json_arch = NULL;
    cJSON *json_value = NULL;
    cJSON *old_data = NULL;
    cJSON *old_attributes = NULL;
    cJSON *changed_attributes = NULL;
    char *path = NULL;
    char *value = NULL;
    int arch = -1;
    char iso_time[32];

    fim_val_txn_context_t *event_data = (fim_val_txn_context_t *) user_data;

    // In case of deletions, data is NULL, so we need to get the path and arch from the json event
    if (event_data->data == NULL) {
        if (json_path = cJSON_GetObjectItem(result_json, "path"), json_path == NULL) {
            goto end;
        }
        if (json_arch = cJSON_GetObjectItem(result_json, "architecture"), json_arch == NULL) {
            goto end;
        }
        if (json_value = cJSON_GetObjectItem(result_json, "value"), json_value == NULL) {
            goto end;
        }
        path = cJSON_GetStringValue(json_path);
        arch = (strcmp(cJSON_GetStringValue(json_arch), "[x32]") == 0) ? ARCH_32BIT: ARCH_64BIT;
        value = cJSON_GetStringValue(json_value);
    } else {
        path = event_data->data->path;
        arch = event_data->data->architecture;
        value = event_data->data->value;
    }

    if (event_data->config == NULL) {
        event_data->config = fim_registry_configuration(path, arch);
        if (event_data->config == NULL) {
            goto end;
        }
    }

    switch (resultType) {
        case INSERTED:
            event_data->evt_data->type = FIM_ADD;
            break;

        case MODIFIED:
            event_data->evt_data->type = FIM_MODIFICATION;
            break;

        case DELETED:
            if (event_data->config->opts & CHECK_SEECHANGES) {
                fim_diff_process_delete_value(path, value, arch);
            }
            event_data->evt_data->type = FIM_DELETE;
            break;

        case MAX_ROWS:
            mdebug1("Couldn't insert '%s' entry into DB. The DB is full, please check your configuration.", path);

        // Fallthrough
        default:
            goto end;
            break;
    }

    // Do not process if it's the first scan
    if (_base_line == 0) {
        return;
    }

    // Do not process if report_event is false
    if (event_data->evt_data->report_event == false) {
        goto end;
    }

    json_event = cJSON_CreateObject();
    if (json_event == NULL) {
        goto end;
    }

    cJSON_AddStringToObject(json_event, "collector", "registry_value");
    cJSON_AddStringToObject(json_event, "module", "fim");

    cJSON* data = cJSON_CreateObject();
    cJSON_AddItemToObject(json_event, "data", data);

    cJSON* event = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "event", event);

    get_iso8601_utc_time(iso_time, sizeof(iso_time));
    cJSON_AddStringToObject(event, "created", iso_time);
    cJSON_AddStringToObject(event, "type", FIM_EVENT_TYPE_ARRAY[event_data->evt_data->type]);

    cJSON* registry = fim_registry_value_attributes_json(result_json, event_data->data, event_data->config);
    cJSON_AddItemToObject(data, "registry", registry);

    cJSON_AddStringToObject(registry, "path", path);
    cJSON_AddStringToObject(registry, "architecture", arch == ARCH_32BIT ? "[x32]" : "[x64]");
    cJSON_AddStringToObject(registry, "value", value);
    cJSON_AddStringToObject(registry, "mode", FIM_EVENT_MODE[event_data->evt_data->mode]);

    old_data = cJSON_GetObjectItem(result_json, "old");
    if (old_data != NULL) {
        old_attributes = cJSON_CreateObject();
        changed_attributes = cJSON_CreateArray();
        cJSON_AddItemToObject(registry, "previous", old_attributes);
        cJSON_AddItemToObject(event, "changed_fields", changed_attributes);

        fim_calculate_dbsync_difference_value(event_data->data,
                                              event_data->config,
                                              old_data,
                                              changed_attributes,
                                              old_attributes);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            mdebug2(FIM_EMPTY_CHANGED_ATTRIBUTES, path);
            goto end;
        }
    }

    if (event_data->config->tag != NULL) {
        cJSON_AddStringToObject(registry, "tags", event_data->config->tag);
    }

    if (event_data->diff != NULL && resultType == MODIFIED) {
        cJSON_AddStringToObject(registry, "content_changes", event_data->diff);
    }

    send_syscheck_msg(json_event);

end:
    os_free(event_data->diff);
    cJSON_Delete(json_event);
}

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

registry_t *fim_registry_configuration(const char *key, int arch) {
    int it = 0;
    int top = 0;
    int match;
    registry_t *ret = NULL;

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
int fim_registry_validate_recursion_level(const char *key_path, const registry_t *configuration) {
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
int fim_registry_validate_ignore(const char *entry, const registry_t *configuration, int key) {
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
 * @brief Checks if a specific folder has been configured to be checked with a specific restriction
 *
 * @param entry A string holding the full path of the key or the name of the value to be validated.
 * @param restriction The regex restriction to be checked
 * @return 1 if the folder has been configured with the specified restriction, 0 if not
 */
int fim_registry_validate_restrict(const char *entry, OSMatch *restriction) {
    if (entry == NULL) {
        merror(NULL_ERROR);
        return 1;
    }

    // Restrict file types
    if (restriction) {
        if (!OSMatch_Execute(entry, strlen(entry), restriction)) {
            mdebug2(FIM_FILE_IGNORE_RESTRICT, entry, restriction->raw);
            return 1;
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
            "%s:%s:%s:%s:%s:%lu",
            data->permissions ? data->permissions : "",
            data->uid ? data->uid : "",
            data->owner ? data->owner : "",
            data->gid ? data->gid : "",
            data->group ? data->group : "",
            data->mtime);

    os_calloc(size + 1, sizeof(char), checksum);
    snprintf(checksum,
            size + 1,
            "%s:%s:%s:%s:%s:%lu:%d",
            data->permissions ? data->permissions : "",
            data->uid ? data->uid : "",
            data->gid ? data->gid : "",
            data->owner ? data->owner : "",
            data->group ? data->group : "",
            data->mtime,
            data->architecture);

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
            "%u:%llu:%s:%s:%s",
            data->type,
            data->size,
            data->hash_md5 ,
            data->hash_sha1,
            data->hash_sha256);

    os_calloc(size + 1, sizeof(char), checksum);
    snprintf(checksum,
            size + 1,
            "%u:%llu:%s:%s:%s",
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
void fim_registry_init_digests(int opts, EVP_MD_CTX *md5_ctx, EVP_MD_CTX *sha1_ctx, EVP_MD_CTX *sha256_ctx) {
    if (opts & CHECK_MD5SUM) {
        EVP_DigestInit(md5_ctx, EVP_md5());
    }

    if (opts & CHECK_SHA1SUM) {
        EVP_DigestInit(sha1_ctx, EVP_sha1());
    }

    if (opts & CHECK_SHA256SUM) {
        EVP_DigestInit(sha256_ctx, EVP_sha256());
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
                                 EVP_MD_CTX *md5_ctx,
                                 EVP_MD_CTX *sha1_ctx,
                                 EVP_MD_CTX *sha256_ctx) {
    if (opts & CHECK_MD5SUM) {
        EVP_DigestUpdate(md5_ctx, buffer, length);
    }

    if (opts & CHECK_SHA1SUM) {
        EVP_DigestUpdate(sha1_ctx, buffer, length);
    }

    if (opts & CHECK_SHA256SUM) {
        EVP_DigestUpdate(sha256_ctx, buffer, length);
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
                                EVP_MD_CTX *md5_ctx,
                                EVP_MD_CTX *sha1_ctx,
                                EVP_MD_CTX *sha256_ctx,
                                os_md5 md5_output,
                                os_sha1 sha1_output,
                                os_sha256 sha256_output) {
    unsigned char md5_digest[MD5_DIGEST_LENGTH];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    int n;

    if (opts & CHECK_MD5SUM) {
        EVP_DigestFinal(md5_ctx, md5_digest, NULL);
        for (n = 0; n < MD5_DIGEST_LENGTH; n++) {
            snprintf(md5_output, 3, "%02x", md5_digest[n]);
            md5_output += 2;
        }
    }

    if (opts & CHECK_SHA1SUM) {
        EVP_DigestFinal(sha1_ctx, sha1_digest, NULL);
        for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
            snprintf(sha1_output, 3, "%02x", sha1_digest[n]);
            sha1_output += 2;
        }
    }

    if (opts & CHECK_SHA256SUM) {
        EVP_DigestFinal(sha256_ctx, sha256_digest, NULL);
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
void fim_registry_calculate_hashes(fim_entry *entry, registry_t *configuration, BYTE *data_buffer) {
    EVP_MD_CTX *md5_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *sha1_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *sha256_ctx = EVP_MD_CTX_new();

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
    fim_registry_init_digests(configuration->opts, md5_ctx, sha1_ctx, sha256_ctx);

    switch (entry->registry_entry.value->type) {
    case REG_SZ:
    case REG_EXPAND_SZ:
        fim_registry_update_digests(data_buffer, strlen((char *)data_buffer), configuration->opts, md5_ctx, sha1_ctx,
                                    sha256_ctx);
        break;
    case REG_MULTI_SZ:
        /* Print multiple strings */
        for (string_it = (char *)data_buffer; *string_it; string_it += strlen(string_it) + 1) {
            fim_registry_update_digests((BYTE *)string_it, strlen(string_it), configuration->opts, md5_ctx, sha1_ctx,
                                        sha256_ctx);
        }
        break;
    case REG_DWORD:
        length = snprintf((char *)buffer, OS_SIZE_2048, "%08x", *((unsigned int *)data_buffer));
        fim_registry_update_digests(buffer, length, configuration->opts, md5_ctx, sha1_ctx, sha256_ctx);
        break;
    default:
        for (unsigned int i = 0; i < entry->registry_entry.value->size; i++) {
            length = snprintf((char *)buffer, 3, "%02x", (unsigned int)data_buffer[i] & 0xFF);
            fim_registry_update_digests(buffer, length, configuration->opts, md5_ctx, sha1_ctx, sha256_ctx);
        }
        break;
    }

    fim_registry_final_digests(configuration->opts, md5_ctx, sha1_ctx, sha256_ctx,
                               entry->registry_entry.value->hash_md5, entry->registry_entry.value->hash_sha1,
                               entry->registry_entry.value->hash_sha256);

    EVP_MD_CTX_free(md5_ctx);
    EVP_MD_CTX_free(sha1_ctx);
    EVP_MD_CTX_free(sha256_ctx);
}

/**
 * @brief Free all memory associated with a registry key.
 *
 * @param data A fim_registry_key object to be free'd.
 */
void fim_registry_free_key(fim_registry_key *key) {
    if (key) {
        os_free(key->path);
        os_free(key->permissions);
        cJSON_Delete(key->perm_json);
        os_free(key->uid);
        os_free(key->gid);
        os_free(key->owner);
        os_free(key->group);
        free(key);
    }
}

/**
 * @brief Gets all information from a given registry key.
 *
 * @param key_handle A handle to the key whose information we want.
 * @param path A string holding the full path to the key we want to query.
 * @param configuration The confguration associated with the key.
 * @return A fim_registry_key object holding the information from the queried key, NULL on error.
 */
fim_registry_key *fim_registry_get_key_data(HKEY key_handle, const char *path, const registry_t *configuration) {
    fim_registry_key *key;

    os_calloc(1, sizeof(fim_registry_key), key);

    os_strdup(path, key->path);

    key->architecture = configuration->arch;

     if (configuration->opts & CHECK_OWNER) {
        key->owner = get_registry_user(path, &key->uid, key_handle);
    }

    if (configuration->opts & CHECK_GROUP) {
        key->group = get_registry_group(&key->gid, key_handle);
    }

    if (configuration->opts & CHECK_PERM) {
        int error;

        key->perm_json = NULL;
        error = get_registry_permissions(key_handle, &(key->perm_json));
        if (error) {
            mdebug1(FIM_EXTRACT_PERM_FAIL, path, error);
            fim_registry_free_key(key);
            return NULL;
        }

        decode_win_acl_json(key->perm_json);
        key->permissions = cJSON_PrintUnformatted(key->perm_json);
    }

    if (configuration->opts & CHECK_MTIME) {
        key->mtime = get_registry_mtime(key_handle);
    }

    fim_registry_get_checksum_key(key);

    return key;
}

/**
 * @brief Free all memory associated with a registry value.
 *
 * @param data A fim_registry_value_data object to be free'd.
 */
void fim_registry_free_value_data(fim_registry_value_data *data) {
    if (data) {
        os_free(data->value);
        free(data);
    }
}

void fim_registry_free_entry(fim_entry *entry) {
    if (entry) {
        fim_registry_free_key(entry->registry_entry.key);
        fim_registry_free_value_data(entry->registry_entry.value);
        os_free(entry);
    }
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
                     char* path,
                     int arch,
                     DWORD value_count,
                     DWORD max_value_length,
                     DWORD max_value_data_length,
                     TXN_HANDLE regval_txn_handler,
                     fim_val_txn_context_t *txn_ctx_regval) {
    fim_registry_value_data value_data;
    TCHAR *value_buffer;
    BYTE *data_buffer;
    DWORD i;
    fim_entry new;
    char *value_path;
    size_t value_path_length;
    registry_t *configuration = NULL;
    char* diff = NULL;

    value_data.architecture = arch;
    value_data.path = path;
    new.registry_entry.value = &value_data;
    new.registry_entry.key = NULL;

    os_calloc(max_value_length + 1, sizeof(TCHAR), value_buffer);
    os_calloc(max_value_data_length, sizeof(BYTE), data_buffer);

    for (i = 0; i < value_count; i++) {
        DWORD value_size = max_value_length + 1;
        DWORD data_size = max_value_data_length;
        DWORD data_type = 0;

        configuration = fim_registry_configuration(path, arch);
        if (configuration == NULL) {
            return;
        }

        if (RegEnumValue(key_handle, i, value_buffer, &value_size, NULL, &data_type, data_buffer, &data_size) !=
            ERROR_SUCCESS) {
            break;
        }

        new.registry_entry.value->value = value_buffer;
        new.registry_entry.value->type = data_type <= REG_QWORD ? data_type : REG_UNKNOWN;
        new.registry_entry.value->size = data_size;
        new.type = FIM_TYPE_REGISTRY;

        value_path_length = strlen(new.registry_entry.value->path) + strlen(new.registry_entry.value->value) + 2;

        os_malloc(value_path_length, value_path);
        snprintf(value_path, value_path_length, "%s\\%s", new.registry_entry.value->path, new.registry_entry.value->value);

        if (fim_registry_validate_ignore(value_path, configuration, 0)) {
            os_free(value_path);
            os_free(value_data.value);
            continue;
        }
        os_free(value_path);

        if (fim_registry_validate_restrict(new.registry_entry.value->value, configuration->restrict_value)) {
            continue;
        }

        fim_registry_calculate_hashes(&new, configuration, data_buffer);

        fim_registry_get_checksum_value(new.registry_entry.value);

        if (configuration->opts & CHECK_SEECHANGES) {
            diff = fim_registry_value_diff(new.registry_entry.value->path, new.registry_entry.value->value,
                                       (char *)data_buffer, new.registry_entry.value->type, configuration);
        }
        txn_ctx_regval->diff = diff;
        txn_ctx_regval->data = new.registry_entry.value;
        txn_ctx_regval->config = configuration;

        int result_transaction = fim_db_transaction_sync_row(regval_txn_handler, &new);

        if (result_transaction < 0) {
            mdebug2("dbsync transaction failed due to %d", result_transaction);
        }

        txn_ctx_regval->config = NULL;
    }

    new.registry_entry.value = NULL;
    os_free(value_data.value);
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
                  registry_t *parent_configuration,
                  TXN_HANDLE regkey_txn_handler,
                  TXN_HANDLE regval_txn_handler,
                  fim_val_txn_context_t *txn_ctx_regval,
                  fim_key_txn_context_t *txn_ctx_reg) {

    HKEY current_key_handle = NULL;
    REGSAM access_rights;
    DWORD sub_key_count = 0;
    DWORD value_count;
    DWORD max_value_length;
    DWORD max_value_data_length;
    FILETIME file_time = { 0 };
    DWORD i;
    fim_entry new;
    registry_t *configuration;
    int result_transaction = -1;

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
        fim_open_key(root_key_handle, new_full_key, new_sub_key, arch, mode, configuration, regkey_txn_handler,
                     regval_txn_handler, txn_ctx_regval, txn_ctx_reg);

        os_free(new_full_key);
    }

    // Restrict check
    if (fim_registry_validate_restrict(full_key, configuration->restrict_key)) {
        return;
    }

    // Done scanning sub_keys, trigger an alert on the current key if required.
    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = fim_registry_get_key_data(current_key_handle, full_key, configuration);
    new.registry_entry.value = NULL;

    if (new.registry_entry.key == NULL) {
        return;
    }

    txn_ctx_reg->key = new.registry_entry.key;
    txn_ctx_reg->config = configuration;

    result_transaction = fim_db_transaction_sync_row(regkey_txn_handler, &new);

    if(result_transaction < 0){
        merror("Dbsync registry transaction failed due to %d", result_transaction);
    }

    if (value_count) {
        fim_read_values(current_key_handle, new.registry_entry.key->path, new.registry_entry.key->architecture, value_count, max_value_length, max_value_data_length,
                        regval_txn_handler, txn_ctx_regval);
    }

    txn_ctx_reg->config = NULL;

    fim_registry_free_key(new.registry_entry.key);
    RegCloseKey(current_key_handle);
}

void fim_registry_scan() {
    HKEY root_key_handle = NULL;
    const char *sub_key = NULL;
    int i = 0;
    event_data_t evt_data_registry_key = { .report_event = true, .mode = FIM_SCHEDULED, .w_evt = NULL };
    fim_key_txn_context_t txn_ctx_reg = { .evt_data = &evt_data_registry_key, .config = NULL };
    TXN_HANDLE regkey_txn_handler = fim_db_transaction_start(FIMDB_REGISTRY_KEY_TXN_TABLE, registry_key_transaction_callback, &txn_ctx_reg);
    event_data_t evt_data_registry_value = { .report_event = true, .mode = FIM_SCHEDULED, .w_evt = NULL };
    fim_val_txn_context_t txn_ctx_regval = { .evt_data = &evt_data_registry_value, .config = NULL };
    TXN_HANDLE regval_txn_handler = fim_db_transaction_start(FIMDB_REGISTRY_VALUE_TXN_TABLE,
                                                             registry_value_transaction_callback, &txn_ctx_regval);

    /* Debug entries */
    mdebug1(FIM_WINREGISTRY_START);
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
                     NULL, regkey_txn_handler, regval_txn_handler, &txn_ctx_regval, &txn_ctx_reg);
    }
    txn_ctx_reg.key = NULL;
    txn_ctx_regval.data = NULL;
    fim_db_transaction_deleted_rows(regval_txn_handler, registry_value_transaction_callback, &txn_ctx_regval);
    fim_db_transaction_deleted_rows(regkey_txn_handler, registry_key_transaction_callback, &txn_ctx_reg);
    regkey_txn_handler = NULL;
    regval_txn_handler = NULL;

    mdebug1(FIM_WINREGISTRY_ENDED);

    if (_base_line == 0) {
        _base_line = 1;
    }
}

#endif
