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

static const char *FIM_EVENT_TYPE[] = { "added", "deleted", "modified" };

static const char *FIM_EVENT_MODE[] = { "scheduled", "realtime", "whodata" };


/* Check if the registry entry is valid */
int fim_set_root_key(HKEY *root_key_handle, const char *full_key, char **sub_key) {
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

fim_registry_key *fim_registry_get_key_data(HKEY key_handle, const registry *configuration) {
    return NULL;
}

cJSON *fim_registry_value_attributes_json(const fim_entry *data) {
    fim_registry_key *key_data = data->registry_entry.key;
    fim_registry_value_data *value_data = data->registry_entry.value;
    cJSON *attributes = cJSON_CreateObject();

    cJSON_AddStringToObject(attributes, "type", "registry_value");

    if (key_data->options & CHECK_TYPE) {
        cJSON_AddNumberToObject(attributes, "registry_type", value_data->type);
    }

    if (key_data->options & CHECK_SIZE) {
        cJSON_AddNumberToObject(attributes, "size", value_data->size);
    }

    if (key_data->options & CHECK_MTIME) {
        cJSON_AddNumberToObject(attributes, "mtime", value_data->mtime);
    }

    if (key_data->options & CHECK_MD5SUM) {
        cJSON_AddStringToObject(attributes, "hash_md5", value_data->hash_md5);
    }

    if (key_data->options & CHECK_SHA1SUM) {
        cJSON_AddStringToObject(attributes, "hash_sha1", value_data->hash_sha1);
    }

    if (key_data->options & CHECK_SHA256SUM) {
        cJSON_AddStringToObject(attributes, "hash_sha256", value_data->hash_sha256);
    }

    if (*value_data->checksum) {
        cJSON_AddStringToObject(attributes, "checksum", value_data->checksum);
    }

    return attributes;
}

cJSON *fim_registry_compare_value_attrs(const fim_entry *new_data, const fim_entry *old_data) {
    fim_registry_value_data *new_value = new_data->registry_entry.value;
    fim_registry_value_data *old_value = old_data->registry_entry.value;
    cJSON *changed_attributes = cJSON_CreateArray();

    if ((old_data->registry_entry.key->options & CHECK_SIZE) && old_value->size != new_value->size) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("size"));
    }

    if ((old_data->registry_entry.key->options & CHECK_TYPE) && old_value->type != new_value->type) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("type"));
    }

    if ((old_data->registry_entry.key->options & CHECK_MTIME) && old_value->mtime != new_value->mtime) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("mtime"));
    }

    if ((old_data->registry_entry.key->options & CHECK_MD5SUM) && (strcmp(old_value->hash_md5, new_value->hash_md5) != 0)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("md5"));
    }

    if ((old_data->registry_entry.key->options & CHECK_SHA1SUM) && (strcmp(old_value->hash_sha1, new_value->hash_sha1) != 0)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sha1"));
    }

    if ((old_data->registry_entry.key->options & CHECK_SHA256SUM) && (strcmp(old_value->hash_sha256, new_value->hash_sha256) != 0)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sha256"));
    }

    return changed_attributes;
}

cJSON *fim_registry_value_json_event(const fim_entry *new_data,
                                     const fim_entry *old_data,
                                     const registry *configuration,
                                     fim_event_mode mode,
                                     unsigned int type,
                                     __attribute__((unused)) whodata_evt *w_evt,
                                     const char *diff) {
    cJSON *changed_attributes;

    if (old_data != NULL) {
        changed_attributes = fim_registry_compare_value_attrs(new_data, old_data);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            cJSON_Delete(changed_attributes);
            return NULL;
        }
    }

    cJSON *json_event = cJSON_CreateObject();
    cJSON_AddStringToObject(json_event, "type", "event");

    cJSON *data = cJSON_CreateObject();
    cJSON_AddItemToObject(json_event, "data", data);

    char path[OS_SIZE_512];
    snprintf(path, OS_SIZE_512, "%s\\%s", new_data->registry_entry.key->path, new_data->registry_entry.value->name);
    cJSON_AddStringToObject(data, "path", path);
    cJSON_AddStringToObject(data, "mode", FIM_EVENT_MODE[mode]);
    cJSON_AddStringToObject(data, "type", FIM_EVENT_TYPE[type]);
    cJSON_AddNumberToObject(data, "timestamp", new_data->registry_entry.value->last_event);

    cJSON_AddItemToObject(data, "attributes", fim_registry_value_attributes_json(new_data));

    if (old_data) {
        cJSON_AddItemToObject(data, "changed_attributes", changed_attributes);
        cJSON_AddItemToObject(data, "old_attributes", fim_registry_value_attributes_json(old_data));
    }

    if (diff != NULL) {
        cJSON_AddStringToObject(data, "content_changes", diff);
    }

    if (configuration->tag != NULL) {
        cJSON_AddStringToObject(data, "tags", configuration->tag);
    }

    return json_event;
}

cJSON *fim_registry_key_attributes_json(const fim_registry_key *data) {
    cJSON *attributes = cJSON_CreateObject();

    cJSON_AddStringToObject(attributes, "type", "registry_key");

    if (data->options & CHECK_PERM) {
        cJSON_AddStringToObject(attributes, "perm", data->perm);
    }

    if (data->options & CHECK_OWNER) {
        cJSON_AddStringToObject(attributes, "uid", data->uid);
    }

    if (data->options & CHECK_GROUP) {
        cJSON_AddStringToObject(attributes, "gid", data->gid);
    }

    if (data->user_name) {
        cJSON_AddStringToObject(attributes, "user_name", data->user_name);
    }

    if (data->group_name) {
        cJSON_AddStringToObject(attributes, "group_name", data->group_name);
    }

    if (*data->checksum) {
        cJSON_AddStringToObject(attributes, "checksum", data->checksum);
    }

    return attributes;
}

cJSON *fim_registry_compare_key_attrs(const fim_registry_key *new_data, const fim_registry_key *old_data) {
    cJSON *changed_attributes = cJSON_CreateArray();

    if ((old_data->options & CHECK_PERM) && strcmp(old_data->perm, new_data->perm) != 0) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("permission"));
    }

    if (old_data->options & CHECK_OWNER) {
        if (old_data->uid && new_data->uid && strcmp(old_data->uid, new_data->uid) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("uid"));
        }

        if (old_data->user_name && new_data->user_name && strcmp(old_data->user_name, new_data->user_name) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("user_name"));
        }
    }

    if (old_data->options & CHECK_GROUP) {
        if (old_data->gid && new_data->gid && strcmp(old_data->gid, new_data->gid) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("gid"));
        }

        if (old_data->group_name && new_data->group_name && strcmp(old_data->group_name, new_data->group_name) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("group_name"));
        }
    }

    return changed_attributes;
}

cJSON *fim_registry_key_json_event(const fim_registry_key *new_data,
                                   const fim_registry_key *old_data,
                                   const registry *configuration,
                                   fim_event_mode mode,
                                   unsigned int type,
                                   __attribute__((unused)) whodata_evt *w_evt) {
    cJSON *changed_attributes;

    if (old_data != NULL) {
        changed_attributes = fim_registry_compare_key_attrs(new_data, old_data);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            cJSON_Delete(changed_attributes);
            return NULL;
        }
    }

    cJSON *json_event = cJSON_CreateObject();
    cJSON_AddStringToObject(json_event, "type", "event");

    cJSON *data = cJSON_CreateObject();
    cJSON_AddItemToObject(json_event, "data", data);

    cJSON_AddStringToObject(data, "path", new_data->path);
    cJSON_AddStringToObject(data, "mode", FIM_EVENT_MODE[mode]);
    cJSON_AddStringToObject(data, "type", FIM_EVENT_TYPE[type]);
    // cJSON_AddNumberToObject(data, "timestamp", new_data->last_event);

    cJSON_AddItemToObject(data, "attributes", fim_registry_key_attributes_json(new_data));

    if (old_data) {
        cJSON_AddItemToObject(data, "changed_attributes", changed_attributes);
        cJSON_AddItemToObject(data, "old_attributes", fim_registry_key_attributes_json(old_data));
    }

    if (configuration->tag != NULL) {
        cJSON_AddStringToObject(data, "tags", configuration->tag);
    }

    return json_event;
}

/**
 * @brief Check and trigger a FIM event on a registry.
 *
 * @param new New key data aquired from the actual registry entry.
 * @param saved Key registry information retrieved from the FIM DB.
 * @param configuration Configuration associated with the given registry.
 * @return 0 if no event was send, 1 if event was send, OS_INVALID on error.
 */
int fim_registry_event(const fim_entry *new,
                       const fim_entry *saved,
                       const registry *configuration,
                       fim_event_mode mode,
                       unsigned int event_type,
                       const char *diff) {
    cJSON *json_event = NULL;
    char *json_formated;

    if (new == NULL) {
        // This should never happen
        merror("LOGIC ERROR - new '%p' - saved '%p'", new, saved);
        return OS_INVALID;
    }

    if (new->registry_entry.key == NULL) {
        // This shouldn't happen either
        merror("LOGIC ERROR - Registry event with no new key data");
        return OS_INVALID;
    }

    if (new->type != FIM_TYPE_REGISTRY || saved ? saved->type != FIM_TYPE_REGISTRY : 0) {
        // This is just silly now
        merror("LOGIC ERROR - Entry type is not Registry - new '%d' - saved '%d'", new->type, saved->type);
        return OS_INVALID;
    }

    if (new->registry_entry.value != NULL) {
        json_event = fim_registry_value_json_event(new, saved, configuration, mode, event_type, NULL, diff);
    } else {
        json_event =
        fim_registry_key_json_event(new->registry_entry.key, saved->registry_entry.key, configuration, mode, event_type, NULL);
    }

    if (json_event == NULL) {
        // Nothing left to do.
        return 0;
    }

    if (fim_db_insert_registry(syscheck.database, new) != 0) {
        mwarn("Couldn't insert into DB");
    }

    if (_base_line) {
        json_formated = cJSON_PrintUnformatted(json_event);
        send_syscheck_msg(json_formated);
        os_free(json_formated);
    }

    cJSON_Delete(json_event);
    return 1;
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

        new->registry_entry.value->name = value_buffer;
        new->registry_entry.value->type = data_type;
        new->registry_entry.value->size = data_size;
        new->registry_entry.value->mode = FIM_SCHEDULED;

        saved->registry_entry.value =
        fim_db_get_registry_data(syscheck.database, new->registry_entry.key->id, new->registry_entry.value->name);

        if (value_configuration->opts | CHECK_SEECHANGES) {
            diff = fim_registry_value_diff(new->registry_entry.key->path, new->registry_entry.value->name, data_buffer, data_type);
        }

        fim_registry_event(new, saved, value_configuration, FIM_SCHEDULED,
                           saved->registry_entry.value == NULL ? FIM_ADD : FIM_MODIFIED, diff);

        fim_db_set_registry_data_scanned(syscheck.database, new->registry_entry.value->name, new->registry_entry.key->id);

        os_free(diff);

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
    new.registry_entry.key = fim_registry_get_key_data(current_key_handle, configuration);
    new.registry_entry.value = NULL;

    saved.type = FIM_TYPE_REGISTRY;
    saved.registry_entry.key = fim_db_get_registry_key(syscheck.database, full_key);
    saved.registry_entry.value = NULL;

    fim_registry_event(&new, &saved, configuration, FIM_SCHEDULED, saved.registry_entry.key == NULL ? FIM_ADD : FIM_MODIFIED, NULL);

    fim_db_set_registry_key_scanned(syscheck.database, new.registry_entry.key->path);

    if (value_count) {
        fim_read_values(current_key_handle, &new, &saved, configuration, value_count);
    }

    RegCloseKey(current_key_handle);
    return;
}

void fim_registry_scan() {
    HKEY root_key_handle = NULL;
    char *sub_key = NULL;
    int i = 0;

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
            mdebug1(FIM_INV_REG, syscheck.registry[i].entry, syscheck.registry[i].arch == ARCH_64BIT ? "[x64] " : "[x32]");
            *syscheck.registry[i].entry = '\0';
            continue;
        }

        fim_open_key(root_key_handle, syscheck.registry[i].entry, sub_key, &syscheck.registry[i]);
    }

    mdebug1(FIM_WINREGISTRY_ENDED);

    if (_base_line == 0) {
        _base_line = 1;
    }

    return;
}
#endif /* WIN32 */
