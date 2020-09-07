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


typedef struct __registry_key_t {
    const registry *configuration;
    const char *full_key;
    const char *sub_key;
} registry_key_t;

/* Check if the registry entry is valid */
int fim_set_root_key(HKEY *root_key_handle, registry_key_t *rkey, char *full_key, registry *configuration) {
    int root_key_length;

    if (root_key_handle == NULL || rkey == NULL || full_key == NULL || configuration == NULL) {
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

    rkey->full_key = full_key;
    rkey->configuration = configuration;
    rkey->sub_key = &rkey->full_key[root_key_length + 1];
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

int fim_init_registry_key(registry_key_t *rkey, const char *full_key, int arch) {
    registry *configuration;

    if (rkey == NULL || full_key == NULL) {
        return -1;
    }

    configuration = fim_registry_configuration(full_key, arch);

    if (configuration == NULL) {
        return -1;
    }

    rkey->full_key = full_key;
    rkey->configuration = configuration;
    rkey->sub_key = strchr(rkey->full_key, '\\');

    if (rkey->sub_key) {
        rkey->sub_key++;
    }

    return 0;
}

fim_registry_key *fim_registry_get_key_data(HKEY key_handle, registry_key_t *rkey) {
    return NULL;
}


cJSON *fim_registry_value_json_event(const fim_registry_value_data *new_data,
                                     const fim_registry_value_data *old_data,
                                     const registry *configuration,
                                     fim_event_mode mode,
                                     unsigned int type,
                                     __attribute__((unused)) whodata_evt *w_evt) {
    return NULL;
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
int fim_registry_event(const fim_entry *new, const fim_entry *saved, const registry *configuration, fim_event_mode mode, unsigned int event_type) {
    cJSON *json_event = NULL;
    char *json_formated;

    if (new == NULL || saved == NULL) {
        // This should never happen
        merror("LOGIC ERROR - new '%p' - saved '%p'", new, saved);
        return OS_INVALID;
    }

    if (new->registry_entry.key == NULL) {
        // This shouldn't happen either
        merror("LOGIC ERROR - Registry event with no new key data");
        return OS_INVALID;
    }

    // if (new->type != REGISTRY || saved->type != REGISTRY) {
    //     // This is just silly now
    // }

    if (new->registry_entry.value != NULL) {
        json_event = fim_registry_value_json_event(new->registry_entry.value, saved->registry_entry.value,
                                                   configuration, mode, event_type, NULL);
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


int fim_check_key(registry_key_t *rkey) {
    int ign_it;

    if (rkey == NULL || rkey->full_key == NULL) {
        return -1;
    }

    // TODO: Add recursion_level checks.

    /* Registry ignore list */
    if (syscheck.registry_ignore) {
        for (ign_it = 0; syscheck.registry_ignore[ign_it].entry; ign_it++) {
            if (syscheck.registry_ignore[ign_it].arch != rkey->configuration->arch) {
                continue;
            }

            if (strcasecmp(syscheck.registry_ignore[ign_it].entry, rkey->full_key) == 0) {
                mdebug2(FIM_IGNORE_ENTRY, "registry", rkey->full_key, syscheck.registry_ignore[ign_it].entry);
                return -1;
            }
        }
    }

    if (syscheck.registry_ignore_regex) {
        for (ign_it = 0; syscheck.registry_ignore_regex[ign_it].regex; ign_it++) {
            if (syscheck.registry_ignore_regex[ign_it].arch != rkey->configuration->arch) {
                continue;
            }

            if (OSMatch_Execute(rkey->full_key, strlen(rkey->full_key), syscheck.registry_ignore_regex[ign_it].regex)) {
                mdebug2(FIM_IGNORE_SREGEX, "registry", rkey->full_key, syscheck.registry_ignore_regex[ign_it].regex->raw);
                return -1;
            }
        }
    }

    return 0;
}

/* Query the key and get all its values */
void fim_read_values(const HKEY key_handle, fim_entry *new, fim_entry *saved, registry_key_t *rkey, DWORD value_count) {
    DWORD i;

    /* Variables for RegEnumValue */
    TCHAR value_buffer[MAX_VALUE_NAME + 1];
    TCHAR data_buffer[MAX_VALUE_NAME + 1];
    DWORD value_size;
    DWORD data_size;

    /* Data type for RegEnumValue */
    DWORD data_type = 0;

    // char *mt_data;

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, EVP_sha1());

    /* Clear the values for value_size and data_size */
    value_buffer[MAX_VALUE_NAME] = '\0';
    data_buffer[MAX_VALUE_NAME] = '\0';

    os_calloc(1, sizeof(fim_registry_value_data), new->registry_entry.value);

    for (i = 0; i < value_count; i++) {
        char value_path[MAX_KEY + 2];
        registry_key_t value_key;

        value_size = MAX_VALUE_NAME;
        data_size = MAX_VALUE_NAME;

        value_buffer[0] = '\0';
        data_buffer[0] = '\0';

        /* No more values available */
        if (RegEnumValue(key_handle, i, value_buffer, &value_size, NULL, &data_type, (LPBYTE)data_buffer, &data_size) != ERROR_SUCCESS) {
            break;
        }

        /* Check if no value name is specified */
        if (value_buffer[0] == '\0') {
            value_buffer[0] = '@';
            value_buffer[1] = '\0';
        }

        snprintf(value_path, MAX_KEY, "%s\\%s", rkey->full_key, value_buffer);
        if (fim_init_registry_key(&value_key, value_path, rkey->configuration->arch)) {
            mwarn("Failed to create child registry '%s'", value_path);
            continue;
        }

        if (fim_check_key(&value_key)) {
            continue;
        }

        new->registry_entry.value->name = value_buffer;
        new->registry_entry.value->type = data_type;
        new->registry_entry.value->size = data_size;
        new->registry_entry.value->mode = FIM_SCHEDULED;

        saved->registry_entry.value =
        fim_db_get_registry_data(syscheck.database, new->registry_entry.key->data_id, new->registry_entry.key->path);

        fim_registry_event(new, saved, value_key.configuration, FIM_SCHEDULED,
                           saved->registry_entry.value == NULL ? FIM_ADD : FIM_MODIFIED);

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
void fim_open_key(const HKEY root_key_handle, registry_key_t *rkey) {
    HKEY sub_key_handle = NULL;
    REGSAM access_rights;
    DWORD subkey_count = 0;
    DWORD value_count;
    FILETIME file_time = { 0 };
    DWORD i;
    fim_entry new, saved;

    if (rkey == NULL || root_key_handle == NULL || rkey->full_key == NULL) {
        return;
    }

    // Check ignore and recursion level restrictions.
    if (fim_check_key(rkey)) {
        return;
    }

    access_rights = KEY_READ | (rkey->configuration->arch == ARCH_32BIT ? KEY_WOW64_32KEY : KEY_WOW64_64KEY);

    if (RegOpenKeyEx(root_key_handle, rkey->sub_key, 0, access_rights, &sub_key_handle) != ERROR_SUCCESS) {
        mdebug1(FIM_REG_OPEN, rkey->sub_key, rkey->configuration->arch == ARCH_32BIT ? "[x32]" : "[x64]");
        return;
    }

    /* We use the class_name, subkey_count and the value count */
    if (RegQueryInfoKey(sub_key_handle, NULL, NULL, NULL, &subkey_count, NULL, NULL, &value_count, NULL, NULL, NULL,
                        &file_time) != ERROR_SUCCESS) {
        return;
    }

    /* Query each subkey and call open_key */
    for (i = 0; i < subkey_count; i++) {
        char new_key[MAX_KEY + 2];
        TCHAR sub_key_name_b[MAX_KEY_LENGTH + 1];
        registry_key_t child_key;
        DWORD sub_key_name_s = MAX_KEY_LENGTH;

        if (RegEnumKeyEx(sub_key_handle, i, sub_key_name_b, &sub_key_name_s, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            continue;
        }

        new_key[MAX_KEY + 1] = '\0';

        snprintf(new_key, MAX_KEY, "%s\\%s", rkey->full_key, sub_key_name_b);

        if (fim_init_registry_key(&child_key, new_key, rkey->configuration->arch)) {
            mwarn("Failed to create child registry '%s'", new_key);
            continue;
        }

        /* Open subkey */
        fim_open_key(root_key_handle, &child_key);
    }

    // Done scanning sub_keys, trigger an alert on the current key if required.
    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = fim_registry_get_key_data(sub_key_handle, rkey);
    new.registry_entry.value = NULL;

    saved.type = FIM_TYPE_REGISTRY;
    saved.registry_entry.key = fim_db_get_registry_key(syscheck.database, rkey->full_key);
    saved.registry_entry.value = NULL;

    fim_registry_event(&new, &saved, rkey->configuration, FIM_SCHEDULED, saved.registry_entry.key == NULL ? FIM_ADD : FIM_MODIFIED);

    if (value_count) {
        fim_read_values(sub_key_handle, &new, &saved, rkey, value_count);
    }

    RegCloseKey(sub_key_handle);
    return;
}

void fim_registry_scan() {
    HKEY root_key_handle = NULL;
    registry_key_t rkey;
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

        if (fim_set_root_key(&root_key_handle, &rkey, syscheck.registry[i].entry, &syscheck.registry[i]) != 0) {
            mdebug1(FIM_INV_REG, syscheck.registry[i].entry, syscheck.registry[i].arch == ARCH_64BIT ? "[x64] " : "[x32]");
            *syscheck.registry[i].entry = '\0';
            continue;
        }

        fim_open_key(root_key_handle, &rkey);
    }

    mdebug1(FIM_WINREGISTRY_ENDED);

    if (_base_line == 0) {
        _base_line = 1;
    }

    return;
}
#endif /* WIN32 */
