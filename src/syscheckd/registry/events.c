/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include "../syscheck.h"

static const char *FIM_EVENT_TYPE[] = { "added", "deleted", "modified" };

static const char *FIM_EVENT_MODE[] = { "scheduled", "realtime", "whodata" };

cJSON *fim_registry_value_attributes_json(const fim_registry_value_data *data, const registry *configuration) {
    static const char *VALUE_TYPE[] = {
        [REG_NONE] = "REG_NONE",
        [REG_SZ] = "REG_SZ",
        [REG_EXPAND_SZ] = "REG_EXPAND_SZ",
        [REG_BINARY] = "REG_BINARY",
        [REG_DWORD] = "REG_DWORD",
        [REG_DWORD_BIG_ENDIAN] = "REG_DWORD_BIG_ENDIAN",
        [REG_LINK] = "REG_LINK",
        [REG_MULTI_SZ] = "REG_MULTI_SZ",
        [REG_RESOURCE_LIST] = "REG_RESOURCE_LIST",
        [REG_FULL_RESOURCE_DESCRIPTOR] = "REG_FULL_RESOURCE_DESCRIPTOR",
        [REG_RESOURCE_REQUIREMENTS_LIST] = "REG_RESOURCE_REQUIREMENTS_LIST",
        [REG_QWORD] = "REG_QWORD",
    };

    cJSON *attributes = cJSON_CreateObject();

    cJSON_AddStringToObject(attributes, "type", "registry_value");

    if (configuration->opts & CHECK_TYPE && data->type <= REG_QWORD) {
        cJSON_AddStringToObject(attributes, "value_type", VALUE_TYPE[data->type]);
    }

    if (configuration->opts & CHECK_SIZE) {
        cJSON_AddNumberToObject(attributes, "size", data->size);
    }

    if (configuration->opts & CHECK_MD5SUM) {
        cJSON_AddStringToObject(attributes, "hash_md5", data->hash_md5);
    }

    if (configuration->opts & CHECK_SHA1SUM) {
        cJSON_AddStringToObject(attributes, "hash_sha1", data->hash_sha1);
    }

    if (configuration->opts & CHECK_SHA256SUM) {
        cJSON_AddStringToObject(attributes, "hash_sha256", data->hash_sha256);
    }

    if (*data->checksum) {
        cJSON_AddStringToObject(attributes, "checksum", data->checksum);
    }

    return attributes;
}

/**
 * @brief Compare new and old attributes from a registry value and return an array specifying which of them changed.
 *
 * @param new_data A fim_registry_value_data object holding the most recent information associated with a registry
 * value.
 * @param old_data A fim_registry_value_data object holding information associated with a registry value retrieved from
 * the FIM DB.
 * @param configuration The configuration associated with the registry value.
 * @return A pointer to a cJSON array holding strings with the changed attributes.
 */
cJSON *fim_registry_compare_value_attrs(const fim_registry_value_data *new_data,
                                        const fim_registry_value_data *old_data,
                                        const registry *configuration) {
    cJSON *changed_attributes = cJSON_CreateArray();

    if ((configuration->opts & CHECK_SIZE) && old_data->size != new_data->size) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("size"));
    }

    if ((configuration->opts & CHECK_TYPE) && old_data->type != new_data->type) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("type"));
    }

    if ((configuration->opts & CHECK_MD5SUM) && (strcmp(old_data->hash_md5, new_data->hash_md5) != 0)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("md5"));
    }

    if ((configuration->opts & CHECK_SHA1SUM) && (strcmp(old_data->hash_sha1, new_data->hash_sha1) != 0)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sha1"));
    }

    if ((configuration->opts & CHECK_SHA256SUM) && (strcmp(old_data->hash_sha256, new_data->hash_sha256) != 0)) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sha256"));
    }

    return changed_attributes;
}

/**
 * @brief Generate a registry value event from the provided information.
 *
 * @param new_data A fim_entry object holding the most recent information associated with a registry value.
 * @param old_data A fim_entry object holding information associated with a registry value retrieved from the FIM DB.
 * @param configuration The configuration associated with the registry value.
 * @param mode A value specifying if the event has been triggered in scheduled, realtime or whodata mode.
 * @param type A value specifying if the event corresponds to an add, delete or modify event.
 * @param w_evt A whodata object holding information corresponding to the event.
 * @param diff A string holding the change in the value content.
 * @return A pointer to a cJSON object holding the FIM event, NULL on error or if no event is generated.
 */
cJSON *fim_registry_value_json_event(const fim_entry *new_data,
                                     const fim_entry *old_data,
                                     const registry *configuration,
                                     fim_event_mode mode,
                                     unsigned int type,
                                     __attribute__((unused)) whodata_evt *w_evt,
                                     const char *diff) {
    cJSON *changed_attributes = NULL;

    if (old_data != NULL && old_data->registry_entry.value != NULL) {
        changed_attributes = fim_registry_compare_value_attrs(new_data->registry_entry.value,
                                                              old_data->registry_entry.value, configuration);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            cJSON_Delete(changed_attributes);
            return NULL;
        }
    }

    cJSON *json_event = cJSON_CreateObject();
    cJSON_AddStringToObject(json_event, "type", "event");

    cJSON *data = cJSON_CreateObject();
    cJSON_AddItemToObject(json_event, "data", data);

    cJSON_AddStringToObject(data, "path", new_data->registry_entry.key->path);
    cJSON_AddStringToObject(data, "mode", FIM_EVENT_MODE[mode]);
    cJSON_AddStringToObject(data, "type", FIM_EVENT_TYPE[type]);
    cJSON_AddStringToObject(data, "arch", new_data->registry_entry.key->arch == ARCH_32BIT ? "[x32]" : "[x64]");
    cJSON_AddStringToObject(data, "value_name", new_data->registry_entry.value->name);
    cJSON_AddNumberToObject(data, "timestamp", new_data->registry_entry.value->last_event);

    cJSON_AddItemToObject(data, "attributes",
                          fim_registry_value_attributes_json(new_data->registry_entry.value, configuration));

    if (old_data != NULL && old_data->registry_entry.value != NULL) {
        cJSON_AddItemToObject(data, "changed_attributes", changed_attributes);
        cJSON_AddItemToObject(data, "old_attributes",
                              fim_registry_value_attributes_json(old_data->registry_entry.value, configuration));
    }

    if (diff != NULL) {
        cJSON_AddStringToObject(data, "content_changes", diff);
    }

    if (configuration->tag != NULL) {
        cJSON_AddStringToObject(data, "tags", configuration->tag);
    }

    return json_event;
}

/**
 * @brief Create a cJSON object holding the attributes associated with a fim_registry_key according to its
 * configuration.
 *
 * @param data A fim_registry_key object holding the key attributes to be tranlated.
 * @param configuration The configuration associated with the registry key.
 * @return A pointer to a cJSON object the translated key attributes.
 */
cJSON *fim_registry_key_attributes_json(const fim_registry_key *data, const registry *configuration) {
    cJSON *attributes = cJSON_CreateObject();

    cJSON_AddStringToObject(attributes, "type", "registry_key");

    if (configuration->opts & CHECK_PERM) {
        cJSON_AddStringToObject(attributes, "perm", data->perm);
    }

    if (configuration->opts & CHECK_OWNER) {
        cJSON_AddStringToObject(attributes, "uid", data->uid);

        if (data->user_name) {
            cJSON_AddStringToObject(attributes, "user_name", data->user_name);
        }
    }

    if (configuration->opts & CHECK_GROUP) {
        cJSON_AddStringToObject(attributes, "gid", data->gid);

        if (data->group_name) {
            cJSON_AddStringToObject(attributes, "group_name", data->group_name);
        }
    }

    if (configuration->opts & CHECK_MTIME) {
        cJSON_AddNumberToObject(attributes, "mtime", data->mtime);
    }

    if (*data->checksum) {
        cJSON_AddStringToObject(attributes, "checksum", data->checksum);
    }

    return attributes;
}

/**
 * @brief Compare new and old attributes from a registry key and return an array specifying which of them changed.
 *
 * @param new_data A fim_registry_key object holding the most recent information associated with a registry key.
 * @param old_data A fim_registry_key object holding information associated with a registry key retrieved from the FIM
 * DB.
 * @param configuration The configuration associated with the registry key.
 * @return A pointer to a cJSON array holding strings with the changed attributes.
 */
cJSON *fim_registry_compare_key_attrs(const fim_registry_key *new_data,
                                      const fim_registry_key *old_data,
                                      const registry *configuration) {
    cJSON *changed_attributes = cJSON_CreateArray();

    if ((configuration->opts & CHECK_PERM) && strcmp(old_data->perm, new_data->perm) != 0) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("permission"));
    }

    if (configuration->opts & CHECK_OWNER) {
        if (old_data->uid && new_data->uid && strcmp(old_data->uid, new_data->uid) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("uid"));
        }

        if (old_data->user_name && new_data->user_name && strcmp(old_data->user_name, new_data->user_name) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("user_name"));
        }
    }

    if (configuration->opts & CHECK_GROUP) {
        if (old_data->gid && new_data->gid && strcmp(old_data->gid, new_data->gid) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("gid"));
        }

        if (old_data->group_name && new_data->group_name && strcmp(old_data->group_name, new_data->group_name) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("group_name"));
        }
    }

    if ((configuration->opts & CHECK_MTIME) && old_data->mtime != new_data->mtime) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("mtime"));
    }

    return changed_attributes;
}

/**
 * @brief Generate a registry key event from the provided information.
 *
 * @param new_data A fim_registry_key object holding the most recent information associated with a registry key.
 * @param old_data A fim_registry_key object holding information associated with a registry key retrieved from the FIM
 * DB.
 * @param configuration The configuration associated with the registry key.
 * @param mode A value specifying if the event has been triggered in scheduled, realtime or whodata mode.
 * @param type A value specifying if the event corresponds to an add, delete or modify event.
 * @param w_evt A whodata object holding information corresponding to the event.
 * @return A pointer to a cJSON object holding the FIM event, NULL on error.
 */
cJSON *fim_registry_key_json_event(const fim_registry_key *new_data,
                                   const fim_registry_key *old_data,
                                   const registry *configuration,
                                   fim_event_mode mode,
                                   unsigned int type,
                                   __attribute__((unused)) whodata_evt *w_evt) {
    cJSON *changed_attributes;

    if (old_data != NULL) {
        changed_attributes = fim_registry_compare_key_attrs(new_data, old_data, configuration);

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
    cJSON_AddStringToObject(data, "arch", new_data->arch == ARCH_32BIT ? "[x32]" : "[x64]");
    cJSON_AddNumberToObject(data, "timestamp", new_data->last_event);

    cJSON_AddItemToObject(data, "attributes", fim_registry_key_attributes_json(new_data, configuration));

    if (old_data) {
        cJSON_AddItemToObject(data, "changed_attributes", changed_attributes);
        cJSON_AddItemToObject(data, "old_attributes", fim_registry_key_attributes_json(old_data, configuration));
    }

    if (configuration->tag != NULL) {
        cJSON_AddStringToObject(data, "tags", configuration->tag);
    }

    return json_event;
}

cJSON *fim_registry_event(const fim_entry *new,
                          const fim_entry *saved,
                          const registry *configuration,
                          fim_event_mode mode,
                          unsigned int event_type,
                          __attribute__((unused)) whodata_evt *w_evt,
                          const char *diff) {
    cJSON *json_event = NULL;

    if (new == NULL) {
        mwarn(FIM_REGISTRY_EVENT_NULL_ENTRY);
        return NULL;
    }

    if (new->registry_entry.key == NULL) {
        mwarn(FIM_REGISTRY_EVENT_NULL_ENTRY_KEY);
        return NULL;
    }

    if (new->type != FIM_TYPE_REGISTRY) {
        mwarn(FIM_REGISTRY_EVENT_WRONG_ENTRY_TYPE);
        return NULL;
    }

    if (saved && saved->type != FIM_TYPE_REGISTRY) {
        mwarn(FIM_REGISTRY_EVENT_WRONG_SAVED_TYPE);
        return NULL;
    }

    if (new->registry_entry.value != NULL) {
        json_event = fim_registry_value_json_event(new, saved, configuration, mode, event_type, w_evt, diff);
    } else {
        json_event = fim_registry_key_json_event(new->registry_entry.key, saved ? saved->registry_entry.key : NULL,
                                                 configuration, mode, event_type, w_evt);
    }

    return json_event;
}

#endif
