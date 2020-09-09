/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include "../syscheck.h"

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
