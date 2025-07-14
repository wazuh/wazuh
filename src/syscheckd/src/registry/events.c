/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include "../../include/syscheck.h"

static const char *FIM_EVENT_TYPE_ARRAY[] = { "added", "deleted", "modified" };

static const char *FIM_EVENT_MODE[] = { "scheduled", "realtime", "whodata" };

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
    [REG_UNKNOWN] = "REG_UNKNOWN"
};


void fim_calculate_dbsync_difference_key(const fim_registry_key* registry_data,
                                         const registry_t *configuration,
                                         const cJSON* old_data,
                                         cJSON* changed_attributes,
                                         cJSON* old_attributes) {

    if (old_attributes == NULL || changed_attributes == NULL || !cJSON_IsArray(changed_attributes)) {
        return; //LCOV_EXCL_LINE
    }
    cJSON *aux = NULL;

    cJSON_AddStringToObject(old_attributes, "type", "registry_key");

    if (configuration->opts & CHECK_PERM) {
        if (aux = cJSON_GetObjectItem(old_data, "permissions"), aux != NULL) {
            cJSON_AddItemToObject(old_attributes, "permissions", cJSON_Parse(cJSON_GetStringValue(aux)));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("permissions"));
        } else {
            cJSON_AddItemToObject(old_attributes, "permissions", cJSON_Parse(registry_data->permissions));
        }
    }

    if (configuration->opts & CHECK_OWNER) {
        if (aux = cJSON_GetObjectItem(old_data, "uid"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "uid", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("uid"));
        } else {
            cJSON_AddStringToObject(old_attributes, "uid", registry_data->uid);
        }

        if (aux = cJSON_GetObjectItem(old_data, "owner"), aux != NULL) {
            char *username = cJSON_GetStringValue(aux);
            cJSON_AddStringToObject(old_attributes, "owner", username);
            // AD might fail to solve the owner, we don't trigger an event if the owner is empty
            if (username != NULL && *username != '\0') {
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("owner"));
            }
        } else {
            cJSON_AddStringToObject(old_attributes, "owner", registry_data->owner);
        }
    }

    if (configuration->opts & CHECK_GROUP) {
        if (aux = cJSON_GetObjectItem(old_data, "gid"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "gid", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("gid"));
        } else {
            cJSON_AddStringToObject(old_attributes, "gid", registry_data->uid);
        }
        if (aux = cJSON_GetObjectItem(old_data, "group"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "group", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("group"));
        } else {
            cJSON_AddStringToObject(old_attributes, "group", registry_data->group);
        }
    }

    if (configuration->opts & CHECK_MTIME) {
         if (aux = cJSON_GetObjectItem(old_data, "mtime"), aux != NULL) {
            cJSON_AddNumberToObject(old_attributes, "mtime", aux->valueint);
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("mtime"));
        } else {
            cJSON_AddNumberToObject(old_attributes, "mtime", registry_data->mtime);
        }
    }

    if (*registry_data->checksum) {
        cJSON_AddStringToObject(old_attributes, "checksum", registry_data->checksum);
    }

}

void fim_calculate_dbsync_difference_value(const fim_registry_value_data* value_data,
                                           const registry_t* configuration,
                                           const cJSON* old_data,
                                           cJSON* changed_attributes,
                                           cJSON* old_attributes) {
    if (value_data == NULL || old_attributes == NULL ||
        changed_attributes == NULL || !cJSON_IsArray(changed_attributes)) {
        return; //LCOV_EXCL_LINE
    }

    cJSON *aux = NULL;

    cJSON_AddStringToObject(old_attributes, "type", "registry_value");

    if (configuration->opts & CHECK_SIZE) {
        if (aux = cJSON_GetObjectItem(old_data, "size"), aux != NULL) {
            cJSON_AddNumberToObject(old_attributes, "size", aux->valueint);
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("size"));
        } else {
            cJSON_AddNumberToObject(old_attributes, "size", value_data->size);
        }
    }

    if (configuration->opts & CHECK_TYPE) {
        if (aux = cJSON_GetObjectItem(old_data, "type"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "type", VALUE_TYPE[aux->valueint]);
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("type"));
        } else {
            cJSON_AddStringToObject(old_attributes, "type", VALUE_TYPE[value_data->type]);
        }
    }

    if (configuration->opts & CHECK_MD5SUM) {
        if (aux = cJSON_GetObjectItem(old_data, "hash_md5"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "hash_md5", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("md5"));
        } else {
            cJSON_AddStringToObject(old_attributes, "hash_md5", value_data->hash_md5);
        }
    }

    if (configuration->opts & CHECK_SHA1SUM) {
        if (aux = cJSON_GetObjectItem(old_data, "hash_sha1"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "hash_sha1", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sha1"));
        } else {
            cJSON_AddStringToObject(old_attributes, "hash_sha1", value_data->hash_sha1);
        }
    }

    if (configuration->opts & CHECK_SHA256SUM) {
        if (aux = cJSON_GetObjectItem(old_data, "hash_sha256"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "hash_sha256", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("sha256"));
        } else {
            cJSON_AddStringToObject(old_attributes, "hash_sha256", value_data->hash_sha256);
        }
    }
}

cJSON *fim_registry_value_attributes_json(const cJSON* dbsync_event, const fim_registry_value_data *data,
                                          const registry_t *configuration) {

    cJSON *attributes = cJSON_CreateObject();

    cJSON_AddStringToObject(attributes, "type", "registry_value");

    if (data) {
        if (configuration->opts & CHECK_TYPE) {
            cJSON_AddStringToObject(attributes, "type", VALUE_TYPE[data->type]);
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

    } else {
        cJSON *type, *checksum, *sha256, *md5, *sha1, *size;

        if (type = cJSON_GetObjectItem(dbsync_event, "type"), type != NULL) {
            if (configuration->opts & CHECK_TYPE) {
                cJSON_AddStringToObject(attributes, "type", VALUE_TYPE[type->valueint]);
            }
        }

        if (configuration->opts & CHECK_SIZE) {
            if (size = cJSON_GetObjectItem(dbsync_event, "size"), size != NULL) {
                cJSON_AddNumberToObject(attributes, "size", size->valueint);
            }
        }

        if (configuration->opts & CHECK_MD5SUM) {
            if (md5 = cJSON_GetObjectItem(dbsync_event, "hash_md5"), md5 != NULL){
                cJSON_AddStringToObject(attributes, "hash_md5", cJSON_GetStringValue(md5));
            }
        }

        if (configuration->opts & CHECK_SHA1SUM) {
            if (sha1 = cJSON_GetObjectItem(dbsync_event, "hash_sha1"), sha1 != NULL){
                cJSON_AddStringToObject(attributes, "hash_sha1", cJSON_GetStringValue(sha1));
            }
        }

        if (configuration->opts & CHECK_SHA256SUM) {
            if (sha256 = cJSON_GetObjectItem(dbsync_event, "hash_sha256"), sha256 != NULL){
                cJSON_AddStringToObject(attributes, "hash_sha256", cJSON_GetStringValue(sha256));
            }
        }

        if (checksum = cJSON_GetObjectItem(dbsync_event, "checksum"), checksum != NULL){
            cJSON_AddStringToObject(attributes, "checksum", cJSON_GetStringValue(checksum));
        }

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
                                        const registry_t *configuration) {
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


// LCOV_EXCL_START
// This function is not used for now, as it's ment to be used on event based monitoring.
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
                                     const registry_t *configuration,
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
    cJSON_AddNumberToObject(data, "version", 2.0);
    cJSON_AddStringToObject(data, "mode", FIM_EVENT_MODE[mode]);
    cJSON_AddStringToObject(data, "type", FIM_EVENT_TYPE_ARRAY[type]);
    cJSON_AddStringToObject(data, "architecture", new_data->registry_entry.key->architecture == ARCH_32BIT ? "[x32]" : "[x64]");
    cJSON_AddStringToObject(data, "value", new_data->registry_entry.value->value);

    //cJSON_AddItemToObject(data, "attributes",
    //                      fim_registry_value_attributes_json(new_data->registry_entry.value, configuration));

    if (old_data != NULL && old_data->registry_entry.value != NULL) {
        cJSON_AddItemToObject(data, "changed_attributes", changed_attributes);
        //cJSON_AddItemToObject(data, "old_attributes",
        //                      fim_registry_value_attributes_json(old_data->registry_entry.value, configuration));
    }

    if (diff != NULL) {
        cJSON_AddStringToObject(data, "content_changes", diff);
    }

    if (configuration->tag != NULL) {
        cJSON_AddStringToObject(data, "tags", configuration->tag);
    }

    return json_event;
}
// LCOV_EXCL_STOP

/**
 * @brief Create a cJSON object holding the attributes associated with a fim_registry_key according to its
 * configuration.
 *
 * @param data A fim_registry_key object holding the key attributes to be tranlated.
 * @param configuration The configuration associated with the registry key.
 * @return A pointer to a cJSON object the translated key attributes.
 */
cJSON *fim_registry_key_attributes_json(const cJSON* dbsync_event, const fim_registry_key *data, const registry_t *configuration) {
    cJSON *attributes = cJSON_CreateObject();

    cJSON_AddStringToObject(attributes, "type", "registry_key");

    if (data) {
        if (configuration->opts & CHECK_PERM) {
            cJSON_AddItemToObject(attributes, "permissions", cJSON_Parse(data->permissions));
        }

        if (configuration->opts & CHECK_OWNER) {
            cJSON_AddStringToObject(attributes, "uid", data->uid);

            if (data->owner) {
                cJSON_AddStringToObject(attributes, "owner", data->owner);
            }
        }

        if (configuration->opts & CHECK_GROUP) {
            cJSON_AddStringToObject(attributes, "gid", data->gid);

            if (data->group) {
                cJSON_AddStringToObject(attributes, "group", data->group);
            }
        }

        if (configuration->opts & CHECK_MTIME) {
            cJSON_AddNumberToObject(attributes, "mtime", data->mtime);
        }

        if (*data->checksum) {
            cJSON_AddStringToObject(attributes, "checksum", data->checksum);
        }
    } else {
        cJSON *permissions, *uid, *owner, *gid, *group, *mtime, *checksum;

        if (configuration->opts & CHECK_PERM) {
            if (permissions = cJSON_GetObjectItem(dbsync_event, "permissions"), permissions != NULL) {
                cJSON_AddItemToObject(attributes, "permissions", cJSON_Parse(cJSON_GetStringValue(permissions)));
            }
        }

        if (configuration->opts & CHECK_OWNER) {
            if (uid = cJSON_GetObjectItem(dbsync_event, "uid"), uid != NULL) {
                cJSON_AddStringToObject(attributes, "uid", cJSON_GetStringValue(uid));
            }

            if (owner = cJSON_GetObjectItem(dbsync_event, "owner"), owner != NULL) {
                cJSON_AddStringToObject(attributes, "owner", cJSON_GetStringValue(owner));
            }

        }

        if (configuration->opts & CHECK_GROUP) {
            if (gid = cJSON_GetObjectItem(dbsync_event, "gid"), gid != NULL) {
                cJSON_AddStringToObject(attributes, "gid", cJSON_GetStringValue(gid));
            }

            if (group = cJSON_GetObjectItem(dbsync_event, "group"), group != NULL) {
                cJSON_AddStringToObject(attributes, "group", cJSON_GetStringValue(group));
            }

        }

        if (configuration->opts & CHECK_MTIME) {
            if (mtime = cJSON_GetObjectItem(dbsync_event, "mtime"), mtime != NULL) {
                cJSON_AddNumberToObject(attributes, "mtime", mtime->valueint);
            }
        }

        if (checksum = cJSON_GetObjectItem(dbsync_event, "checksum"), checksum != NULL) {
            cJSON_AddStringToObject(attributes, "checksum", cJSON_GetStringValue(checksum));
        }

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
                                      const registry_t *configuration) {
    cJSON *changed_attributes = cJSON_CreateArray();

    if ((configuration->opts & CHECK_PERM) && strcmp(old_data->permissions, new_data->permissions) != 0) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("permissions"));
    }

    if (configuration->opts & CHECK_OWNER) {
        if (old_data->uid && new_data->uid && strcmp(old_data->uid, new_data->uid) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("uid"));
        }

        // AD might fail to solve the owner, we don't trigger an event if the owner is empty
        if (old_data->owner && *old_data->owner != '\0' && new_data->owner &&
            *new_data->owner != '\0' && strcmp(old_data->owner, new_data->owner) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("owner"));
        }
    }

    if (configuration->opts & CHECK_GROUP) {
        if (old_data->gid && new_data->gid && strcmp(old_data->gid, new_data->gid) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("gid"));
        }

        if (old_data->group && new_data->group && strcmp(old_data->group, new_data->group) != 0) {
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("group"));
        }
    }

    if ((configuration->opts & CHECK_MTIME) && old_data->mtime != new_data->mtime) {
        cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("mtime"));
    }

    return changed_attributes;
}


// LCOV_EXCL_START
// These functions are not used for now, as their are ment to be used on event based monitoring.
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
                                   const registry_t *configuration,
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
    cJSON_AddNumberToObject(data, "version", 2.0);
    cJSON_AddStringToObject(data, "mode", FIM_EVENT_MODE[mode]);
    cJSON_AddStringToObject(data, "type", FIM_EVENT_TYPE_ARRAY[type]);
    cJSON_AddStringToObject(data, "architecture", new_data->architecture == ARCH_32BIT ? "[x32]" : "[x64]");

    //cJSON_AddItemToObject(data, "attributes", fim_registry_key_attributes_json(new_data, configuration));

    if (old_data) {
        cJSON_AddItemToObject(data, "changed_attributes", changed_attributes);
        //cJSON_AddItemToObject(data, "old_attributes", fim_registry_key_attributes_json(old_data, configuration));
    }

    if (configuration->tag != NULL) {
        cJSON_AddStringToObject(data, "tags", configuration->tag);
    }

    return json_event;
}

cJSON *fim_registry_event(const fim_entry *new,
                          const fim_entry *saved,
                          const registry_t *configuration,
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
// LCOV_EXCL_STOP

#endif
