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

    if (configuration->opts & CHECK_PERM) {
        if (aux = cJSON_GetObjectItem(old_data, "permissions"), aux != NULL) {
            cJSON_AddItemToObject(old_attributes, "permissions", cJSON_Parse(cJSON_GetStringValue(aux)));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("registry.permissions"));
        }
    }

    if (configuration->opts & CHECK_OWNER) {
        if (aux = cJSON_GetObjectItem(old_data, "uid"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "uid", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("registry.uid"));
        }

        if (aux = cJSON_GetObjectItem(old_data, "owner"), aux != NULL) {
            char *username = cJSON_GetStringValue(aux);
            // AD might fail to solve the owner, we don't trigger an event if the owner is empty
            if (username != NULL && *username != '\0') {
                cJSON_AddStringToObject(old_attributes, "owner", username);
                cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("registry.owner"));
            }
        }
    }

    if (configuration->opts & CHECK_GROUP) {
        if (aux = cJSON_GetObjectItem(old_data, "gid"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "gid", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("registry.gid"));
        }
        if (aux = cJSON_GetObjectItem(old_data, "group_"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "group", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("registry.group"));
        }
    }

    if (configuration->opts & CHECK_MTIME) {
         if (aux = cJSON_GetObjectItem(old_data, "mtime"), aux != NULL) {
            cJSON_AddNumberToObject(old_attributes, "mtime", aux->valueint);
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("registry.mtime"));
        }
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

    if (configuration->opts & CHECK_SIZE) {
        if (aux = cJSON_GetObjectItem(old_data, "size"), aux != NULL) {
            cJSON_AddNumberToObject(old_attributes, "size", aux->valueint);
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("registry.size"));
        }
    }

    bool has_data = false;
    cJSON* data = cJSON_CreateObject();

    if (configuration->opts & CHECK_TYPE) {
        if (aux = cJSON_GetObjectItem(old_data, "type"), aux != NULL) {
            cJSON_AddStringToObject(data, "type", VALUE_TYPE[aux->valueint]);
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("registry.data.type"));
            has_data = true;
        }
    }

    bool has_hash = false;
    cJSON* hash = cJSON_CreateObject();

    if (configuration->opts & CHECK_MD5SUM) {
        if (aux = cJSON_GetObjectItem(old_data, "hash_md5"), aux != NULL) {
            cJSON_AddStringToObject(hash, "md5", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("registry.data.hash.md5"));
            has_hash = true;
            has_data = true;
        }
    }

    if (configuration->opts & CHECK_SHA1SUM) {
        if (aux = cJSON_GetObjectItem(old_data, "hash_sha1"), aux != NULL) {
            cJSON_AddStringToObject(hash, "sha1", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("registry.data.hash.sha1"));
            has_hash = true;
            has_data = true;
        }
    }

    if (configuration->opts & CHECK_SHA256SUM) {
        if (aux = cJSON_GetObjectItem(old_data, "hash_sha256"), aux != NULL) {
            cJSON_AddStringToObject(hash, "sha256", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("registry.data.hash.sha256"));
            has_hash = true;
            has_data = true;
        }
    }

    if (has_hash) {
        cJSON_AddItemToObject(data, "hash", hash);
    } else {
        cJSON_Delete(hash);
    }

    if (has_data) {
        cJSON_AddItemToObject(old_attributes, "data", data);
    } else {
        cJSON_Delete(data);
    }
}

/**
 * @brief Create a cJSON object holding the attributes associated with a fim_registry_value_data according to its
 * configuration.
 *
 * @param dbsync_event A cJSON object holding the dbsync event.
 * @param data A fim_registry_value_data object holding the key attributes to be tranlated.
 * @param configuration The configuration associated with the registry key.
 * @return A pointer to a cJSON object the translated key attributes.
 */
cJSON *fim_registry_value_attributes_json(const cJSON* dbsync_event, const fim_registry_value_data *data,
                                          const registry_t *configuration) {

    cJSON *attributes = cJSON_CreateObject();

    if (data) {
        if (configuration->opts & CHECK_SIZE) {
            cJSON_AddNumberToObject(attributes, "size", data->size);
        }

        bool has_data = false;
        cJSON* data_json = cJSON_CreateObject();

        if (configuration->opts & CHECK_TYPE) {
            cJSON_AddStringToObject(data_json, "type", VALUE_TYPE[data->type]);
            has_data = true;
        }

        bool has_hash = false;
        cJSON* hash = cJSON_CreateObject();

        if (configuration->opts & CHECK_MD5SUM) {
            cJSON_AddStringToObject(hash, "md5", data->hash_md5);
            has_hash = true;
            has_data = true;
        }

        if (configuration->opts & CHECK_SHA1SUM) {
            cJSON_AddStringToObject(hash, "sha1", data->hash_sha1);
            has_hash = true;
            has_data = true;
        }

        if (configuration->opts & CHECK_SHA256SUM) {
            cJSON_AddStringToObject(hash, "sha256", data->hash_sha256);
            has_hash = true;
            has_data = true;
        }

        if (has_hash) {
            cJSON_AddItemToObject(data_json, "hash", hash);
        } else {
            cJSON_Delete(hash);
        }

        if (has_data) {
            cJSON_AddItemToObject(attributes, "data", data_json);
        } else {
            cJSON_Delete(data_json);
        }

    } else {
        cJSON *size, *type, *md5, *sha1, *sha256;

        if (configuration->opts & CHECK_SIZE) {
            if (size = cJSON_GetObjectItem(dbsync_event, "size"), size != NULL) {
                cJSON_AddNumberToObject(attributes, "size", size->valueint);
            }
        }

        bool has_data = false;
        cJSON* data_json = cJSON_CreateObject();

        if (type = cJSON_GetObjectItem(dbsync_event, "type"), type != NULL) {
            if (configuration->opts & CHECK_TYPE) {
                cJSON_AddStringToObject(data_json, "type", VALUE_TYPE[type->valueint]);
                has_data = true;
            }
        }

        bool has_hash = false;
        cJSON* hash = cJSON_CreateObject();

        if (configuration->opts & CHECK_MD5SUM) {
            if (md5 = cJSON_GetObjectItem(dbsync_event, "hash_md5"), md5 != NULL) {
                cJSON_AddStringToObject(hash, "md5", cJSON_GetStringValue(md5));
                has_hash = true;
                has_data = true;
            }
        }

        if (configuration->opts & CHECK_SHA1SUM) {
            if (sha1 = cJSON_GetObjectItem(dbsync_event, "hash_sha1"), sha1 != NULL) {
                cJSON_AddStringToObject(hash, "sha1", cJSON_GetStringValue(sha1));
                has_hash = true;
                has_data = true;
            }
        }

        if (configuration->opts & CHECK_SHA256SUM) {
            if (sha256 = cJSON_GetObjectItem(dbsync_event, "hash_sha256"), sha256 != NULL) {
                cJSON_AddStringToObject(hash, "sha256", cJSON_GetStringValue(sha256));
                has_hash = true;
                has_data = true;
            }
        }

        if (has_hash) {
            cJSON_AddItemToObject(data_json, "hash", hash);
        } else {
            cJSON_Delete(hash);
        }

        if (has_data) {
            cJSON_AddItemToObject(attributes, "data", data_json);
        } else {
            cJSON_Delete(data_json);
        }
    }

    return attributes;
}

/**
 * @brief Create a cJSON object holding the attributes associated with a fim_registry_key according to its
 * configuration.
 *
 * @param dbsync_event A cJSON object holding the dbsync event.
 * @param data A fim_registry_key object holding the key attributes to be tranlated.
 * @param configuration The configuration associated with the registry key.
 * @return A pointer to a cJSON object the translated key attributes.
 */
cJSON *fim_registry_key_attributes_json(const cJSON* dbsync_event, const fim_registry_key *data, const registry_t *configuration) {
    cJSON *attributes = cJSON_CreateObject();

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

    } else {
        cJSON *permissions, *uid, *owner, *gid, *group, *mtime;

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

            if (group = cJSON_GetObjectItem(dbsync_event, "group_"), group != NULL) {
                cJSON_AddStringToObject(attributes, "group", cJSON_GetStringValue(group));
            }
        }

        if (configuration->opts & CHECK_MTIME) {
            if (mtime = cJSON_GetObjectItem(dbsync_event, "mtime"), mtime != NULL) {
                cJSON_AddNumberToObject(attributes, "mtime", mtime->valueint);
            }
        }
    }

    return attributes;
}

#endif
