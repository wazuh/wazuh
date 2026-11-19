/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscheck.h"
#include "file.h"

#ifdef WIN32
#define gmtime_r(x, y) (gmtime_s(y, x) == 0 ? (y) : NULL)
#endif

static void fim_add_permission_keyword(cJSON *array, const char *sid, const char *kind, const char *value) {
    size_t size = strlen(sid) + strlen(kind) + strlen(value) + 3;
    char *keyword = NULL;

    os_malloc(size, keyword);
    snprintf(keyword, size, "%s:%s:%s", sid, kind, value);
    cJSON_AddItemToArray(array, cJSON_CreateString(keyword));
    os_free(keyword);
}

cJSON *fim_win_permissions_json(const char *permissions) {
    cJSON *perm_array = cJSON_CreateArray();
    cJSON *parsed = permissions ? cJSON_Parse(permissions) : NULL;

    if (parsed == NULL || !cJSON_IsObject(parsed)) {
        // Not an ACL object: keep the stored value as it is
        if (permissions != NULL) {
            cJSON_AddItemToArray(perm_array, cJSON_CreateString(permissions));
        }
        cJSON_Delete(parsed);
        return perm_array;
    }

    static const char * const ace_types[] = { "allowed", "denied" };
    cJSON *ace = NULL;

    cJSON_ArrayForEach(ace, parsed) {
        const char *sid = ace->string;

        if (sid == NULL || !cJSON_IsObject(ace)) {
            continue;
        }

        const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(ace, "name"));
        if (name != NULL && *name != '\0') {
            fim_add_permission_keyword(perm_array, sid, "name", name);
        }

        for (size_t i = 0; i < sizeof(ace_types) / sizeof(ace_types[0]); i++) {
            cJSON *right = NULL;

            cJSON_ArrayForEach(right, cJSON_GetObjectItem(ace, ace_types[i])) {
                const char *right_str = cJSON_GetStringValue(right);

                if (right_str != NULL) {
                    fim_add_permission_keyword(perm_array, sid, ace_types[i], right_str);
                }
            }
        }
    }

    cJSON_Delete(parsed);
    return perm_array;
}

bool fim_epoch_to_iso8601(time_t timestamp, char *buffer, size_t buffer_size) {
    struct tm tm_info;
    if (gmtime_r(&timestamp, &tm_info) &&
        strftime(buffer, buffer_size, "%Y-%m-%dT%H:%M:%S.000Z", &tm_info) > 0) {
        return true;
    }
    return false;
}

void fim_calculate_dbsync_difference(const directory_t *configuration,
                                     const cJSON* old_data,
                                     cJSON* changed_attributes,
                                     cJSON* old_attributes) {

    if (old_attributes == NULL || changed_attributes == NULL || !cJSON_IsArray(changed_attributes)) {
        return;
    }

    cJSON *aux = NULL;

    if (configuration->options & CHECK_SIZE) {
        if (aux = cJSON_GetObjectItem(old_data, "size"), aux != NULL) {
            cJSON_AddNumberToObject(old_attributes, "size", aux->valueint);
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.size"));
        }
    }

    if (configuration->options & CHECK_PERM) {
        if (aux = cJSON_GetObjectItem(old_data, "permissions"), aux != NULL) {
#ifdef WIN32
            cJSON_AddItemToObject(old_attributes, "permissions", fim_win_permissions_json(cJSON_GetStringValue(aux)));
#else
            cJSON *perm_array = cJSON_CreateArray();
            cJSON_AddItemToArray(perm_array, cJSON_CreateString(cJSON_GetStringValue(aux)));
            cJSON_AddItemToObject(old_attributes, "permissions", perm_array);
#endif
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.permissions"));
        }
    }

    if (configuration->options & CHECK_OWNER) {
        if (aux = cJSON_GetObjectItem(old_data, "uid"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "uid", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.uid"));
        }

        if (aux = cJSON_GetObjectItem(old_data, "owner"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "owner", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.owner"));
        }
    }

    if (configuration->options & CHECK_GROUP) {
        if (aux = cJSON_GetObjectItem(old_data, "gid"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "gid", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.gid"));
        }

        if (aux = cJSON_GetObjectItem(old_data, "group_"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "group", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.group"));
        }
    }

    if (configuration->options & CHECK_INODE) {
         if ((aux = cJSON_GetObjectItem(old_data, "inode")) != NULL) {
             if (cJSON_IsString(aux)) {
                 cJSON_AddStringToObject(old_attributes, "inode", cJSON_GetStringValue(aux));
                 cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.inode"));
             } else if (cJSON_IsNumber(aux)) {
                 char inode_str[32];
                 snprintf(inode_str, sizeof(inode_str), "%llu", (unsigned long long)cJSON_GetNumberValue(aux));
                 cJSON_AddStringToObject(old_attributes, "inode", inode_str);
                 cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.inode"));
             } else {
                 minfo(FIM_WARN_INODE_WRONG_TYPE);
             }
         }
     }

    if (configuration->options & CHECK_DEVICE) {
        if (aux = cJSON_GetObjectItem(old_data, "device"), aux != NULL) {
            if (cJSON_IsString(aux)) {
                cJSON_AddStringToObject(old_attributes, "device", cJSON_GetStringValue(aux));
            } else if (cJSON_IsNumber(aux)) {
                char device_str[32];
                snprintf(device_str, sizeof(device_str), "%d", aux->valueint);
                cJSON_AddStringToObject(old_attributes, "device", device_str);
            }
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.device"));
        }
    }

    if (configuration->options & CHECK_MTIME) {
        if (aux = cJSON_GetObjectItem(old_data, "mtime"), aux != NULL) {
            if (cJSON_IsString(aux)) {
                cJSON_AddStringToObject(old_attributes, "mtime", cJSON_GetStringValue(aux));
            } else if (cJSON_IsNumber(aux)) {
                char mtime_str[25];
                time_t t = (time_t)cJSON_GetNumberValue(aux);
                if (fim_epoch_to_iso8601(t, mtime_str, sizeof(mtime_str))) {
                    cJSON_AddStringToObject(old_attributes, "mtime", mtime_str);
                } else {
                    cJSON_AddNumberToObject(old_attributes, "mtime", cJSON_GetNumberValue(aux));
                }
            }
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.mtime"));
        }
    }

    bool has_hash = false;
    cJSON* hash = cJSON_CreateObject();

    if (configuration->options & CHECK_MD5SUM) {
        if (aux = cJSON_GetObjectItem(old_data, "hash_md5"), aux != NULL) {
            cJSON_AddStringToObject(hash, "md5", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.hash.md5"));
            has_hash = true;
        }
    }

    if (configuration->options & CHECK_SHA1SUM) {
        if (aux = cJSON_GetObjectItem(old_data, "hash_sha1"), aux != NULL) {
            cJSON_AddStringToObject(hash, "sha1", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.hash.sha1"));
            has_hash = true;
        }
    }

    if (configuration->options & CHECK_SHA256SUM) {
        if (aux = cJSON_GetObjectItem(old_data, "hash_sha256"), aux != NULL) {
            cJSON_AddStringToObject(hash, "sha256", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.hash.sha256"));
            has_hash = true;
        }
    }

    if (has_hash) {
        cJSON_AddItemToObject(old_attributes, "hash", hash);
    } else {
        cJSON_Delete(hash);
    }

#ifdef WIN32
    if (configuration->options & CHECK_ATTRS) {
        if (aux = cJSON_GetObjectItem(old_data, "attributes"), aux != NULL) {
            cJSON *attr_array = cJSON_CreateArray();
            cJSON_AddItemToArray(attr_array, cJSON_CreateString(cJSON_GetStringValue(aux)));
            cJSON_AddItemToObject(old_attributes, "attributes", attr_array);
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.attributes"));
        }
    }
#endif
}

cJSON * fim_attributes_json(const cJSON *dbsync_event, const fim_file_data *data, const directory_t *configuration) {
    cJSON * attributes = cJSON_CreateObject();
    cJSON *aux = NULL;

    if (data) {
        if (configuration->options & CHECK_SIZE) {
            cJSON_AddNumberToObject(attributes, "size", data->size);
        }

        if (configuration->options & CHECK_PERM) {
#ifdef WIN32
            cJSON_AddItemToObject(attributes, "permissions", fim_win_permissions_json(data->permissions));
#else
            cJSON *perm_array = cJSON_CreateArray();
            cJSON_AddItemToArray(perm_array, cJSON_CreateString(data->permissions));
            cJSON_AddItemToObject(attributes, "permissions", perm_array);
#endif
        }

        if (configuration->options & CHECK_OWNER && data->uid && *data->uid != '\0' ) {
            cJSON_AddStringToObject(attributes, "uid", data->uid);
        }

        if (configuration->options & CHECK_OWNER && data->owner && *data->owner != '\0' ) {
            cJSON_AddStringToObject(attributes, "owner", data->owner);
        }

        if (configuration->options & CHECK_GROUP && data->gid && *data->gid != '\0' ) {
            cJSON_AddStringToObject(attributes, "gid", data->gid);
        }

        if (configuration->options & CHECK_GROUP && data->group && *data->group != '\0') {
            cJSON_AddStringToObject(attributes, "group", data->group);
        }

        if (configuration->options & CHECK_INODE) {
            char inode_str[32];
            snprintf(inode_str, sizeof(inode_str), "%llu", data->inode);
            cJSON_AddStringToObject(attributes, "inode", inode_str);
        }

        if (configuration->options & CHECK_DEVICE) {
            char device_str[32];
            snprintf(device_str, sizeof(device_str), "%lu", data->device);
            cJSON_AddStringToObject(attributes, "device", device_str);
        }

        if (configuration->options & CHECK_MTIME) {
            char mtime_str[25];
            if (fim_epoch_to_iso8601((time_t)data->mtime, mtime_str, sizeof(mtime_str))) {
                cJSON_AddStringToObject(attributes, "mtime", mtime_str);
            } else {
                cJSON_AddNumberToObject(attributes, "mtime", data->mtime);
            }
        }

        bool has_hash = false;
        cJSON* hash = cJSON_CreateObject();

        if (configuration->options & CHECK_MD5SUM) {
            cJSON_AddStringToObject(hash, "md5", data->hash_md5);
            has_hash = true;
        }

        if (configuration->options & CHECK_SHA1SUM) {
            cJSON_AddStringToObject(hash, "sha1", data->hash_sha1);
            has_hash = true;
        }

        if (configuration->options & CHECK_SHA256SUM) {
            cJSON_AddStringToObject(hash, "sha256", data->hash_sha256);
            has_hash = true;
        }

        if (has_hash) {
            cJSON_AddItemToObject(attributes, "hash", hash);
        } else {
            cJSON_Delete(hash);
        }

#ifdef WIN32
        if (configuration->options & CHECK_ATTRS) {
            cJSON *attr_array = cJSON_CreateArray();
            cJSON_AddItemToArray(attr_array, cJSON_CreateString(data->attributes));
            cJSON_AddItemToObject(attributes, "attributes", attr_array);
        }
#endif

    } else {
        if (configuration->options & CHECK_SIZE) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "size"), aux != NULL) {
                cJSON_AddNumberToObject(attributes, "size", aux->valueint);
            }
        }

        if (configuration->options & CHECK_PERM) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "permissions"), aux != NULL) {
#ifdef WIN32
                cJSON_AddItemToObject(attributes, "permissions", fim_win_permissions_json(cJSON_GetStringValue(aux)));
#else
                cJSON *perm_array = cJSON_CreateArray();
                cJSON_AddItemToArray(perm_array, cJSON_CreateString(cJSON_GetStringValue(aux)));
                cJSON_AddItemToObject(attributes, "permissions", perm_array);
#endif
            }
        }

        if (configuration->options & CHECK_OWNER) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "uid"), aux != NULL) {
                char *uid = cJSON_GetStringValue(aux);
                if (uid != NULL && *uid != '\0') {
                    cJSON_AddStringToObject(attributes, "uid", uid);
                }
            }

            if (aux = cJSON_GetObjectItem(dbsync_event, "owner"), aux != NULL) {
                char *owner = cJSON_GetStringValue(aux);
                if (owner != NULL && *owner != '\0') {
                    cJSON_AddStringToObject(attributes, "owner", cJSON_GetStringValue(aux));
                }
            }
        }

        if (configuration->options & CHECK_GROUP) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "gid"), aux != NULL) {
                char *gid = cJSON_GetStringValue(aux);
                if (gid != NULL && *gid != '\0') {
                    cJSON_AddStringToObject(attributes, "gid", gid);
                }
            }

            if (aux = cJSON_GetObjectItem(dbsync_event, "group_"), aux != NULL) {
                char *group = cJSON_GetStringValue(aux);
                if (group != NULL && *group != '\0') {
                    cJSON_AddStringToObject(attributes, "group", cJSON_GetStringValue(aux));
                }
            }
        }

        if (configuration->options & CHECK_INODE) {
            if ((aux = cJSON_GetObjectItem(dbsync_event, "inode")) != NULL) {
                if (cJSON_IsString(aux)) {
                    cJSON_AddStringToObject(attributes, "inode", cJSON_GetStringValue(aux));
                } else if (cJSON_IsNumber(aux)) {
                    char inode_str[32];
                    snprintf(inode_str, sizeof(inode_str), "%llu", (unsigned long long)cJSON_GetNumberValue(aux));
                    cJSON_AddStringToObject(attributes, "inode", inode_str);
                } else {
                    minfo(FIM_WARN_INODE_WRONG_TYPE);
                }
            }
        }

        if (configuration->options & CHECK_DEVICE) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "device"), aux != NULL) {
                if (cJSON_IsString(aux)) {
                    cJSON_AddStringToObject(attributes, "device", cJSON_GetStringValue(aux));
                } else if (cJSON_IsNumber(aux)) {
                    char device_str[32];
                    snprintf(device_str, sizeof(device_str), "%d", aux->valueint);
                    cJSON_AddStringToObject(attributes, "device", device_str);
                }
            }
        }

        if (configuration->options & CHECK_MTIME) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "mtime"), aux != NULL) {
                if (cJSON_IsString(aux)) {
                    cJSON_AddStringToObject(attributes, "mtime", cJSON_GetStringValue(aux));
                } else if (cJSON_IsNumber(aux)) {
                    char mtime_str[25];
                    time_t t = (time_t)cJSON_GetNumberValue(aux);
                    if (fim_epoch_to_iso8601(t, mtime_str, sizeof(mtime_str))) {
                        cJSON_AddStringToObject(attributes, "mtime", mtime_str);
                    } else {
                        cJSON_AddNumberToObject(attributes, "mtime", cJSON_GetNumberValue(aux));
                    }
                }
            }
        }

        bool has_hash = false;
        cJSON* hash = cJSON_CreateObject();

        if (configuration->options & CHECK_MD5SUM) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "hash_md5"), aux != NULL) {
                cJSON_AddStringToObject(hash, "md5", cJSON_GetStringValue(aux));
                has_hash = true;
            }
        }

        if (configuration->options & CHECK_SHA1SUM) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "hash_sha1"), aux != NULL) {
                cJSON_AddStringToObject(hash, "sha1", cJSON_GetStringValue(aux));
                has_hash = true;
            }
        }

        if (configuration->options & CHECK_SHA256SUM) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "hash_sha256"), aux != NULL) {
                cJSON_AddStringToObject(hash, "sha256", cJSON_GetStringValue(aux));
                has_hash = true;
            }
        }

        if (has_hash) {
            cJSON_AddItemToObject(attributes, "hash", hash);
        } else {
            cJSON_Delete(hash);
        }

#ifdef WIN32
        if (configuration->options & CHECK_ATTRS) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "attributes"), aux != NULL) {
                cJSON *attr_array = cJSON_CreateArray();
                cJSON_AddItemToArray(attr_array, cJSON_CreateString(cJSON_GetStringValue(aux)));
                cJSON_AddItemToObject(attributes, "attributes", attr_array);
            }
        }
#endif
    }

    return attributes;
}

cJSON * fim_audit_json(const whodata_evt * w_evt) {
    cJSON * fim_audit = cJSON_CreateObject();

    if (w_evt->user_id) cJSON_AddStringToObject(fim_audit, "user_id", w_evt->user_id);
    if (w_evt->user_name) cJSON_AddStringToObject(fim_audit, "user_name", w_evt->user_name);
    if (w_evt->process_name) cJSON_AddStringToObject(fim_audit, "process_name", w_evt->process_name);
    cJSON_AddNumberToObject(fim_audit, "process_id", w_evt->process_id);
#ifndef WIN32
    if (w_evt->cwd) cJSON_AddStringToObject(fim_audit, "cwd", w_evt->cwd);
    if (w_evt->group_id) cJSON_AddStringToObject(fim_audit, "group_id", w_evt->group_id);
    if (w_evt->group_name) cJSON_AddStringToObject(fim_audit, "group_name", w_evt->group_name);
    if (w_evt->audit_uid) cJSON_AddStringToObject(fim_audit, "audit_uid", w_evt->audit_uid);
    if (w_evt->audit_name) cJSON_AddStringToObject(fim_audit, "audit_name", w_evt->audit_name);
    if (w_evt->effective_uid) cJSON_AddStringToObject(fim_audit, "effective_uid", w_evt->effective_uid);
    if (w_evt->effective_name) cJSON_AddStringToObject(fim_audit, "effective_name", w_evt->effective_name);
    if (w_evt->parent_name) cJSON_AddStringToObject(fim_audit, "parent_name", w_evt->parent_name);
    if (w_evt->parent_cwd) cJSON_AddStringToObject(fim_audit, "parent_cwd", w_evt->parent_cwd);
    cJSON_AddNumberToObject(fim_audit, "ppid", w_evt->ppid);
#endif

    return fim_audit;
}
