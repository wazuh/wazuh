/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../../include/syscheck.h"

void fim_calculate_dbsync_difference(const fim_file_data* data,
                                     const directory_t *configuration,
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
#ifndef WIN32
            cJSON_AddStringToObject(old_attributes, "permissions", cJSON_GetStringValue(aux));
#else
            cJSON_AddItemToObject(old_attributes, "permissions", cJSON_Parse(cJSON_GetStringValue(aux)));
#endif
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.permissions"));
        }
    }

    if (configuration->options & CHECK_OWNER) {
        if (aux = cJSON_GetObjectItem(old_data, "uid"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "uid", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.uid"));
        }
    }

    if (configuration->options & CHECK_GROUP) {
        if (aux = cJSON_GetObjectItem(old_data, "gid"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "gid", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.gid"));
        }
    }

    if (data->owner) {
        if (aux = cJSON_GetObjectItem(old_data, "owner"), aux != NULL) {
            cJSON_AddStringToObject(old_attributes, "owner", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.owner"));
        }
    }

    if (data->group) {
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
             } else {
                 mwarn(FIM_WARN_INODE_WRONG_TYPE);
             }
         }
     }

    if (configuration->options & CHECK_MTIME) {
        if (aux = cJSON_GetObjectItem(old_data, "mtime"), aux != NULL) {
            cJSON_AddNumberToObject(old_attributes, "mtime", aux->valueint);
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
            cJSON_AddStringToObject(old_attributes, "attributes", cJSON_GetStringValue(aux));
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.attributes"));
        }
    }
#endif

    if (data->device > 0) {
        if (aux = cJSON_GetObjectItem(old_data, "device"), aux != NULL) {
            cJSON_AddNumberToObject(old_attributes, "device", aux->valueint);
            cJSON_AddItemToArray(changed_attributes, cJSON_CreateString("file.device"));
        }
    }
}

cJSON * fim_attributes_json(const cJSON *dbsync_event, const fim_file_data *data, const directory_t *configuration) {
    cJSON * attributes = cJSON_CreateObject();
    cJSON *aux = NULL;

    if (data) {
        if (configuration->options & CHECK_SIZE) {
            cJSON_AddNumberToObject(attributes, "size", data->size);
        }

        if (configuration->options & CHECK_PERM) {
#ifndef WIN32
            cJSON_AddStringToObject(attributes, "permissions", data->permissions);
#else
            cJSON_AddItemToObject(attributes, "permissions", cJSON_Parse(data->permissions));
#endif
        }

        if (configuration->options & CHECK_OWNER && data->uid && *data->uid != '\0' ) {
            cJSON_AddStringToObject(attributes, "uid", data->uid);
        }

        if (configuration->options & CHECK_GROUP && data->gid && *data->gid != '\0' ) {
            cJSON_AddStringToObject(attributes, "gid", data->gid);
        }

        if (data->owner && *data->owner != '\0' ) {
            cJSON_AddStringToObject(attributes, "owner", data->owner);
        }

        if (data->group && *data->group != '\0') {
            cJSON_AddStringToObject(attributes, "group", data->group);
        }

        if (configuration->options & CHECK_INODE) {
            char inode_str[32];
            snprintf(inode_str, sizeof(inode_str), "%llu", data->inode);
            cJSON_AddStringToObject(attributes, "inode", inode_str);
        }

        if (configuration->options & CHECK_MTIME) {
            cJSON_AddNumberToObject(attributes, "mtime", data->mtime);
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
            cJSON_AddStringToObject(attributes, "attributes", data->attributes);
        }
#endif

        if (data->device > 0) {
            cJSON_AddNumberToObject(attributes, "device", data->device);
        }

    } else {
        if (configuration->options & CHECK_SIZE) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "size"), aux != NULL) {
                cJSON_AddNumberToObject(attributes, "size", aux->valueint);
            }
        }

        if (configuration->options & CHECK_PERM) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "permissions"), aux != NULL) {
#ifndef WIN32
                cJSON_AddStringToObject(attributes, "permissions", cJSON_GetStringValue(aux));
#else
                cJSON_AddItemToObject(attributes, "permissions", cJSON_Parse(cJSON_GetStringValue(aux)));
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
        }

        if (configuration->options & CHECK_GROUP) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "gid"), aux != NULL) {
                char *gid = cJSON_GetStringValue(aux);
                if (gid != NULL && *gid != '\0') {
                    cJSON_AddStringToObject(attributes, "gid", gid);
                }
            }
        }

        if (aux = cJSON_GetObjectItem(dbsync_event, "owner"), aux != NULL) {
            char *owner = cJSON_GetStringValue(aux);
            if (owner != NULL && *owner != '\0') {
                cJSON_AddStringToObject(attributes, "owner", cJSON_GetStringValue(aux));
            }
        }

        if (aux = cJSON_GetObjectItem(dbsync_event, "group_"), aux != NULL) {
            char *group = cJSON_GetStringValue(aux);
            if (group != NULL && *group != '\0') {
                cJSON_AddStringToObject(attributes, "group", cJSON_GetStringValue(aux));
            }
        }

        if (configuration->options & CHECK_INODE) {
            if ((aux = cJSON_GetObjectItem(dbsync_event, "inode")) != NULL) {
                if (cJSON_IsString(aux)) {
                    cJSON_AddStringToObject(attributes, "inode", cJSON_GetStringValue(aux));
                } else {
                    mwarn(FIM_WARN_INODE_WRONG_TYPE);
                }
            }
        }

        if (configuration->options & CHECK_MTIME) {
            if (aux = cJSON_GetObjectItem(dbsync_event, "mtime"), aux != NULL) {
                cJSON_AddNumberToObject(attributes, "mtime", aux->valueint);
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
                cJSON_AddStringToObject(attributes, "attributes", cJSON_GetStringValue(aux));
            }
        }
#endif

        if (aux = cJSON_GetObjectItem(dbsync_event, "device"), aux != NULL) {
            cJSON_AddNumberToObject(attributes, "device", aux->valueint);
        }
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
