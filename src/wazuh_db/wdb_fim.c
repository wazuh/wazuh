/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"
#include "helpers/wdb_global_helpers.h"

int wdb_syscheck_load(wdb_t * wdb, const char * file, char * output, size_t size) {
    sqlite3_stmt * stmt;
    sk_sum_t sum;
    char *str_perm;

    memset(&sum, 0, sizeof(sk_sum_t));

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_LOAD) < 0) {
        merror("DB(%s) Can't cache statement", wdb->id);
        return -1;
    }

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        merror("DB(%s) Can't begin transaction", wdb->id);
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_FIM_LOAD];

    if (sqlite3_bind_text(stmt, 1, file, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:

        sum.changes = (long)sqlite3_column_int64(stmt, 0);
        sum.size = (char *)sqlite3_column_text(stmt, 1);
        str_perm = (char *)sqlite3_column_text(stmt, 2);
        sum.uid = (char *)sqlite3_column_text(stmt, 3);
        sum.gid = (char *)sqlite3_column_text(stmt, 4);
        sum.md5 = (char *)sqlite3_column_text(stmt, 5);
        sum.sha1 = (char *)sqlite3_column_text(stmt, 6);
        sum.uname = (char *)sqlite3_column_text(stmt, 7);
        sum.gname = (char *)sqlite3_column_text(stmt, 8);
        sum.mtime = (long)sqlite3_column_int64(stmt, 9);
        sum.inode = (long)sqlite3_column_int64(stmt, 10);
        sum.sha256 = (char *)sqlite3_column_text(stmt, 11);
        sum.date_alert = (long)sqlite3_column_int64(stmt, 12);
        sum.attributes = (char *)sqlite3_column_text(stmt, 13);
        sum.symbolic_path = (char *)sqlite3_column_text(stmt, 14);

        if (str_perm && isdigit(*str_perm)) {
            sum.perm = strtol(str_perm, NULL, 8);
        } else {
            sum.win_perm = str_perm;
        }

        output[size - 1] = '\0';

    case SQLITE_DONE:
        *output = 0;
        return 0;

    default:
        merror("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}
/*****************************************************************************************
 TODO-LEGACY-ANALYSISD-FIM: Delete this function when the new system is ready
 Should not depend on analsysid code
int wdb_syscheck_save(wdb_t * wdb, int ftype, char * checksum, const char * file) {
    sk_sum_t sum;
    int retval = -1;

    memset(&sum, 0, sizeof(sk_sum_t));

    if (sk_decode_extradata(&sum, checksum) < 0) {
        mdebug1("Checksum: %s", checksum);
        goto end;
    }

    if (sk_decode_sum(&sum, checksum, NULL) < 0) {
        mdebug1("Checksum: %s", checksum);
        goto end;
    }

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        merror("DB(%s) Can't begin transaction", wdb->id);
        goto end;
    }

    switch (wdb_fim_find_entry(wdb, file)) {
    case -1:
        mdebug1("DB(%s) Can't find file by name", wdb->id);
        goto end;

    case 0:
        // File not found, add

        if (wdb_fim_insert_entry(wdb, file, ftype, &sum) < 0) {
            mdebug1("DB(%s) Can't insert file entry", wdb->id);
            goto end;
        }

        break;

    default:
        // Update entry

        if (wdb_fim_update_entry(wdb, file, &sum) < 1) {
            mdebug1("DB(%s) Can't update file entry", wdb->id);
            goto end;
        }
    }

    retval = 0;

end:
    sk_sum_clean(&sum);
    return retval;
}
*****************************************************************************************/

// LCOV_EXCL_STOP
int wdb_syscheck_save2(wdb_t * wdb, const char * payload) {
    int retval = -1;
    cJSON * data = cJSON_Parse(payload);

    if (!wdb) {
        merror("WDB object cannot be null.");
        goto end;
    }

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse FIM payload: '%s'", wdb->id, payload == NULL ? "" : payload);
        goto end;
    }

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        merror("DB(%s) Can't begin transaction.", wdb->id);
        goto end;
    }

    if (wdb_fim_insert_entry2(wdb, data) == -1) {
        mdebug1("DB(%s) Can't insert file entry.", wdb->id);
        goto end;
    }

    retval = 0;

end:
    cJSON_Delete(data);
    return retval;
}

// Find file entry: returns 1 if found, 0 if not, or -1 on error.
// LCOV_EXCL_START
int wdb_fim_find_entry(wdb_t * wdb, const char * path) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_FIND_ENTRY) < 0) {
        merror("DB(%s) Can't cache statement", wdb->id);
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_FIM_FIND_ENTRY];

    sqlite3_bind_text(stmt, 1, path, -1, NULL);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        return 1;
        break;
    case SQLITE_DONE:
        return 0;
        break;
    default:
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_fim_insert_entry(wdb_t * wdb, const char * file, int ftype, const sk_sum_t * sum) {
    sqlite3_stmt *stmt = NULL;
    char s_perm[16];
    const char * s_ftype;

    switch (ftype) {
    case WDB_FILE_TYPE_FILE:
        s_ftype = "file";
        break;
    case WDB_FILE_TYPE_REGISTRY:
        s_ftype = "registry_key";
        break;
    default:
        merror("DB(%s) Invalid file type '%d'", wdb->id, ftype);
        return -1;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_INSERT_ENTRY) < 0) {
        merror("DB(%s) Can't cache statement", wdb->id);
        return -1;
    }

    snprintf(s_perm, sizeof(s_perm), "%06o", sum->perm);
    stmt = wdb->stmt[WDB_STMT_FIM_INSERT_ENTRY];

    // If we have Windows permissions, they will be escaped. We
    // need to save them unescaped
    char *unescaped_perms = NULL;
    if (sum->win_perm) {
        unescaped_perms = wstr_replace(sum->win_perm, "\\:", ":");
    }

    sqlite3_bind_text(stmt, 1, file, -1, NULL);
    sqlite3_bind_text(stmt, 2, s_ftype, -1, NULL);
    sqlite3_bind_text(stmt, 3, sum->size, -1, NULL);
    sqlite3_bind_text(stmt, 4, (!unescaped_perms) ? s_perm : unescaped_perms, -1, NULL);
    sqlite3_bind_text(stmt, 5, sum->uid, -1, NULL);
    sqlite3_bind_text(stmt, 6, sum->gid, -1, NULL);
    sqlite3_bind_text(stmt, 7, sum->md5, -1, NULL);
    sqlite3_bind_text(stmt, 8, sum->sha1, -1, NULL);
    sqlite3_bind_text(stmt, 9, sum->uname, -1, NULL);
    sqlite3_bind_text(stmt, 10, sum->gname, -1, NULL);
    sqlite3_bind_int64(stmt, 11, sum->mtime);
    sqlite3_bind_int64(stmt, 12, sum->inode);
    sqlite3_bind_text(stmt, 13, sum->sha256, -1, NULL);
    sqlite3_bind_text(stmt, 14, sum->attributes, -1, NULL);
    sqlite3_bind_text(stmt, 15, sum->symbolic_path, -1, NULL);
    sqlite3_bind_text(stmt, 16, file, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE) {
        free(unescaped_perms);
        return 0;
    } else {
        free(unescaped_perms);
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}
// LCOV_EXCL_STOP

int wdb_fim_insert_entry2(wdb_t * wdb, const cJSON * data) {
    cJSON *json_path;
    char *path, *arch, *value_name, *item_type;
    char *full_path = NULL;

    if (!wdb) {
        merror("WDB object cannot be null.");
        return -1;
    }

    json_path = cJSON_GetObjectItem(data, "path");

    // Fallback for RSync format. Windows registries comes with both path and index fields,
    // path corresponds to the key_path, and index is the hash used as full_path,
    // It is included in the 3.0 version code
    if (!json_path) {
        json_path = cJSON_GetObjectItem(data, "index");
    }

    if (!json_path) {
        merror("DB(%s) fim/save request with no file path argument.", wdb->id);
        return -1;
    }

    path = cJSON_GetStringValue(json_path);
    cJSON * timestamp = cJSON_GetObjectItem(data, "timestamp");

    if (!cJSON_IsNumber(timestamp)) {
        merror("DB(%s) fim/save request with no timestamp path argument.", wdb->id);
        return -1;
    }

    cJSON * version = cJSON_GetObjectItem(data, "version");

    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");

    if (!cJSON_IsObject(attributes)) {
        merror("DB(%s) fim/save request with no valid attributes.", wdb->id);
        return -1;
    }

    item_type = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type"));

    if (item_type == NULL) {
        merror("DB(%s) fim/save request with no type attribute.", wdb->id);
        return -1;
    } else if (strcmp(item_type, "file") == 0) {
        arch = NULL;
        value_name = NULL;
        os_strdup(path, full_path);
    } else if(strcmp(item_type, "registry") == 0) {
        arch = NULL;
        value_name = NULL;
        os_strdup(path, full_path);
        item_type = "registry_key";
    } else if (strncmp(item_type, "registry_", 9) == 0) {

        if (!cJSON_IsNumber(version)) {
            // Synchronization messages without the "version" attribute are ignored, but won't trigger any error
            // message.
            return 0;
        }

        arch = cJSON_GetStringValue(cJSON_GetObjectItem(data, "arch"));
        value_name = cJSON_GetStringValue(cJSON_GetObjectItem(data, "value_name"));

        // Second version of the message, both registry keys and registry values
        // work with the same component "fim_registry".
        // full_path example: "[x32] HKEY_LOCAL_MACHINE\\\\software\\:value_name"
        if (version->valuedouble == 2.0) {
            int full_path_length;
            char *path_escaped_slahes;
            char *path_escaped;

            path_escaped_slahes = wstr_replace(path, "\\", "\\\\");
            path_escaped = wstr_replace(path_escaped_slahes, ":", "\\:");
            os_free(path_escaped_slahes);

            if (arch == NULL) {
                merror("DB(%s) fim/save registry request with no arch argument.", wdb->id);
                os_free(path_escaped);
                return -1;
            }

            if (strcmp(item_type + 9, "key") == 0) {
                value_name = NULL;
                full_path_length = snprintf(NULL, 0, "%s %s", arch, path_escaped);

                os_calloc(full_path_length + 1, sizeof(char), full_path);

                snprintf(full_path, full_path_length + 1, "%s %s", arch, path_escaped);
            } else if (strcmp(item_type + 9, "value") == 0) {
                char *value_name_escaped_slashes;
                char *value_name_escaped;

                if (value_name == NULL) {
                    merror("DB(%s) fim/save registry value request with no value name argument.", wdb->id);
                    os_free(path_escaped);
                    return -1;
                }

                value_name_escaped_slashes = wstr_replace(value_name, "\\", "\\\\");
                value_name_escaped = wstr_replace(value_name_escaped_slashes, ":", "\\:");
                os_free(value_name_escaped_slashes);

                full_path_length = snprintf(NULL, 0, "%s %s:%s", arch, path_escaped, value_name_escaped);

                os_calloc(full_path_length + 1, sizeof(char), full_path);

                snprintf(full_path, full_path_length + 1, "%s %s:%s", arch, path_escaped, value_name_escaped);

                os_free(value_name_escaped);
            } else {
                merror("DB(%s) fim/save request with invalid '%s' type argument.", wdb->id, item_type);
                os_free(path_escaped);
                return -1;
            }

            os_free(path_escaped);
        } else if (version->valuedouble == 3.0) {
            // Third version of the messages, field index its a hash formed with arch,
            // path and value_name (if it is a value). It is used for full_path db field.
            // Differents components for keys and values.
            cJSON *json_index = cJSON_GetObjectItem(data, "index");

            if (!json_index) {
                merror("DB(%s) version 3.0 fim/save request with no index argument.", wdb->id);
                return -1;
            }

            char* index = cJSON_GetStringValue(json_index);

            os_strdup(index, full_path);
        }
    } else {
        merror("DB(%s) fim/save request with invalid '%s' type argument.", wdb->id, item_type);
        return -1;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_INSERT_ENTRY2) < 0) {
        merror("DB(%s) Can't cache statement", wdb->id);
        os_free(full_path);
        return -1;
    }

    sqlite3_stmt * stmt = wdb->stmt[WDB_STMT_FIM_INSERT_ENTRY2];
    sqlite3_bind_text(stmt, 1, path, -1, NULL);
    sqlite3_bind_text(stmt, 2, item_type, -1, NULL);
    sqlite3_bind_int64(stmt, 3, (long)timestamp->valuedouble);
    sqlite3_bind_text(stmt, 18, arch, -1, NULL);
    sqlite3_bind_text(stmt, 19, value_name, -1, NULL);
    sqlite3_bind_text(stmt, 21, full_path, -1, NULL);

    cJSON * element;
    char *perm = NULL;

    cJSON_ArrayForEach(element, attributes) {
        if (element->string == NULL) {
            os_free(perm);
            os_free(full_path);
            return -1;
        }

        switch (element->type) {
        case cJSON_Number:
            if (strcmp(element->string, "size") == 0) {
                sqlite3_bind_int64(stmt, 4, element->valuedouble);
            } else if (strcmp(element->string, "mtime") == 0) {
                sqlite3_bind_int(stmt, 12, element->valueint);
            } else if (strcmp(element->string, "inode") == 0) {
                sqlite3_bind_int64(stmt, 13, element->valuedouble);
            } else {
                merror("DB(%s) Invalid attribute name: %s", wdb->id, element->string);
                os_free(perm);
                os_free(full_path);
                return -1;
            }

            break;

        case cJSON_String:
            if (strcmp(element->string, "type") == 0) {
                // Already bound before.
            } else if (strcmp(element->string, "perm") == 0) {
                sqlite3_bind_text(stmt, 5, element->valuestring, -1, NULL);
            } else if (strcmp(element->string, "uid") == 0) {
                sqlite3_bind_text(stmt, 6, element->valuestring, -1, NULL);
            } else if (strcmp(element->string, "gid") == 0) {
                sqlite3_bind_text(stmt, 7, element->valuestring, -1, NULL);
            } else if (strcmp(element->string, "hash_md5") == 0) {
                sqlite3_bind_text(stmt, 8, element->valuestring, -1, NULL);
            } else if (strcmp(element->string, "hash_sha1") == 0) {
                sqlite3_bind_text(stmt, 9, element->valuestring, -1, NULL);
            } else if (strcmp(element->string, "user_name") == 0) {
                sqlite3_bind_text(stmt, 10, element->valuestring, -1, NULL);
            } else if (strcmp(element->string, "group_name") == 0) {
                sqlite3_bind_text(stmt, 11, element->valuestring, -1, NULL);
            } else if (strcmp(element->string, "hash_sha256") == 0) {
                sqlite3_bind_text(stmt, 14, element->valuestring, -1, NULL);
            } else if (strcmp(element->string, "symbolic_path") == 0) {
                sqlite3_bind_text(stmt, 16, element->valuestring, -1, NULL);
            } else if (strcmp(element->string, "checksum") == 0) {
                sqlite3_bind_text(stmt, 17, element->valuestring, -1, NULL);
            } else if (strcmp(element->string, "attributes") == 0) {
                sqlite3_bind_text(stmt, 15, element->valuestring, -1, NULL);
            } else if (strcmp(element->string, "value_type") == 0) {
                sqlite3_bind_text(stmt, 20, element->valuestring, -1, NULL);
            } else {
                merror("DB(%s) Invalid attribute name: %s", wdb->id, element->string);
                os_free(perm);
                os_free(full_path);
                return -1;
            }

            break;

        case cJSON_Object:
            if (strcmp(element->string, "perm") == 0) {
                perm = cJSON_PrintUnformatted(element);

                if (perm == NULL) {
                    mwarn("DB(%s) Failed formatting permissions", wdb->id); // LCOV_EXCL_LINE
                    continue;                                               // LCOV_EXCL_LINE
                }

                sqlite3_bind_text(stmt, 5, perm, -1, NULL);
            } else {
                merror("DB(%s) Invalid attribute name: %s", wdb->id, element->string);
                os_free(perm);
                os_free(full_path);
                return -1;
            }
        }
    }

    if (wdb_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
        os_free(perm);
        os_free(full_path);
        return -1;
    }
    os_free(full_path);
    os_free(perm);
    return 0;
}

// LCOV_EXCL_START
int wdb_fim_update_entry(wdb_t * wdb, const char * file, const sk_sum_t * sum) {
    sqlite3_stmt *stmt = NULL;
    char s_perm[16];

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_UPDATE_ENTRY) < 0) {
        merror("DB(%s) Can't cache statement", wdb->id);
        return -1;
    }

    snprintf(s_perm, sizeof(s_perm), "%06o", sum->perm);
    stmt = wdb->stmt[WDB_STMT_FIM_UPDATE_ENTRY];

    // If we have Windows permissions, they will be escaped. We
    // need to save them unescaped
    char *unescaped_perms = NULL;
    if (sum->win_perm) {
        unescaped_perms = wstr_replace(sum->win_perm, "\\:", ":");
    }

    sqlite3_bind_int64(stmt, 1, sum->changes);
    sqlite3_bind_text(stmt, 2, sum->size, -1, NULL);
    sqlite3_bind_text(stmt, 3, (!unescaped_perms) ? s_perm : unescaped_perms, -1, NULL);
    sqlite3_bind_text(stmt, 4, sum->uid, -1, NULL);
    sqlite3_bind_text(stmt, 5, sum->gid, -1, NULL);
    sqlite3_bind_text(stmt, 6, sum->md5, -1, NULL);
    sqlite3_bind_text(stmt, 7, sum->sha1, -1, NULL);
    sqlite3_bind_text(stmt, 8, sum->uname, -1, NULL);
    sqlite3_bind_text(stmt, 9, sum->gname, -1, NULL);
    sqlite3_bind_int64(stmt, 10, sum->mtime);
    sqlite3_bind_int64(stmt, 11, sum->inode);
    sqlite3_bind_text(stmt, 12, sum->sha256, -1, NULL);
    sqlite3_bind_text(stmt, 13, sum->attributes, -1, NULL);
    sqlite3_bind_text(stmt, 14, sum->symbolic_path, -1, NULL);
    sqlite3_bind_text(stmt, 15, file, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE) {
        free(unescaped_perms);
        return sqlite3_changes(wdb->db);
    } else {
        free(unescaped_perms);
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

// Delete file entry: returns 1 if found, 0 if not, or -1 on error.
int wdb_fim_delete(wdb_t * wdb, const char * path) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_DELETE) < 0) {
        merror("DB(%s) Can't cache statement", wdb->id);
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_FIM_DELETE];

    sqlite3_bind_text(stmt, 1, path, -1, NULL);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        return 0;
        break;
    case SQLITE_DONE:
        return 0;
        break;
    default:
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_fim_update_date_entry(wdb_t * wdb, const char *path) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_UPDATE_DATE) < 0) {
        merror("DB(%s) Can't cache statement", wdb->id);
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_FIM_UPDATE_DATE];

    sqlite3_bind_text(stmt, 1, path, -1, NULL);

    switch (wdb_step(stmt)) {
    case SQLITE_DONE:
        mdebug2("DB(%s) Updated date field for file '%s' to '%ld'", wdb->id, path, (long)time(NULL));
        return 0;
    default:
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_fim_clean_old_entries(wdb_t * wdb) {
    sqlite3_stmt *stmt = NULL;
    char *file;
    int result, del_result;
    long tscheck3 = 0;
    long date;

    if(result = wdb_scan_info_get (wdb, "fim", "fim_third_check", &tscheck3), result < 0) {
        mdebug1("DB(%s) Can't get scan_info entry", wdb->id);
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_FIND_DATE_ENTRIES) < 0) {
        merror("DB(%s) Can't cache statement", wdb->id);
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_FIM_FIND_DATE_ENTRIES];
    sqlite3_bind_int64(stmt, 1, tscheck3);

    while(result = wdb_step(stmt), result != SQLITE_DONE) {
        switch (result) {
            case SQLITE_ROW:
                //call to delete
                file = (char *)sqlite3_column_text(stmt, 0);
                date = sqlite3_column_int64(stmt, 13);
                mdebug2("DB(%s) Cleaning FIM DDBB. Deleting entry '%s' date<tscheck3 '%ld'<'%ld'.", wdb->id, file, date, tscheck3);
                if(strcmp(file, "internal_options.conf") != 0 && strcmp(file, "ossec.conf") != 0) {
                    if (del_result = wdb_fim_delete(wdb, file), del_result < 0) {
                        mdebug1("DB(%s) Can't delete FIM entry '%s'.", wdb->id, file);
                    }
                }
                break;
            default:
                mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
                return -1;
        }
    }

    return 0;
}
// LCOV_EXCL_STOP
