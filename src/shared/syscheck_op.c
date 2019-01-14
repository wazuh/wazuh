/*
 * Shared functions for Syscheck events decoding
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscheck_op.h"

#ifdef WIN32
#include <sddl.h>
int copy_ace_info(void *ace, char *perm, int perm_size);
int w_get_account_info(SID *sid, char **account_name, char **account_domain);
#elif !CLIENT
static char *unescape_whodata_sum(char *sum);
static char *unescape_perm_sum(char *sum);
#endif
int delete_target_file(const char *path) {
    char full_path[PATH_MAX] = "\0";
    snprintf(full_path, PATH_MAX, "%s%clocal", DIFF_DIR_PATH, PATH_SEP);

#ifdef WIN32
    char *windows_path = strchr(path, ':');
    strncat(full_path, (windows_path + 1), PATH_MAX - strlen(full_path) - 1);
#else
    strncat(full_path, path, PATH_MAX - strlen(full_path) - 1);
#endif
    if(rmdir_ex(full_path) == 0){
        mdebug1("Deleting last-entry of file '%s'", full_path);
        return(remove_empty_folders(full_path));
    }
    return 1;
}

int fim_find_child_depth(const char *parent, const char *child) {

    int length_A = strlen(parent);
    int length_B = strlen(child);

    char* p_first = strdup(parent);
    char *p_second = strdup(child);

    char *diff_str;

    if(parent[length_A - 1] == PATH_SEP){
        p_first[length_A - 1] = '\0';
    }

    if(child[length_B - 1] == PATH_SEP){
        p_second[length_B - 1] = '\0';
    }


#ifndef WIN32
    if(strncmp(parent, child, length_A) == 0) {
#else
    if(strncasecmp(parent, child, length_A) == 0) {
#endif
        diff_str = p_second;
        diff_str += length_A;
    }
#ifndef WIN32
    else if(strncmp(child, parent, length_B) == 0) {
#else
    else if(strncasecmp(child, parent, length_B) == 0) {
#endif
        diff_str = p_first;
        diff_str += length_B;
    }
    else{
        os_free(p_first);
        os_free(p_second);
        return INT_MAX;
    }

    char *c;
    int child_depth = 0;
    c = strchr(diff_str, PATH_SEP);
    while (c != NULL) {
        child_depth++;
        c = strchr(c + 1, PATH_SEP);
    }

    os_free(p_first);
    os_free(p_second);
    return child_depth;
}

void normalize_path(char * path) {
    char *ptname = path;

    if(ptname[1] == ':' && ((ptname[0] >= 'A' && ptname[0] <= 'Z') || (ptname[0] >= 'a' && ptname[0] <= 'z'))) {
        /* Change forward slashes to backslashes on entry */
        ptname = strchr(ptname, '/');
        while (ptname) {
            *ptname = '\\';
            ptname++;

            ptname = strchr(ptname, '/');
        }
    }
}

int remove_empty_folders(const char *path) {
    const char LOCALDIR[] = { PATH_SEP, 'l', 'o', 'c', 'a', 'l', '\0' };
    char DIFF_PATH[MAXPATHLEN] = DIFF_DIR_PATH;
    strcat(DIFF_PATH, LOCALDIR);
    const char *c;
    char parent[PATH_MAX] = "\0";
    char ** subdir;
    int retval = 0;

    // Get parent
    c = strrchr(path, PATH_SEP);
    if (c) {
        memcpy(parent, path, c - path);
        parent[c - path] = '\0';
        // Don't delete above /local
        if (strcmp(DIFF_PATH, parent) != 0) {
            subdir = wreaddir(parent);
            if (!(subdir && *subdir)) {
                // Remove empty folder
                mdebug1("Removing empty directory '%s'.", parent);
                if (rmdir_ex(parent) != 0) {
                    mwarn("Empty directory '%s' couldn't be deleted. ('%s')",
                        parent, strerror(errno));
                    retval = 1;
                } else {
                    // Get parent and remove it if it's empty
                    retval = remove_empty_folders(parent);
                }
            }

            free_strarray(subdir);
        }
    }

    return retval;
}

#ifndef WIN32
#ifndef CLIENT
/* Parse c_sum string. Returns 0 if success, 1 when c_sum denotes a deleted file
   or -1 on failure. */
int sk_decode_sum(sk_sum_t *sum, char *c_sum, char *w_sum) {
    char *c_perm;
    char *c_mtime;
    char *c_inode;
    char *attrs;
    int retval = 0;
    char * uname;

    if (c_sum[0] == '-' && c_sum[1] == '1') {
        retval = 1;
    } else {
        sum->size = c_sum;

        if (!(c_perm = strchr(c_sum, ':')))
            return -1;

        *(c_perm++) = '\0';

        if (!(sum->uid = strchr(c_perm, ':')))
            return -1;

        *(sum->uid++) = '\0';

        if (*c_perm == '|') {
            // Windows permissions
            sum->win_perm = unescape_perm_sum(c_perm);
        } else {
            sum->perm = atoi(c_perm);
        }

        if (!(sum->gid = strchr(sum->uid, ':')))
            return -1;

        *(sum->gid++) = '\0';

        if (!(sum->md5 = strchr(sum->gid, ':')))
            return -1;

        *(sum->md5++) = '\0';

        if (!(sum->sha1 = strchr(sum->md5, ':')))
            return -1;

        *(sum->sha1++) = '\0';

        // New fields: user name, group name, modification time and inode

        if ((uname = strchr(sum->sha1, ':'))) {
            *(uname++) = '\0';

            if (!(sum->gname = strchr(uname, ':')))
                return -1;

            *(sum->gname++) = '\0';

            sum->uname = os_strip_char(uname, '\\');

            if (!(c_mtime = strchr(sum->gname, ':')))
                return -1;

            *(c_mtime++) = '\0';

            if (!(c_inode = strchr(c_mtime, ':')))
                return -1;

            *(c_inode++) = '\0';

            sum->sha256 = NULL;

            if ((sum->sha256 = strchr(c_inode, ':'))) {
                *(sum->sha256++) = '\0';

                if (sum->sha256) {
                    if (attrs = strchr(sum->sha256, ':'), attrs) {
                        *(attrs++) = '\0';
                        sum->attrs = strtoul(attrs, NULL, 10);
                    }
                }

                sum->mtime = atol(c_mtime);
                sum->inode = atol(c_inode);
            }
        }
    }

    // Get extra data wdata+tags(optional)
    if (w_sum) {
        sum->wdata.user_id = w_sum;

        if ((sum->wdata.user_name = wstr_chr(w_sum, ':'))) {
            *(sum->wdata.user_name++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.group_id = wstr_chr(sum->wdata.user_name, ':'))) {
            *(sum->wdata.group_id++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.group_name = wstr_chr(sum->wdata.group_id, ':'))) {
            *(sum->wdata.group_name++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.process_name = wstr_chr(sum->wdata.group_name, ':'))) {
            *(sum->wdata.process_name++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.audit_uid = wstr_chr(sum->wdata.process_name, ':'))) {
            *(sum->wdata.audit_uid++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.audit_name = wstr_chr(sum->wdata.audit_uid, ':'))) {
            *(sum->wdata.audit_name++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.effective_uid = wstr_chr(sum->wdata.audit_name, ':'))) {
            *(sum->wdata.effective_uid++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.effective_name = wstr_chr(sum->wdata.effective_uid, ':'))) {
            *(sum->wdata.effective_name++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.ppid = wstr_chr(sum->wdata.effective_name, ':'))) {
            *(sum->wdata.ppid++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.process_id = wstr_chr(sum->wdata.ppid, ':'))) {
            *(sum->wdata.process_id++) = '\0';
        } else {
            return -1;
        }

        /* Look for a defined tag */
        if (sum->tag = wstr_chr(sum->wdata.process_id, ':'), sum->tag) {
            *(sum->tag++) = '\0';
        } else {
            sum->tag = NULL;
        }

        sum->wdata.user_name = unescape_whodata_sum(sum->wdata.user_name);
        sum->wdata.process_name = unescape_whodata_sum(sum->wdata.process_name);
        if (*sum->wdata.ppid == '-') {
            sum->wdata.ppid = NULL;
        }
    }

    return retval;
}

// Only decoded by manager
int sk_decode_extradata(sk_sum_t *sum, char *c_sum) {
    char *changes;
    char *date_alert;

    if (changes = strchr(c_sum, '!'), !changes) {
        return -1;
    }
    *changes++ = '\0';

    if (date_alert = strchr(changes, ':'), !date_alert) {
        return -1;
    }
    *(date_alert++) = '\0';
    sum->changes = atoi(changes);
    sum->date_alert = atol(date_alert);

    return 0;
}

char *unescape_whodata_sum(char *sum) {
    char *esc_it;

    if (*sum != '\0' ) {
        // The parameter string is not released
        esc_it = wstr_replace(sum, "\\ ", " ");
        sum = wstr_replace(esc_it, "\\:", ":");
        os_free(esc_it);
        return sum;
    }
    return NULL;
}

char *unescape_perm_sum(char *sum) {
    char *esc_it;

    if (*sum != '\0' ) {
        esc_it = wstr_replace(sum, "\\!", "!");
        sum = wstr_replace(esc_it, "\\:", ":");
        free(esc_it);
        esc_it = wstr_replace(sum, "\\ ", " ");
        free(sum);
        return esc_it;
    }
    return NULL;
}

void sk_fill_event(Eventinfo *lf, const char *f_name, const sk_sum_t *sum) {
    os_strdup(f_name, lf->filename);
    os_strdup(f_name, lf->fields[SK_FILE].value);

    if (sum->size) {
        os_strdup(sum->size, lf->size_after);
        os_strdup(sum->size, lf->fields[SK_SIZE].value);
    }

    if (sum->perm) {
        lf->perm_after = sum->perm;
        os_calloc(7, sizeof(char), lf->fields[SK_PERM].value);
        snprintf(lf->fields[SK_PERM].value, 7, "%06o", sum->perm);
    } else if (sum->win_perm && *sum->win_perm != '\0') {
        int size;
        os_strdup(sum->win_perm, lf->win_perm_after);
        os_calloc(OS_SIZE_256 + 1, sizeof(char), lf->fields[SK_PERM].value);
        if (size = decode_win_permissions(lf->fields[SK_PERM].value, OS_SIZE_256, lf->win_perm_after, 1, NULL), size > 1) {
            os_realloc(lf->fields[SK_PERM].value, size + 1, lf->fields[SK_PERM].value);
        }
    }

    if (sum->uid) {
        os_strdup(sum->uid, lf->owner_after);
        os_strdup(sum->uid, lf->fields[SK_UID].value);
    }

    if (sum->gid) {
        os_strdup(sum->gid, lf->gowner_after);
        os_strdup(sum->gid, lf->fields[SK_GID].value);
    }

    if (sum->md5) {
        os_strdup(sum->md5, lf->md5_after);
        os_strdup(sum->md5, lf->fields[SK_MD5].value);
    }

    if (sum->sha1) {
        os_strdup(sum->sha1, lf->sha1_after);
        os_strdup(sum->sha1, lf->fields[SK_SHA1].value);
    }

    if (sum->uname) {
        os_strdup(sum->uname, lf->uname_after);
        os_strdup(sum->uname, lf->fields[SK_UNAME].value);
    }

    if (sum->gname) {
        os_strdup(sum->gname, lf->gname_after);
        os_strdup(sum->gname, lf->fields[SK_GNAME].value);
    }

    if (sum->mtime) {
        lf->mtime_after = sum->mtime;
        os_calloc(20, sizeof(char), lf->fields[SK_MTIME].value);
        snprintf(lf->fields[SK_MTIME].value, 20, "%ld", sum->mtime);
    }

    if (sum->inode) {
        lf->inode_after = sum->inode;
        os_calloc(20, sizeof(char), lf->fields[SK_INODE].value);
        snprintf(lf->fields[SK_INODE].value, 20, "%ld", sum->inode);
    }

    if(sum->sha256) {
        os_strdup(sum->sha256, lf->sha256_after);
        os_strdup(sum->sha256, lf->fields[SK_SHA256].value);
    }

    if(sum->attrs) {
        lf->attrs_after = sum->attrs;
        os_calloc(OS_SIZE_256 + 1, sizeof(char), lf->fields[SK_ATTRS].value);
        decode_win_attributes(lf->fields[SK_ATTRS].value, lf->attrs_after);
    }

    if(sum->wdata.user_id) {
        os_strdup(sum->wdata.user_id, lf->user_id);
        os_strdup(sum->wdata.user_id, lf->fields[SK_USER_ID].value);
    }

    if(sum->wdata.user_name) {
        os_strdup(sum->wdata.user_name, lf->user_name);
        os_strdup(sum->wdata.user_name, lf->fields[SK_USER_NAME].value);
    }

    if(sum->wdata.group_id) {
        os_strdup(sum->wdata.group_id, lf->group_id);
        os_strdup(sum->wdata.group_id, lf->fields[SK_GROUP_ID].value);
    }

    if(sum->wdata.group_name) {
        os_strdup(sum->wdata.group_name, lf->group_name);
        os_strdup(sum->wdata.group_name, lf->fields[SK_GROUP_NAME].value);
    }

    if(sum->wdata.process_name) {
        os_strdup(sum->wdata.process_name, lf->process_name);
        os_strdup(sum->wdata.process_name, lf->fields[SK_PROC_NAME].value);
    }

    if(sum->wdata.audit_uid) {
        os_strdup(sum->wdata.audit_uid, lf->audit_uid);
        os_strdup(sum->wdata.audit_uid, lf->fields[SK_AUDIT_ID].value);
    }

    if(sum->wdata.audit_name) {
        os_strdup(sum->wdata.audit_name, lf->audit_name);
        os_strdup(sum->wdata.audit_name, lf->fields[SK_AUDIT_NAME].value);
    }

    if(sum->wdata.effective_uid) {
        os_strdup(sum->wdata.effective_uid, lf->effective_uid);
        os_strdup(sum->wdata.effective_uid, lf->fields[SK_EFFECTIVE_UID].value);
    }

    if(sum->wdata.effective_name) {
        os_strdup(sum->wdata.effective_name, lf->effective_name);
        os_strdup(sum->wdata.effective_name, lf->fields[SK_EFFECTIVE_NAME].value);
    }

    if(sum->wdata.ppid) {
        os_strdup(sum->wdata.ppid, lf->ppid);
        os_strdup(sum->wdata.ppid, lf->fields[SK_PPID].value);
    }

    if(sum->wdata.process_id) {
        os_strdup(sum->wdata.process_id, lf->process_id);
        os_strdup(sum->wdata.process_id, lf->fields[SK_PROC_ID].value);
    }

    if(sum->tag) {
        os_strdup(sum->tag, lf->sk_tag);
        os_strdup(sum->tag, lf->fields[SK_TAG].value);
    }
}

int sk_build_sum(const sk_sum_t * sum, char * output, size_t size) {
    int r;
    char s_perm[16];
    char s_mtime[16];
    char s_inode[16];
    char *username;

    if(sum->perm) {
        snprintf(s_perm, sizeof(s_perm), "%d", sum->perm);
    } else {
        *s_perm = '\0';
    }
    snprintf(s_mtime, sizeof(s_mtime), "%ld", sum->mtime);
    snprintf(s_inode, sizeof(s_inode), "%ld", sum->inode);

    username = wstr_replace((const char*)sum->uname, " ", "\\ ");

    // size:permision:uid:gid:md5:sha1:uname:gname:mtime:inode:sha256:attrs!changes:date_alert
    // ^^^^^^^^^^^^^^^^^^^^^^^^^^^checksum^^^^^^^^^^^^^^^^^^^^^^^^^^^!^^^^extradata^^^^^
    r = snprintf(output, size, "%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%u!%d:%ld",
            sum->size,
            (!sum->win_perm) ? s_perm : sum->win_perm,
            sum->uid,
            sum->gid,
            sum->md5,
            sum->sha1,
            sum->uname ? username : "",
            sum->gname ? sum->gname : "",
            sum->mtime ? s_mtime : "",
            sum->inode ? s_inode : "",
            sum->sha256 ? sum->sha256 : "",
            sum->attrs ? sum->attrs : 0,
            sum->changes,
            sum->date_alert
    );

    free(username);
    return r < (int)size ? 0 : -1;
}

void sk_sum_clean(sk_sum_t * sum) {
    os_free(sum->wdata.user_name);
    os_free(sum->wdata.process_name);
    os_free(sum->uname);
    os_free(sum->win_perm);
}

#endif

const char *get_user(__attribute__((unused)) const char *path, int uid, __attribute__((unused)) char **sid) {
    struct passwd *user = getpwuid(uid);
    return user ? user->pw_name : "";
}

const char *get_group(int gid) {
    struct group *group = getgrgid(gid);
    return group ? group->gr_name : "";
}

    void decode_win_attributes(char *str, unsigned int attrs) {
    size_t size;

    size = snprintf(str, OS_SIZE_256, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                    attrs & FILE_ATTRIBUTE_ARCHIVE ? "ARCHIVE, " : "",
                    attrs & FILE_ATTRIBUTE_COMPRESSED ? "COMPRESSED, " : "",
                    attrs & FILE_ATTRIBUTE_DEVICE ? "DEVICE, " : "",
                    attrs & FILE_ATTRIBUTE_DIRECTORY ? "DIRECTORY, " : "",
                    attrs & FILE_ATTRIBUTE_ENCRYPTED ? "ENCRYPTED, " : "",
                    attrs & FILE_ATTRIBUTE_HIDDEN ? "HIDDEN, " : "",
                    attrs & FILE_ATTRIBUTE_INTEGRITY_STREAM ? "INTEGRITY_STREAM, " : "",
                    attrs & FILE_ATTRIBUTE_NORMAL ? "NORMAL, " : "",
                    attrs & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED ? "NOT_CONTENT_INDEXED, " : "",
                    attrs & FILE_ATTRIBUTE_NO_SCRUB_DATA ? "NO_SCRUB_DATA, " : "",
                    attrs & FILE_ATTRIBUTE_OFFLINE ? "OFFLINE, " : "",
                    attrs & FILE_ATTRIBUTE_READONLY ? "READONLY, " : "",
                    attrs & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS ? "RECALL_ON_DATA_ACCESS, " : "",
                    attrs & FILE_ATTRIBUTE_RECALL_ON_OPEN ? "RECALL_ON_OPEN, " : "",
                    attrs & FILE_ATTRIBUTE_REPARSE_POINT ? "REPARSE_POINT, " : "",
                    attrs & FILE_ATTRIBUTE_SPARSE_FILE ? "SPARSE_FILE, " : "",
                    attrs & FILE_ATTRIBUTE_SYSTEM ? "SYSTEM, " : "",
                    attrs & FILE_ATTRIBUTE_TEMPORARY ? "TEMPORARY, " : "",
                    attrs & FILE_ATTRIBUTE_VIRTUAL ? "VIRTUAL, " : "");
    if (size > 2) {
        str[size - 2] = '\0';
    }
}

int decode_win_permissions(char *str, int str_size, char *raw_perm, char seq, cJSON *perm_array) {
    int writted = 0;
    int size;
    char *perm_it = NULL;
    char *base_it = NULL;
    char *account_name = NULL;
    static char *str_a = "allowed";
    static char *str_d = "denied";
    static char *str_n = "name";
    cJSON *perm_type = NULL;
    cJSON *json_it;
    char a_type;
    long mask;

    perm_it = raw_perm;
    while (perm_it = strchr(perm_it, '|'), perm_it) {
        // Get the account/group name
        base_it = ++perm_it;
        if (perm_it = strchr(perm_it, ','), !perm_it) {
            goto error;
        }
        *perm_it = '\0';
        os_strdup(base_it, account_name);
        *perm_it = ',';

        // Get the access type
        base_it = ++perm_it;
        if (perm_it = strchr(perm_it, ','), !perm_it) {
            goto error;
        }
        *perm_it = '\0';
        a_type = *base_it;
        *perm_it = ',';

        // Get the access mask
        base_it = ++perm_it;
        if (perm_it = strchr(perm_it, '|'), perm_it) {
            *perm_it = '\0';
            mask = strtol(base_it, NULL, 10);
            *perm_it = '|';
        } else {
            // End of the msg
            mask = strtol(base_it, NULL, 10);
        }

        if (perm_array) {
            cJSON *a_found = NULL;
            char *perm_type_str;


            perm_type_str = (a_type == '0') ? str_a : str_d;
            for (json_it = perm_array->child; json_it; json_it = json_it->next) {
                cJSON *obj;
                if (obj = cJSON_GetObjectItem(json_it, str_n), obj) {
                    if (!strcmp(obj->valuestring, account_name)) {
                        if (obj = cJSON_GetObjectItem(json_it, perm_type_str), obj) {
                            mdebug2("ACL [%s] fragmented. All permissions may not be displayed.", raw_perm);
                            goto next_it;
                        }
                        a_found = json_it;
                        break;
                    }
                }
            }

            if (perm_type = cJSON_CreateArray(), !perm_type) {
                goto error;
            }

            if (mask & GENERIC_READ) cJSON_AddItemToArray(perm_type, cJSON_CreateString("GENERIC_READ"));
            if (mask & GENERIC_WRITE) cJSON_AddItemToArray(perm_type, cJSON_CreateString("GENERIC_WRITE"));
            if (mask & GENERIC_EXECUTE) cJSON_AddItemToArray(perm_type, cJSON_CreateString("GENERIC_EXECUTE"));
            if (mask & GENERIC_ALL) cJSON_AddItemToArray(perm_type, cJSON_CreateString("GENERIC_ALL"));

            if (mask & DELETE) cJSON_AddItemToArray(perm_type, cJSON_CreateString("DELETE"));
            if (mask & READ_CONTROL) cJSON_AddItemToArray(perm_type, cJSON_CreateString("READ_CONTROL"));
            if (mask & WRITE_DAC) cJSON_AddItemToArray(perm_type, cJSON_CreateString("WRITE_DAC"));
            if (mask & WRITE_OWNER) cJSON_AddItemToArray(perm_type, cJSON_CreateString("WRITE_OWNER"));
            if (mask & SYNCHRONIZE) cJSON_AddItemToArray(perm_type, cJSON_CreateString("SYNCHRONIZE"));

            if (mask & FILE_READ_DATA) cJSON_AddItemToArray(perm_type, cJSON_CreateString("FILE_READ_DATA"));
            if (mask & FILE_WRITE_DATA) cJSON_AddItemToArray(perm_type, cJSON_CreateString("FILE_WRITE_DATA"));
            if (mask & FILE_APPEND_DATA) cJSON_AddItemToArray(perm_type, cJSON_CreateString("FILE_APPEND_DATA"));
            if (mask & FILE_READ_EA) cJSON_AddItemToArray(perm_type, cJSON_CreateString("FILE_READ_EA"));
            if (mask & FILE_WRITE_EA) cJSON_AddItemToArray(perm_type, cJSON_CreateString("FILE_WRITE_EA"));
            if (mask & FILE_EXECUTE) cJSON_AddItemToArray(perm_type, cJSON_CreateString("FILE_EXECUTE"));
            if (mask & FILE_READ_ATTRIBUTES) cJSON_AddItemToArray(perm_type, cJSON_CreateString("FILE_READ_ATTRIBUTES"));
            if (mask & FILE_WRITE_ATTRIBUTES) cJSON_AddItemToArray(perm_type, cJSON_CreateString("FILE_WRITE_ATTRIBUTES"));

            if (!a_found) {
                if (a_found = cJSON_CreateObject(), !a_found) {
                    goto error;
                }
                cJSON_AddStringToObject(a_found, str_n, account_name);
                cJSON_AddItemToArray(perm_array, a_found);
            }

            cJSON_AddItemToObject(a_found, perm_type_str, perm_type);
            perm_type = NULL;
            writted = 1;
        } else if (seq) {
            writted = snprintf(str, 50, "Permissions changed.\n");
        } else {
            size = snprintf(str, str_size, "   %s  (%s) -%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                            account_name,
                            a_type == '0' ? "ALLOWED" : "DENIED",
                            mask & GENERIC_READ ? " GENERIC_READ," : "",
                            mask & GENERIC_WRITE ? " GENERIC_WRITE," : "",
                            mask & GENERIC_EXECUTE ? " GENERIC_EXECUTE," : "",
                            mask & GENERIC_ALL ? " GENERIC_ALL," : "",
                            mask & DELETE ? " DELETE," : "",
                            mask & READ_CONTROL ? " READ_CONTROL," : "",
                            mask & WRITE_DAC ? " WRITE_DAC," : "",
                            mask & WRITE_OWNER ? " WRITE_OWNER," : "",
                            mask & SYNCHRONIZE ? " SYNCHRONIZE," : "",
                            mask & FILE_READ_DATA ? " FILE_READ_DATA," : "",
                            mask & FILE_WRITE_DATA ? " FILE_WRITE_DATA," : "",
                            mask & FILE_APPEND_DATA ? " FILE_APPEND_DATA," : "",
                            mask & FILE_READ_EA ? " FILE_READ_EA," : "",
                            mask & FILE_WRITE_EA ? " FILE_WRITE_EA," : "",
                            mask & FILE_EXECUTE ? " FILE_EXECUTE," : "",
                            mask & FILE_READ_ATTRIBUTES ? " FILE_READ_ATTRIBUTES," : "",
                            mask & FILE_WRITE_ATTRIBUTES ? " FILE_WRITE_ATTRIBUTES," : ""
                        );
            if (size > 1) {
                str[size - 1] = '\n';
            }
            writted += size;
            str += size;
        }

next_it:
        os_free(account_name);
        if (!perm_it) {
            break;
        }
    }

    return writted;
error:
    if (perm_type) {
        cJSON_free(perm_type);
    }
    os_free(account_name);
    mdebug1("The file permissions could not be decoded: '%s'", raw_perm);
    *str = '\0';
    return 0;
}

cJSON *perm_to_json(char *permissions) {
    cJSON *perm_array;

    if (perm_array = cJSON_CreateArray(), !perm_array) {
        return NULL;
    }

    if (!decode_win_permissions(NULL, 0, permissions, 0, perm_array)) {
        os_free(perm_array);
    }

    return perm_array;
}

cJSON *attrs_to_json(unsigned int attributes) {
    cJSON *ab_array;

    if (ab_array = cJSON_CreateArray(), !ab_array) {
        return NULL;
    }

    if (attributes & FILE_ATTRIBUTE_ARCHIVE) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("ARCHIVE"));
    }
    if (attributes & FILE_ATTRIBUTE_COMPRESSED) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("COMPRESSED"));
    }
    if (attributes & FILE_ATTRIBUTE_DEVICE) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("DEVICE"));
    }
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("DIRECTORY"));
    }
    if (attributes & FILE_ATTRIBUTE_ENCRYPTED) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("ENCRYPTED"));
    }
    if (attributes & FILE_ATTRIBUTE_HIDDEN) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("HIDDEN"));
    }
    if (attributes & FILE_ATTRIBUTE_INTEGRITY_STREAM) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("INTEGRITY_STREAM"));
    }
    if (attributes & FILE_ATTRIBUTE_NORMAL) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("NORMAL"));
    }
    if (attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("NOT_CONTENT_INDEXED"));
    }
    if (attributes & FILE_ATTRIBUTE_NO_SCRUB_DATA) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("NO_SCRUB_DATA"));
    }
    if (attributes & FILE_ATTRIBUTE_OFFLINE) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("OFFLINE"));
    }
    if (attributes & FILE_ATTRIBUTE_READONLY) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("READONLY"));
    }
    if (attributes & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("RECALL_ON_DATA_ACCESS"));
    }
    if (attributes & FILE_ATTRIBUTE_RECALL_ON_OPEN) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("RECALL_ON_OPEN"));
    }
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("REPARSE_POINT"));
    }
    if (attributes & FILE_ATTRIBUTE_SPARSE_FILE) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("SPARSE_FILE"));
    }
    if (attributes & FILE_ATTRIBUTE_SYSTEM) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("SYSTEM"));
    }
    if (attributes & FILE_ATTRIBUTE_TEMPORARY) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("TEMPORARY"));
    }
    if (attributes & FILE_ATTRIBUTE_VIRTUAL) {
        cJSON_AddItemToArray(ab_array, cJSON_CreateString("VIRTUAL"));
    }
    return ab_array;
}

char *get_attr_from_checksum(char *checksum, int attr) {
    char *str_attr = NULL;
    char *str_end = NULL;
    int i;

    if (attr < 1 || attr > FIM_NATTR) {
        return NULL;
    }

    str_attr = checksum;

    for(i = 2; i <= attr && str_attr; i++){
        str_attr = strchr(str_attr, ':');
        if(str_attr) {
            str_attr++;
        }
    }

    if (str_attr) {
        if(str_end = strchr(str_attr, ':'), str_end) {
            *(str_end++) = '\0';
        }
        return str_attr;
    }

    return NULL;
}

#else

char *escape_perm_sum(char *sum) {
    char *esc_it;

    if (*sum != '\0' ) {
        esc_it = wstr_replace(sum, "!", "\\!");
        sum = wstr_replace(esc_it, ":", "\\:");
        free(esc_it);
        esc_it = wstr_replace(sum, " ", "\\ ");
        free(sum);
        return esc_it;
    }
    return NULL;
}

char *get_user(const char *path, __attribute__((unused)) int uid, char **sid)
{
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
    BOOL bRtnBool = TRUE;
    char AcctName[BUFFER_LEN];
    char DomainName[BUFFER_LEN];
    DWORD dwAcctName = BUFFER_LEN;
    DWORD dwDomainName = BUFFER_LEN;
    SID_NAME_USE eUse = SidTypeUnknown;
    HANDLE hFile;
    PSECURITY_DESCRIPTOR pSD = NULL;
    char *result;

    // Get the handle of the file object.
    hFile = CreateFile(
                       TEXT(path),
                       GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

    // Check GetLastError for CreateFile error code.
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD dwErrorCode = GetLastError();
        LPSTR messageBuffer = NULL;
        LPSTR end;

        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwErrorCode, 0, (LPTSTR) &messageBuffer, 0, NULL);

        if (end = strchr(messageBuffer, '\r'), end) {
            *end = '\0';
        }

        switch (dwErrorCode) {
        case ERROR_ACCESS_DENIED:     // 5
        case ERROR_SHARING_VIOLATION: // 32
            mdebug1("At get_user(%s): CreateFile(): %s (%lu)", path, messageBuffer, dwErrorCode);
            break;
        default:
            mwarn("At get_user(%s): CreateFile(): %s (%lu)", path, messageBuffer, dwErrorCode);
        }

        LocalFree(messageBuffer);
        *AcctName = '\0';
        goto end;
    }

    // Get the owner SID of the file.
    dwRtnCode = GetSecurityInfo(
                                hFile,
                                SE_FILE_OBJECT,
                                OWNER_SECURITY_INFORMATION,
                                &pSidOwner,
                                NULL,
                                NULL,
                                NULL,
                                &pSD);

    CloseHandle(hFile);


    if (!ConvertSidToStringSid(pSidOwner, sid)) {
        *sid = NULL;
        mdebug1("The user's SID could not be extracted.");
    }

    // Check GetLastError for GetSecurityInfo error condition.
    if (dwRtnCode != ERROR_SUCCESS) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        merror("GetSecurityInfo error = %lu", dwErrorCode);
        *AcctName = '\0';
        goto end;
    }

    // Second call to LookupAccountSid to get the account name.
    bRtnBool = LookupAccountSid(
                                NULL,                   // name of local or remote computer
                                pSidOwner,              // security identifier
                                AcctName,               // account name buffer
                                (LPDWORD)&dwAcctName,   // size of account name buffer
                                DomainName,             // domain name
                                (LPDWORD)&dwDomainName, // size of domain name buffer
                                &eUse);                 // SID type

    // Check GetLastError for LookupAccountSid error condition.
    if (bRtnBool == FALSE) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();

        if (dwErrorCode == ERROR_NONE_MAPPED)
            mdebug1("Account owner not found for file '%s'", path);
        else
            merror("Error in LookupAccountSid.");

        *AcctName = '\0';
    }

end:
    if (pSD) {
        LocalFree(pSD);
    }

    result = wstr_replace((const char*)&AcctName, " ", "\\ ");

    return result;
}

int w_get_file_permissions(const char *file_path, char *permissions, int perm_size) {
    int retval = 0;
    int error;
    unsigned int i;
    SECURITY_DESCRIPTOR *s_desc = NULL;
    ACL *f_acl = NULL;
    void *f_ace;
    int has_dacl, default_dacl;
    unsigned long size = 0;
    ACL_SIZE_INFORMATION acl_size;
    char *perm_it = permissions;

    *permissions = '\0';

    if (!GetFileSecurity(file_path, DACL_SECURITY_INFORMATION, 0, 0, &size)) {
        // We must have this error at this point
        if (error = GetLastError(), error != ERROR_INSUFFICIENT_BUFFER) {
            return GetLastError();
        }
    }

    if (os_calloc(size, 1, s_desc), !s_desc) {
        return GetLastError();
    }

    if (!GetFileSecurity(file_path, DACL_SECURITY_INFORMATION, s_desc, size, &size)) {
        retval = GetLastError();
        goto end;
    }

    if (!GetSecurityDescriptorDacl(s_desc, &has_dacl, &f_acl, &default_dacl)) {
        mdebug1("The DACL of the file could not be obtained.");
        retval = GetLastError();
        goto end;
    }

    if (!has_dacl) {
        mdebug1("'%s' has no DACL, so no permits can be extracted.", file_path);
        goto end;
    }

    if (!GetAclInformation(f_acl, &acl_size, sizeof(acl_size), AclSizeInformation)) {
        mdebug1("No information could be obtained from the ACL.");
        retval = GetLastError();
        goto end;
    }

    for (i = 0; i < acl_size.AceCount; i++) {
        int written;

        if (!GetAce(f_acl, i, &f_ace)) {
            mdebug1("ACE number %d could not be obtained.", i);
            retval = -2;
            *permissions = '\0';
            goto end;
        }
        written = copy_ace_info(f_ace, perm_it, perm_size);
        if (written > 0) {
            perm_it += written;
            perm_size -= written;
            if (perm_size > 0) {
                continue;
            }
        }
        *permissions = '\0';
        retval = -3;
        mdebug1("The parameters of ACE number %d could not be extracted. %d bytes remaining.", i, perm_size);
        goto end;
    }

    mdebug2("The ACL extracted from '%s' is [%s].", file_path, permissions);
end:
    free(s_desc);
    return retval;
}

int copy_ace_info(void *ace, char *perm, int perm_size) {
    SID *sid;
    char *account_name = NULL;
    char *domain_name = NULL;
    int mask;
    int ace_type;
    int written = 0;
    int error;

	if (((ACCESS_ALLOWED_ACE *)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) {
		ACCESS_ALLOWED_ACE *allowed_ace = (ACCESS_ALLOWED_ACE *)ace;
		sid = (SID *)&allowed_ace->SidStart;
		mask = allowed_ace->Mask;
		ace_type = 0;
	} else if (((ACCESS_DENIED_ACE *)ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE) {
		ACCESS_DENIED_ACE *denied_ace = (ACCESS_DENIED_ACE *)ace;
		sid = (SID *)&denied_ace->SidStart;
		mask = denied_ace->Mask;
		ace_type = 1;
	} else {
        mdebug2("Invalid ACE type.");
        return 0;
    }


    if (!IsValidSid(sid)) {
        mdebug2("Invalid SID found in ACE.");
		return 0;
	}

    if (error = w_get_account_info(sid, &account_name, &domain_name), error) {
        mdebug2("No information could be extracted from the account linked to the SID. Error: %d.", error);
        goto end;
    }

    if (written + 1 < perm_size) {
        written = snprintf(perm, perm_size, "|%s,%d,%d", account_name, ace_type, mask);
    }

end:
    free(account_name);
    free(domain_name);
    return written;
}

int w_get_account_info(SID *sid, char **account_name, char **account_domain) {
    SID_NAME_USE snu;
    unsigned long a_name_size = 0;
    unsigned long a_domain_size = 0;
    int error;

    if (error = LookupAccountSid(0, sid, NULL, &a_name_size, NULL, &a_domain_size, &snu), !error) {
        // We must have this error at this point
        if (error = GetLastError(), error != ERROR_INSUFFICIENT_BUFFER) {
            return GetLastError();
        }
    }

    os_calloc(a_name_size, sizeof(char), *account_name);
    os_calloc(a_domain_size, sizeof(char), *account_domain);

    if (error = LookupAccountSid(0, sid, *account_name, &a_name_size, *account_domain, &a_domain_size, &snu), !error) {
        os_free(*account_name);
        os_free(*account_domain);
        return GetLastError();
    }

    return 0;
}

unsigned int w_get_file_attrs(const char *file_path) {
    unsigned int attrs;

    if (attrs = GetFileAttributesA(file_path), attrs == INVALID_FILE_ATTRIBUTES) {
        attrs = 0;
        merror("The attributes for '%s' could not be obtained. Error '%ld'.", file_path, GetLastError());
    }

    return attrs;
}

const char *get_group(__attribute__((unused)) int gid) {
    return "";
}

#endif
