/*
 * Shared functions for Syscheck events decoding
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscheck_op.h"

#ifdef WAZUH_UNIT_TESTING
/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);

#ifdef WIN32
#include "unit_tests/wrappers/windows/aclapi_wrappers.h"
#include "unit_tests/wrappers/windows/errhandlingapi_wrappers.h"
#include "unit_tests/wrappers/windows/fileapi_wrappers.h"
#include "unit_tests/wrappers/windows/handleapi_wrappers.h"
#include "unit_tests/wrappers/windows/sddl_wrappers.h"
#include "unit_tests/wrappers/windows/securitybaseapi_wrappers.h"
#include "unit_tests/wrappers/windows/winbase_wrappers.h"

#endif
#endif

int delete_target_file(const char *path) {
    char full_path[PATH_MAX] = "\0";
    snprintf(full_path, PATH_MAX, "%s%clocal", DIFF_DIR_PATH, PATH_SEP);

#ifdef WIN32
    char drive[3];
    drive[0] = PATH_SEP;
    drive[1] = path[0];

    char *windows_path = strchr(path, ':');

    if (windows_path == NULL) {
        mdebug1("Incorrect path. This does not contain ':' ");
        return 0;
    }

    strncat(full_path, drive, 2);
    strncat(full_path, (windows_path + 1), PATH_MAX - strlen(full_path) - 1);
#else
    strncat(full_path, path, PATH_MAX - strlen(full_path) - 1);
#endif

    if(rmdir_ex(full_path) == 0){
        return(remove_empty_folders(full_path));
    }

    return 1;
}

char *escape_syscheck_field(char *field) {
    char *esc_it;

    field = wstr_replace(field, "!", "\\!");
    esc_it = wstr_replace(field, ":", "\\:");
    free(field);
    field = wstr_replace(esc_it, " ", "\\ ");
    free(esc_it);

    return field;
}

void normalize_path(char * path) {
    assert(path != NULL);

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
    assert(path != NULL);

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
int sk_decode_sum(sk_sum_t *sum, char *c_sum, char *w_sum) {
    assert(sum != NULL);
    assert(c_sum != NULL);

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

        if (!(sum->uid = wstr_chr(c_perm, ':')))
            return -1;

        *(sum->uid++) = '\0';

        if (*c_perm == '|') {
            // Windows permissions
            char *unsc_perm = unescape_syscheck_field(c_perm);

            // We need to transform them to the new format
            // before processing
            sum->win_perm = decode_win_permissions(unsc_perm);
            free(unsc_perm);
        } else if (*c_perm == ':') {
        } else if (isdigit(*c_perm)) {
            sum->perm = atoi(c_perm);
        } else {
            os_strdup(c_perm, sum->win_perm);
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
                        if (isdigit(*attrs)) {
                            int attributes = strtoul(attrs, NULL, 10);
                            os_calloc(OS_SIZE_256 + 1, sizeof(char), sum->attributes);
                            decode_win_attributes(sum->attributes, attributes);
                        } else {
                            os_strdup(attrs, sum->attributes);
                        }
                    }
                }

                sum->mtime = atol(c_mtime);
                sum->inode = atol(c_inode);
            }
        }
    }

    // Get extra data
    if (w_sum) {
        char * user_name;
        char * process_name;
        char * symbolic_path;

        sum->wdata.user_id = w_sum;

        if ((user_name = wstr_chr(w_sum, ':'))) {
            *(user_name++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.group_id = wstr_chr(user_name, ':'))) {
            *(sum->wdata.group_id++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.group_name = wstr_chr(sum->wdata.group_id, ':'))) {
            *(sum->wdata.group_name++) = '\0';
        } else {
            return -1;
        }

        if ((process_name = wstr_chr(sum->wdata.group_name, ':'))) {
            *(process_name++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.audit_uid = wstr_chr(process_name, ':'))) {
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

        /* Look for a symbolic path */
        if (sum->tag && (symbolic_path = wstr_chr(sum->tag, ':'))) {
            *(symbolic_path++) = '\0';
        } else {
            symbolic_path = NULL;
        }

        /* Look if it is a silent event */
        if (symbolic_path && (c_inode = wstr_chr(symbolic_path, ':'))) {
            *(c_inode++) = '\0';
            if (*c_inode == '+') {
                sum->silent = 1;
            }
        }


        sum->symbolic_path = unescape_syscheck_field(symbolic_path);
        sum->wdata.user_name = unescape_syscheck_field(user_name);
        sum->wdata.process_name = unescape_syscheck_field(process_name);
        if (*sum->wdata.ppid == '-') {
            sum->wdata.ppid = NULL;
        }
    }

    return retval;
}

int sk_decode_extradata(sk_sum_t *sum, char *c_sum) {
    char *changes;
    char *date_alert;
    char *sym_path;

    assert(sum != NULL);
    assert(c_sum != NULL);

    if (changes = strchr(c_sum, '!'), !changes) {
        return 0;
    }
    *changes++ = '\0';

    if (date_alert = strchr(changes, ':'), !date_alert) {
        return 0;
    }
    *(date_alert++) = '\0';

    if (sym_path = strchr(date_alert, ':'), sym_path) {
        *(sym_path++) = '\0';
        sum->symbolic_path = unescape_syscheck_field(sym_path);
    }

    sum->changes = atoi(changes);
    sum->date_alert = atol(date_alert);

    return 1;
}

void sk_fill_event(Eventinfo *lf, const char *f_name, const sk_sum_t *sum) {
    assert(lf != NULL);
    assert(f_name != NULL);
    assert(sum != NULL);

    os_strdup(f_name, lf->filename);
    os_strdup(f_name, lf->fields[FIM_FILE].value);

    if (sum->size) {
        os_strdup(sum->size, lf->fields[FIM_SIZE].value);
    }

    if (sum->perm) {
        os_calloc(7, sizeof(char), lf->fields[FIM_PERM].value);
        snprintf(lf->fields[FIM_PERM].value, 7, "%06o", sum->perm);
    } else if (sum->win_perm && *sum->win_perm != '\0') {
        os_strdup(sum->win_perm, lf->fields[FIM_PERM].value);
    }

    if (sum->uid) {
        os_strdup(sum->uid, lf->fields[FIM_UID].value);
    }

    if (sum->gid) {
        os_strdup(sum->gid, lf->fields[FIM_GID].value);
    }

    if (sum->md5) {
        os_strdup(sum->md5, lf->fields[FIM_MD5].value);
    }

    if (sum->sha1) {
        os_strdup(sum->sha1, lf->fields[FIM_SHA1].value);
    }

    if (sum->uname) {
        os_strdup(sum->uname, lf->fields[FIM_UNAME].value);
    }

    if (sum->gname) {
        os_strdup(sum->gname, lf->fields[FIM_GNAME].value);
    }

    if (sum->mtime) {
        lf->mtime_after = sum->mtime;
        os_calloc(20, sizeof(char), lf->fields[FIM_MTIME].value);
        snprintf(lf->fields[FIM_MTIME].value, 20, "%ld", sum->mtime);
    }

    if (sum->inode) {
        lf->inode_after = sum->inode;
        os_calloc(20, sizeof(char), lf->fields[FIM_INODE].value);
        snprintf(lf->fields[FIM_INODE].value, 20, "%ld", sum->inode);
    }

    if(sum->sha256) {
        os_strdup(sum->sha256, lf->fields[FIM_SHA256].value);
    }

    if(sum->attributes) {
        os_strdup(sum->attributes, lf->fields[FIM_ATTRS].value);
    }

    if(sum->wdata.user_id) {
        os_strdup(sum->wdata.user_id, lf->user_id);
        os_strdup(sum->wdata.user_id, lf->fields[FIM_USER_ID].value);
    }

    if(sum->wdata.user_name) {
        os_strdup(sum->wdata.user_name, lf->user_name);
        os_strdup(sum->wdata.user_name, lf->fields[FIM_USER_NAME].value);
    }

    if(sum->wdata.group_id) {
        os_strdup(sum->wdata.group_id, lf->group_id);
        os_strdup(sum->wdata.group_id, lf->fields[FIM_GROUP_ID].value);
    }

    if(sum->wdata.group_name) {
        os_strdup(sum->wdata.group_name, lf->group_name);
        os_strdup(sum->wdata.group_name, lf->fields[FIM_GROUP_NAME].value);
    }

    if(sum->wdata.process_name) {
        os_strdup(sum->wdata.process_name, lf->process_name);
        os_strdup(sum->wdata.process_name, lf->fields[FIM_PROC_NAME].value);
    }

    if(sum->wdata.parent_name) {
        os_strdup(sum->wdata.parent_name, lf->parent_name);
        os_strdup(sum->wdata.parent_name, lf->fields[FIM_PROC_PNAME].value);
    }

    if(sum->wdata.cwd) {
        os_strdup(sum->wdata.cwd, lf->cwd);
        os_strdup(sum->wdata.cwd, lf->fields[FIM_AUDIT_CWD].value);
    }

    if(sum->wdata.parent_cwd) {
        os_strdup(sum->wdata.parent_cwd, lf->parent_cwd);
        os_strdup(sum->wdata.parent_cwd, lf->fields[FIM_AUDIT_PCWD].value);
    }

    if(sum->wdata.audit_uid) {
        os_strdup(sum->wdata.audit_uid, lf->audit_uid);
        os_strdup(sum->wdata.audit_uid, lf->fields[FIM_AUDIT_ID].value);
    }

    if(sum->wdata.audit_name) {
        os_strdup(sum->wdata.audit_name, lf->audit_name);
        os_strdup(sum->wdata.audit_name, lf->fields[FIM_AUDIT_NAME].value);
    }

    if(sum->wdata.effective_uid) {
        os_strdup(sum->wdata.effective_uid, lf->effective_uid);
        os_strdup(sum->wdata.effective_uid, lf->fields[FIM_EFFECTIVE_UID].value);
    }

    if(sum->wdata.effective_name) {
        os_strdup(sum->wdata.effective_name, lf->effective_name);
        os_strdup(sum->wdata.effective_name, lf->fields[FIM_EFFECTIVE_NAME].value);
    }

    if(sum->wdata.ppid) {
        os_strdup(sum->wdata.ppid, lf->ppid);
        os_strdup(sum->wdata.ppid, lf->fields[FIM_PPID].value);
    }

    if(sum->wdata.process_id) {
        os_strdup(sum->wdata.process_id, lf->process_id);
        os_strdup(sum->wdata.process_id, lf->fields[FIM_PROC_ID].value);
    }

    if(sum->tag) {
        os_strdup(sum->tag, lf->sk_tag);
        os_strdup(sum->tag, lf->fields[FIM_TAG].value);
    }

    if(sum->symbolic_path) {
        os_strdup(sum->symbolic_path, lf->sym_path);
        os_strdup(sum->symbolic_path, lf->fields[FIM_SYM_PATH].value);
    }
}

int sk_build_sum(const sk_sum_t * sum, char * output, size_t size) {
    int r;
    char s_perm[16];
    char s_mtime[16];
    char s_inode[16];
    char *username;

    assert(sum != NULL);
    assert(output != NULL);

    if(sum->perm) {
        snprintf(s_perm, sizeof(s_perm), "%d", sum->perm);
    } else {
        *s_perm = '\0';
    }
    snprintf(s_mtime, sizeof(s_mtime), "%ld", sum->mtime);
    snprintf(s_inode, sizeof(s_inode), "%ld", sum->inode);

    username = wstr_replace((const char*)sum->uname, " ", "\\ ");

    // This string will be sent to Analysisd, who will parse it
    // If it is a Windows event, we need to escape the permissions
    char *win_perm = NULL;
    if (sum->win_perm) {
        win_perm = wstr_replace(sum->win_perm, ":", "\\:");
    }

    // size:permision:uid:gid:md5:sha1:uname:gname:mtime:inode:sha256:attrs!changes:date_alert
    // ^^^^^^^^^^^^^^^^^^^^^^^^^^^checksum^^^^^^^^^^^^^^^^^^^^^^^^^^^!^^^^extradata^^^^^
    r = snprintf(output, size, "%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s!%d:%ld",
            sum->size,
            (!win_perm) ? s_perm : win_perm,
            sum->uid,
            sum->gid,
            sum->md5,
            sum->sha1,
            sum->uname ? username : "",
            sum->gname ? sum->gname : "",
            sum->mtime ? s_mtime : "",
            sum->inode ? s_inode : "",
            sum->sha256 ? sum->sha256 : "",
            sum->attributes ? sum->attributes : "",
            sum->changes,
            sum->date_alert
    );

    free(win_perm);
    free(username);
    return r < (int)size ? 0 : -1;
}

void sk_sum_clean(sk_sum_t * sum) {
    assert(sum != NULL);

    os_free(sum->symbolic_path);
    os_free(sum->attributes);
    os_free(sum->wdata.user_name);
    os_free(sum->wdata.process_name);
    os_free(sum->wdata.parent_cwd);
    os_free(sum->wdata.cwd);
    os_free(sum->wdata.parent_name);
    os_free(sum->uname);
    os_free(sum->win_perm);
}

#endif /* #ifndef CLIENT */

char *unescape_syscheck_field(char *sum) {
    char *esc_it;

    if (sum && *sum != '\0') {
        // The parameter string is not released
        sum = wstr_replace(sum, "\\ ", " ");
        esc_it = wstr_replace(sum, "\\!", "!");
        free(sum);
        sum = wstr_replace(esc_it, "\\:", ":");
        os_free(esc_it);
        return sum;
    }
    return NULL;
}

char *get_user(int uid) {
    struct passwd pwd;
    struct passwd *result;
    char *buf;
    char *user_name = NULL;
    int bufsize;
    int errno;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) {
        bufsize = 16384;
    }

    os_calloc(bufsize, sizeof(char), buf);

#ifdef SOLARIS
    result = getpwuid_r(uid, &pwd, buf, bufsize);
#else
    errno = getpwuid_r(uid, &pwd, buf, bufsize, &result);
#endif
    if (result == NULL) {
        if (errno == 0) {
            mdebug2("User with uid '%d' not found.\n", uid);
        }
        else {
            mdebug2("Failed getting user_name (%d): '%s'\n", errno, strerror(errno));
        }
    } else {
        os_strdup(pwd.pw_name, user_name);
    }

    os_free(buf);

    return user_name;
}

const char *get_group(int gid) {
    struct group *group = getgrgid(gid);
    return group ? group->gr_name : "";
}

/* Send a one-way message to Syscheck */
void ag_send_syscheck(char * message) {
    int sock = OS_ConnectUnixDomain(DEFAULTDIR SYS_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);

    if (sock < 0) {
        mwarn("dbsync: cannot connect to syscheck: %s (%d)", strerror(errno), errno);
        return;
    }

    if (OS_SendSecureTCP(sock, strlen(message), message) < 0) {
        mwarn("Cannot send message to syscheck: %s (%d)", strerror(errno), errno);
    }

    close(sock);
}

#else /* #ifndef WIN32 */

char *get_user(const char *path, char **sid) {
    DWORD dwRtnCode = 0;
    DWORD dwSecurityInfoErrorCode = 0;
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

    if (dwRtnCode != ERROR_SUCCESS) {
        dwSecurityInfoErrorCode = GetLastError();
    }

    CloseHandle(hFile);

    char *aux;
    if (!ConvertSidToStringSid(pSidOwner, &aux)) {
        *sid = NULL;
        mdebug1("The user's SID could not be extracted.");
    } else {
        os_strdup(aux, *sid);
        LocalFree(aux);
    }

    // Check GetLastError for GetSecurityInfo error condition.
    if (dwRtnCode != ERROR_SUCCESS) {
        merror("GetSecurityInfo error = %lu", dwSecurityInfoErrorCode);
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

    if (!has_dacl || !f_acl) {
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
        mdebug1("The parameters of ACE number %d from '%s' could not be extracted. %d bytes remaining.", i, file_path, perm_size);
    }

end:
    free(s_desc);
    return retval;
}

int copy_ace_info(void *ace, char *perm, int perm_size) {
    SID *sid;
    char *sid_str = NULL;
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
        if (!ConvertSidToStringSid(sid, &sid_str)) {
            mdebug2("Could not extract the SID.");
            goto end;
        }
    }

    if (written + 1 < perm_size) {
        written = snprintf(perm, perm_size, "|%s,%d,%d", sid_str ? sid_str : account_name, ace_type, mask);
    }

end:
    if (sid_str) {
        LocalFree(sid_str);
    }
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

unsigned int w_directory_exists(const char *path){
    if (path != NULL){
        unsigned int attrs = w_get_file_attrs(path);
        return attrs & FILE_ATTRIBUTE_DIRECTORY;
    }

    return 0;
}

unsigned int w_get_file_attrs(const char *file_path) {
    unsigned int attrs;

    if (attrs = GetFileAttributesA(file_path), attrs == INVALID_FILE_ATTRIBUTES) {
        attrs = 0;
        mdebug2("The attributes for '%s' could not be obtained. Error '%ld'.", file_path, GetLastError());
    }

    return attrs;
}

const char *get_group(__attribute__((unused)) int gid) {
    return "";
}

/* Send a one-way message to Syscheck */
void ag_send_syscheck(char * message) {
    char * response = NULL;
    syscom_dispatch(message, &response);
    free(response);
}

#endif /* # else (ifndef WIN32) */

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

char *decode_win_permissions(char *raw_perm) {
    int written = 0;
    int size = 0;
    char *base_it = NULL;
    char *account_name = NULL;
    char a_type;
    char *decoded_perm;
    long mask;

    if (*raw_perm != '|') {
        // It is trying to convert to the new format
        // a permissions that have already been transformed
        os_strdup("", decoded_perm);
        return decoded_perm;
    }

    os_calloc(MAX_WIN_PERM_SIZE, sizeof(char), decoded_perm);

    int perm_size = MAX_WIN_PERM_SIZE;
    char *decoded_it = decoded_perm;
    char *perm_it = raw_perm;

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

        size = snprintf(decoded_it, perm_size, "%s (%s): %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                        account_name,
                        a_type == '0' ? "allowed" : "denied",
                        mask & GENERIC_READ ? "generic_read|" : "",
                        mask & GENERIC_WRITE ? "generic_write|" : "",
                        mask & GENERIC_EXECUTE ? "generic_execute|" : "",
                        mask & GENERIC_ALL ? "generic_all|" : "",
                        mask & DELETE ? "delete|" : "",
                        mask & READ_CONTROL ? "read_control|" : "",
                        mask & WRITE_DAC ? "write_dac|" : "",
                        mask & WRITE_OWNER ? "write_owner|" : "",
                        mask & SYNCHRONIZE ? "synchronize|" : "",
                        mask & FILE_READ_DATA ? "read_data|" : "",
                        mask & FILE_WRITE_DATA ? "write_data|" : "",
                        mask & FILE_APPEND_DATA ? "append_data|" : "",
                        mask & FILE_READ_EA ? "read_ea|" : "",
                        mask & FILE_WRITE_EA ? "write_ea|" : "",
                        mask & FILE_EXECUTE ? "execute|" : "",
                        mask & FILE_READ_ATTRIBUTES ? "read_attributes|" : "",
                        mask & FILE_WRITE_ATTRIBUTES ? "write_attributes|" : ""
                    );

        if (size + 1 < perm_size) {
            strncpy(decoded_it + (size++) - 1, ", ", 3);
        }

        written += size;
        decoded_it += size;
        perm_size -= size;

        os_free(account_name);
        if (!perm_it) {
            break;
        }
    }

    if (decoded_it && size > 1) {
        *(decoded_it - 2) = '\0';
        // Adjusts the final size
        os_realloc(decoded_perm, written * sizeof(char), decoded_perm);
    }

    return decoded_perm;
error:
    free(decoded_perm);
    free(account_name);
    mdebug1("The file permissions could not be decoded: '%s'.", raw_perm);
    return NULL;
}

cJSON *attrs_to_json(const char *attributes) {
    cJSON *attrs_array;

    assert(attributes != NULL);

    if (attrs_array = cJSON_CreateArray(), !attrs_array) {
        return NULL;
    }

    char *attrs_cpy;
    os_strdup(attributes, attrs_cpy);
    char *attr = attrs_cpy;

    while (attr) {
        char *sep = strchr(attr, ',');
        if (sep) {
            *(sep++) = '\0';
        }
        while (*attr == ' ') attr++;
        cJSON_AddItemToArray(attrs_array, cJSON_CreateString(attr));
        attr = sep;
    }

    free(attrs_cpy);
    return attrs_array;
}

cJSON *win_perm_to_json(char *perms) {
    cJSON *perms_json;

    assert(perms != NULL);

    if (perms_json = cJSON_CreateArray(), !perms_json) {
        return NULL;
    }

    char *perms_cpy;
    os_strdup(perms, perms_cpy);
    char *perms_it = perms_cpy;

    while (perms_it && *perms_it) {
        char *perm_node = perms_it;
        perms_it = strchr(perms_it, ',');
        if (perms_it) {
            *(perms_it++) = '\0';
        }

        while (*perm_node == ' ') perm_node++;

        // Get the username
        char *username = perm_node;
        perm_node = strchr(perm_node, '(');
        if (!perm_node) {
            goto error;
        }
        *(perm_node++) = '\0';
        {
            size_t u_size = strlen(username);
            if (u_size > 0 && username[u_size - 1] == ' ') {
                username[u_size - 1] = '\0';
            }
        }

        // Get the permission type
        char *perm_type = perm_node;
        perm_node = strchr(perm_node, ')');
        if (!perm_node) {
            goto error;
        }
        *(perm_node++) = '\0';

        perm_node = strchr(perm_node, ' ');
        if (!perm_node) {
            goto error;
        }
        while (*perm_node == ' ') perm_node++;

        // Get the permissions
        char *permissions = perm_node;
        perm_node = strchr(perm_node, ',');
        if (perm_node) {
            *(perm_node++) = '\0'; //LCOV_EXCL_LINE
        }

        const char *tag_name = "name";
        cJSON *json_it;
        cJSON *user_obj = NULL;
        char next_it = 0;
        for (json_it = perms_json->child; json_it; json_it = json_it->next) {
            cJSON *obj;
            if (obj = cJSON_GetObjectItem(json_it, tag_name), !obj || !obj->valuestring) {
                continue; //LCOV_EXCL_LINE
            }
            if (!strcmp(obj->valuestring, username)) {
                user_obj = json_it;
                if (obj = cJSON_GetObjectItem(json_it, perm_type), obj) {
                    mdebug1("ACL [%s] fragmented. All permissions may not be displayed.", perms);
                    next_it = 1;
                }
                break;
            }
        }
        if (next_it) {
            break;
        }

        if (!user_obj) {
            if (user_obj = cJSON_CreateObject(), !user_obj) {
                goto error;
            }
            cJSON_AddStringToObject(user_obj, tag_name, username);
            cJSON_AddItemToArray(perms_json, user_obj);
        }

        cJSON *specific_perms;
        if (specific_perms = cJSON_CreateArray(), !specific_perms) {
            goto error;
        }

        char **perms_array = NULL;
        wstr_split(permissions, "|", NULL, 1, &perms_array);
        if (!perms_array) {
            cJSON_Delete(specific_perms);
            goto error;
        }

        int i;
        for (i = 0; perms_array[i]; i++) {
            str_uppercase(perms_array[i]);
            cJSON_AddItemToArray(specific_perms, cJSON_CreateString(perms_array[i]));
        }
        cJSON_AddItemToObject(user_obj, perm_type, specific_perms);

        w_FreeArray(perms_array);
        free(perms_array);
    }

    free(perms_cpy);
    return perms_json;
error:
    mdebug1("Uncontrolled condition when parsing a Windows permission from '%s'.", perms);
    cJSON_Delete(perms_json);
    free(perms_cpy);
    return NULL;
}
