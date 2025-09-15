/*
 * Shared functions for Syscheck events decoding
 * Copyright (C) 2015, Wazuh Inc.
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
#include "unit_tests/wrappers/windows/winreg_wrappers.h"

#endif
#endif

#ifdef WIN32
/**
 * @brief Retrieves the permissions of a specific file (Windows)
 *
 * @param [out] ace_json cJSON with the mask to process
 * @param [in] mask Mask with the permissions
 * @param [in] ace_type string "allowed" or "denied" depends on ace type
 */
static void make_mask_readable (cJSON *ace_json, int mask, char *ace_type);
#endif

int remove_empty_folders(const char *path) {
    assert(path != NULL);

    char DIFF_PATH[PATH_MAX] = DIFF_DIR;
    const char *c;
    char parent[PATH_MAX] = "\0";
    char ** subdir;
    int retval = 0;

    // Get parent
    c = strrchr(path, PATH_SEP);
    if (c) {
        memcpy(parent, path, c - path);
        parent[c - path] = '\0';
        // Don't delete above /diff
        if (strcmp(DIFF_PATH, parent) != 0) {
            subdir = wreaddir(parent);
            if (!(subdir && *subdir)) {
                // Remove empty folder
                mdebug1("Removing empty directory '%s'.", parent);
                if (rmdir_ex(parent) != 0) {
                    mwarn("Empty directory '%s' couldn't be deleted. ('%s')", parent, strerror(errno));
                    retval = -1;
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
char *get_user(int uid) {
    struct passwd pwd;
    struct passwd *result;
    char *buf;
    char *user_name = NULL;
    int bufsize;
    int errno;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize < 16384) {
        bufsize = 16384;
    }

    os_calloc(bufsize, sizeof(char), buf);

#if defined(SUN_MAJOR_VERSION) && defined(SUN_MINOR_VERSION)  && \
    (SUN_MAJOR_VERSION < 11) || \
    ((SUN_MAJOR_VERSION == 11) && (SUN_MINOR_VERSION < 4))
    result = getpwuid_r(uid, &pwd, buf, bufsize);
#else
    errno = getpwuid_r(uid, &pwd, buf, bufsize, &result);
#endif
    if (result == NULL) {
        if (errno == 0) {
            mdebug2("User with uid '%d' not found.\n", uid);
        }
        else {
            mdebug2("Failed getting user_name for uid %d: (%d): '%s'\n", uid, errno, strerror(errno));
        }
    } else {
        os_strdup(pwd.pw_name, user_name);
    }

    os_free(buf);

    return user_name;
}

char *get_group(int gid) {
    struct group grp;
    struct group *result;
    char *group_name = NULL;
    char *buf;
    int bufsize;

    bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (bufsize < 16384) {
        bufsize = 16384;
    }

    os_calloc(bufsize, sizeof(char), buf);

    result = w_getgrgid(gid, &grp, buf, bufsize);

    if (result == NULL) {
        if (errno == 0) {
            mdebug2("Group with gid '%d' not found.\n", gid);
        } else {
            mdebug2("Failed getting group_name for gid %d: (%d): '%s'\n", gid, errno, strerror(errno));
        }
    } else {
        os_strdup(grp.gr_name, group_name);
    }

    os_free(buf);

    return group_name;
}

/* Send a one-way message to Syscheck */
void ag_send_syscheck(char * message, size_t length) {
    int sock = OS_ConnectUnixDomain(SYS_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);

    if (sock < 0) {
        mwarn("dbsync: cannot connect to syscheck: %s (%d)", strerror(errno), errno);
        return;
    }

    if (OS_SendSecureTCP(sock, length, message) < 0) {
        mwarn("Cannot send message to syscheck: %s (%d)", strerror(errno), errno);
    }

    close(sock);
}

#else /* #ifndef WIN32 */

// LCOV_EXCL_START
char *get_registry_user(const char *path, char **sid, HANDLE hndl) {
    return get_user(path, sid, hndl, SE_REGISTRY_KEY);
}
// LCOV_EXCL_STOP

char *get_file_user(const char *path, char **sid) {
    HANDLE hFile;
    char *result;

    // Get the handle of the file object.
    hFile = wCreateFile(TEXT(path),
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

        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL, dwErrorCode, 0, (LPTSTR) &messageBuffer, 0, NULL);

        if (end = strchr(messageBuffer, '\r'), end) {
            *end = '\0';
        }

        switch (dwErrorCode) {
        case ERROR_ACCESS_DENIED:     // 5
        case ERROR_SHARING_VIOLATION: // 32
            mdebug1("At get_user(%s): wCreateFile(): %s (%lu)", path, messageBuffer, dwErrorCode);
            break;
        default:
            mwarn("At get_user(%s): wCreateFile(): %s (%lu)", path, messageBuffer, dwErrorCode);
        }

        LocalFree(messageBuffer);
    }

    result = get_user(path, sid, hFile, SE_FILE_OBJECT);

    CloseHandle(hFile);

    return result;
}

char *get_user(const char *path, char **sid, HANDLE hndl, SE_OBJECT_TYPE object_type) {
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
    BOOL bRtnBool = TRUE;
    char AcctName[BUFFER_LEN];
    char DomainName[BUFFER_LEN];
    DWORD dwAcctName = BUFFER_LEN;
    DWORD dwDomainName = BUFFER_LEN;
    SID_NAME_USE eUse = SidTypeUnknown;
    PSECURITY_DESCRIPTOR pSD = NULL;
    LPSTR local_sid;
    char *result;

    if (hndl == INVALID_HANDLE_VALUE) {
        os_strdup("", *sid);
        *AcctName = '\0';
        goto end;
    }

    // Get the owner SID of the file or registry
    dwRtnCode = GetSecurityInfo(hndl,                       // Object handle
                                object_type,                // Object type (file or registry)
                                OWNER_SECURITY_INFORMATION, // Security information bit flags
                                &pSidOwner,                 // Owner SID
                                NULL,                       // Group SID
                                NULL,                       // DACL
                                NULL,                       // SACL
                                &pSD);                      // Security descriptor

    if (!ConvertSidToStringSid(pSidOwner, &local_sid)) {
        os_strdup("", *sid);
        mdebug1("The user's SID could not be extracted.");
    } else {
        os_strdup(local_sid, *sid);
        LocalFree(local_sid);
    }

    if (dwRtnCode != ERROR_SUCCESS) {
        mdebug1("GetSecurityInfo error code = (%lu), '%s'", dwRtnCode, win_strerror(dwRtnCode));
        *AcctName = '\0';
        goto end;
    }

    char *utf8_name = NULL;
    char *utf8_domain = NULL;
    bRtnBool = utf8_LookupAccountSid(NULL,              // Name of local or remote computer
                                     pSidOwner,         // Security identifier
                                     &utf8_name,        // Account name buffer
                                     NULL,              // Size of account name buffer
                                     &utf8_domain,      // Domain name
                                     NULL,              // Size of domain name buffer
                                     &eUse);            // SID type

    if (bRtnBool && utf8_name) {
        snprintf(AcctName, BUFFER_LEN, "%s", utf8_name);
        snprintf(DomainName, BUFFER_LEN, "%s", utf8_domain);
    }

    os_free(utf8_name);
    os_free(utf8_domain);

    // Check GetLastError for LookupAccountSidW error condition.
    if (bRtnBool == FALSE) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();

        if (dwErrorCode == ERROR_NONE_MAPPED) {
            mdebug1("Account owner not found for '%s'", path);
        }
        else {
            LPSTR messageBuffer = NULL;
            LPSTR end;

            FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                          NULL, dwErrorCode, 0, (LPTSTR) &messageBuffer, 0, NULL);
            if (end = strchr(messageBuffer, '\r'), end) {
                *end = '\0';
            }

            mwarn(FIM_REGISTRY_ACC_SID, "user", dwErrorCode, messageBuffer);
            LocalFree(messageBuffer);
        }

        *AcctName = '\0';
    }

end:
    if (pSD) {
        LocalFree(pSD);
    }

    result = wstr_replace(AcctName, " ", "\\ ");

    return result;
}


/**
 * @brief Retrieves the permissions of a specific file (Windows)
 *
 * @param [out] acl_json cJSON to write the permissions
 * @param [in] sid The user ID associated to the user
 * @param [in] account_name The account name associated to the sid
 * @param [in] ace_type int with 0 if "allowed" ace, 1 if "denied" ace
 * @param [in] mask Mask with the permissions
 */
static void add_ace_to_json(cJSON *acl_json, char *sid, char *account_name, const char *ace_type, int mask) {
    cJSON *ace_json = NULL;
    cJSON *mask_json = NULL;

    ace_json = cJSON_GetObjectItem(acl_json, sid);
    if (ace_json == NULL) {
        ace_json = cJSON_CreateObject();
        if (ace_json == NULL) {
            mwarn(FIM_CJSON_ERROR_CREATE_ITEM);
            return;
        }
        cJSON_AddStringToObject(ace_json, "name", account_name);
        cJSON_AddItemToObject(acl_json, sid, ace_json);
    }

    mask_json = cJSON_GetObjectItem(ace_json, ace_type);
    if (mask_json == NULL) {
        cJSON_AddNumberToObject(ace_json, ace_type, mask);
        return;
    }

    cJSON_SetNumberValue(mask_json, (mask_json->valueint | mask));

    return;
}


/**
 * @brief Retrieves the permissions of a specific file (Windows)
 *
 * @param [in] ace ACE structure
 * @param [out] acl_json cJSON to write the permissions
 * @return 0 on success, the error code on failure, -2 if ACE could not be obtained
 */
static int process_ace_info(void *ace, cJSON *acl_json) {
    SID *sid;
    char *sid_str = NULL;
    char *account_name = NULL;
    char *domain_name = NULL;
    int mask;
    int ace_type;
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
        return 1;
    }

    if (!IsValidSid(sid)) {
        mdebug2("Invalid SID found in ACE.");
        return 1;
    }

    if (error = w_get_account_info(sid, &account_name, &domain_name), error) {
        mdebug2("No information could be extracted from the account linked to the SID. Error: %d.", error);
    }

    if (!ConvertSidToStringSid(sid, &sid_str)) {
        mdebug2("Could not extract the SID.");
        os_free(account_name);
        os_free(domain_name);
        return 1;
    }

    add_ace_to_json(acl_json, sid_str, account_name, ace_type ? "denied" : "allowed", mask);

    LocalFree(sid_str);
    os_free(account_name);
    os_free(domain_name);

    return 0;
}

/**
 * @brief Translates an ACL permissions to JSON.
 *
 * @param [in] pSecurityDescriptor A security descriptor to be translated.
 * @param [out] acl_json A pointer to a cJSON object where information will be stored.
 * @retval 0 on success.
 * @retval -1 if the cJSON object could not be initialized.
 * @retval -2 if no DACL is retrieved.
 * @retval An error code retrieved from `GetLastError` otherwise.
 */
static int get_win_permissions(PSECURITY_DESCRIPTOR pSecurityDescriptor, cJSON **output_acl) {
    ACL_SIZE_INFORMATION aclsizeinfo;
    ACCESS_ALLOWED_ACE *pAce = NULL;
    PACL pDacl = NULL;
    BOOL fDaclPresent = FALSE;
    BOOL fDaclDefaulted = TRUE;
    BOOL bRtnBool = TRUE;
    DWORD dwErrorCode = 0;
    DWORD cAce;
    cJSON *acl_json = cJSON_CreateObject();

    if (acl_json == NULL) {
        mwarn(FIM_CJSON_ERROR_CREATE_ITEM);
        return -1;
    }

    // Retrieve a pointer to the DACL in the security descriptor.
    bRtnBool = GetSecurityDescriptorDacl(pSecurityDescriptor,   // Structure that contains the DACL
                                         &fDaclPresent,         // Indicates the presence of a DACL
                                         &pDacl,                // Pointer to ACL
                                         &fDaclDefaulted);      // Flag set to the value of the SE_DACL_DEFAULTED flag

    if (bRtnBool == FALSE) {
        dwErrorCode = GetLastError();
        mdebug2("GetSecurityDescriptorDacl failed. GetLastError returned: %ld", dwErrorCode);

        cJSON_Delete(acl_json);
        return dwErrorCode;
    }

    // Check whether no DACL or a NULL DACL was retrieved from the security descriptor buffer.
    if (fDaclPresent == FALSE || pDacl == NULL) {
        mdebug2("No DACL was found (all access is denied), or a NULL DACL (unrestricted access) was found.");

        cJSON_Delete(acl_json);
        return -2;
    }

    // Retrieve the ACL_SIZE_INFORMATION structure to find the number of ACEs in the DACL.
    bRtnBool = GetAclInformation(pDacl,                 // Pointer to an ACL
                                 &aclsizeinfo,          // Pointer to a buffer to receive the requested information
                                 sizeof(aclsizeinfo),   // The size, in bytes, of the buffer
                                 AclSizeInformation);   // Fill the buffer with an ACL_SIZE_INFORMATION structure

    if (bRtnBool == FALSE) {
        dwErrorCode = GetLastError();
        mdebug2("GetAclInformation failed. GetLastError returned: %ld", dwErrorCode);

        cJSON_Delete(acl_json);
        return dwErrorCode;
    }

    // Loop through the ACEs to get the information.
    for (cAce = 0; cAce < aclsizeinfo.AceCount; cAce++) {
        // Get ACE info
        if (GetAce(pDacl, cAce, (LPVOID*)&pAce) == FALSE) {
            mdebug2("GetAce failed. GetLastError returned: %ld", GetLastError());
            continue;
        }
        if (process_ace_info(pAce, acl_json)) {
            mdebug1("ACE number %lu could not be processed.", cAce);
        }
    }

    *output_acl = acl_json;

    return 0;
}


int w_get_file_permissions(const char *file_path, cJSON **output_acl) {
    int retval = 0;
    SECURITY_DESCRIPTOR *s_desc = NULL;
    unsigned long size = 0;

    if (!utf8_GetFileSecurity(file_path, DACL_SECURITY_INFORMATION, 0, 0, &size)) {
        retval = GetLastError();

        // We must have this error at this point
        if (retval != ERROR_INSUFFICIENT_BUFFER) {
            goto end;
        }
    }

    os_calloc(size, 1, s_desc);

    if (!utf8_GetFileSecurity(file_path, DACL_SECURITY_INFORMATION, s_desc, size, &size)) {
        retval = GetLastError();
        goto end;
    }

    retval = get_win_permissions(s_desc, output_acl);

    if (retval != 0) {
        goto end;
    }

end:
    free(s_desc);
    return retval;
}

int w_get_account_info(SID *sid, char **account_name, char **account_domain) {
    SID_NAME_USE snu;

    BOOL result = utf8_LookupAccountSid(NULL, sid, account_name, NULL, account_domain, NULL, &snu);

    if (!result) {
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

    if (attrs = utf8_GetFileAttributes(file_path), attrs == INVALID_FILE_ATTRIBUTES) {
        attrs = 0;
        mdebug2("The attributes for '%s' could not be obtained. Error '%ld'.", file_path, GetLastError());
    }

    return attrs;
}

char *get_group(__attribute__((unused)) int gid) {
    char *result;

    os_strdup("", result);
    return result;
}

char *get_registry_group(char **sid, HANDLE hndl) {
    DWORD dwRtnCode = 0;
    PSID pSidGroup = NULL;
    BOOL bRtnBool = TRUE;
    char GrpName[BUFFER_LEN];
    char DomainName[BUFFER_LEN];
    DWORD dwGrpName = BUFFER_LEN;
    DWORD dwDomainName = BUFFER_LEN;
    SID_NAME_USE eUse = SidTypeUnknown;
    PSECURITY_DESCRIPTOR pSD = NULL;
    char *result;
    LPSTR local_sid;

    // Get the group SID of the file or registry
    dwRtnCode = GetSecurityInfo(hndl,                       // Object handle
                                SE_REGISTRY_KEY,            // Object type (file or registry)
                                GROUP_SECURITY_INFORMATION, // Security information bit flags
                                NULL,                       // Owner SID
                                &pSidGroup,                 // Group SID
                                NULL,                       // DACL
                                NULL,                       // SACL
                                &pSD);                      // Security descriptor

    if (!ConvertSidToStringSid(pSidGroup, &local_sid)) {
        os_strdup("", *sid);
        mdebug1("The user's SID could not be extracted.");
    } else {
        os_strdup(local_sid, *sid);
        LocalFree(local_sid);
    }

    if (dwRtnCode != ERROR_SUCCESS) {
        mdebug1("GetSecurityInfo error code = (%lu), '%s'", dwRtnCode, win_strerror(dwRtnCode));
        *GrpName = '\0';
        goto end;
    }

    char *utf8_name = NULL;
    char *utf8_domain = NULL;
    bRtnBool = utf8_LookupAccountSid(NULL,              // Name of local or remote computer
                                     pSidGroup,         // Security identifier
                                     &utf8_name,        // Group name buffer
                                     NULL,              // Size of group name buffer
                                     &utf8_domain,      // Domain name
                                     NULL,              // Size of domain name buffer
                                     &eUse);            // SID type

    if (bRtnBool && utf8_name) {
        snprintf(GrpName, BUFFER_LEN, "%s", utf8_name);
        snprintf(DomainName, BUFFER_LEN, "%s", utf8_domain);
    }

    os_free(utf8_name);
    os_free(utf8_domain);

    if (strncmp(GrpName, "None", 4) == 0) {
        *GrpName = '\0';
    }

    // Check GetLastError for LookupAccountSidW error condition.
    if (bRtnBool == FALSE) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        if (dwErrorCode == ERROR_NONE_MAPPED) {
            mdebug1("Group not found for registry key");
        }
        else {
            LPSTR messageBuffer = NULL;
            LPSTR end;

            FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                          NULL, dwErrorCode, 0, (LPTSTR) &messageBuffer, 0, NULL);
            if (end = strchr(messageBuffer, '\r'), end) {
                *end = '\0';
            }

            mwarn(FIM_REGISTRY_ACC_SID, "group", dwErrorCode, messageBuffer);
            LocalFree(messageBuffer);
        }

        *GrpName = '\0';
    }

end:
    if (pSD) {
        LocalFree(pSD);
    }

    result = wstr_replace(GrpName, " ", "\\ ");

    return result;
}

DWORD get_registry_permissions(HKEY hndl, cJSON **output_acl) {
    PSECURITY_DESCRIPTOR pSecurityDescriptor;
    DWORD dwRtnCode = 0;
    DWORD lpcbSecurityDescriptor = 0;

    dwRtnCode = RegGetKeySecurity(hndl, DACL_SECURITY_INFORMATION, NULL, &lpcbSecurityDescriptor);

    if (dwRtnCode != ERROR_INSUFFICIENT_BUFFER) {
        return dwRtnCode;
    }

    os_calloc(lpcbSecurityDescriptor, 1, pSecurityDescriptor);

    // Get the security information.
    dwRtnCode = RegGetKeySecurity(hndl,                         // Handle to an open key
                                  DACL_SECURITY_INFORMATION,    // Request DACL security information
                                  pSecurityDescriptor,          // Pointer that receives the DACL information
                                  &lpcbSecurityDescriptor);     // Pointer that specifies the size, in bytes

    if (dwRtnCode != ERROR_SUCCESS) {
        os_free(pSecurityDescriptor);
        return dwRtnCode;
    }

    dwRtnCode = get_win_permissions(pSecurityDescriptor, output_acl);

    if (dwRtnCode != 0) {
        os_free(pSecurityDescriptor);
        return dwRtnCode;
    }

    os_free(pSecurityDescriptor);

    return ERROR_SUCCESS;
}

unsigned int get_registry_mtime(HKEY hndl) {
    FILETIME lpftLastWriteTime;
    DWORD dwRtnCode = 0;

    dwRtnCode = RegQueryInfoKeyA(hndl, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &lpftLastWriteTime);

    if (dwRtnCode != ERROR_SUCCESS) {
        mwarn("Couldn't get modification time for registry key.");
        return 0;
    }

    return get_windows_file_time_epoch(lpftLastWriteTime);
}

/* Send a one-way message to Syscheck */
void ag_send_syscheck(char * message, size_t length) {
    char * response = NULL;
    syscom_dispatch(message, length, &response);
    os_free(response);
}

HKEY w_switch_root_key(char* str_rootkey) {
    if (!strcmp(str_rootkey, STR_HKEY_CLASSES_ROOT)) {
        return HKEY_CLASSES_ROOT;
    }
    else if (!strcmp(str_rootkey, STR_HKEY_CURRENT_CONFIG)) {
        return HKEY_CURRENT_CONFIG;
    }
    else if (!strcmp(str_rootkey, STR_HKEY_CURRENT_USER)) {
        return HKEY_CURRENT_USER;
    }
    else if (!strcmp(str_rootkey, STR_HKEY_LOCAL_MACHINE)) {
        return HKEY_LOCAL_MACHINE;
    }
    else if (!strcmp(str_rootkey, STR_HKEY_USERS)) {
        return HKEY_USERS;
    }
    else {
        mdebug1("Invalid value of root Handle to Registry Key.");
        return NULL;
    }
}

void expand_wildcard_registers(char* entry, char** paths) {
    reg_path_struct** aux_vector;
    reg_path_struct** current_position;
    os_calloc(OS_SIZE_8192, sizeof(reg_path_struct*), aux_vector);

    reg_path_struct* first_e;
    os_calloc(1, sizeof(reg_path_struct), first_e);

    first_e->path           = strdup(entry);
    first_e->has_wildcard   = check_wildcard(entry);
    first_e->checked        = 0;
    *aux_vector             = first_e;
    current_position        = aux_vector; //Save the current pointer for future iteration

    // ----- Begin expansion path section -----
    // New algorithm form proposal

    while (w_is_still_a_wildcard(current_position)) {
        char* pos_qk = strchr((*current_position)->path, '?');
        char* pos_sr = strchr((*current_position)->path, '*');
        if (pos_qk != NULL && pos_sr != NULL) {
            if (pos_qk < pos_sr) {
                w_expand_by_wildcard(current_position, '?');
            } else {
                w_expand_by_wildcard(current_position, '*');
            }
        } else if (pos_sr != NULL) {
            w_expand_by_wildcard(current_position, '*');
        } else if (pos_qk != NULL) {
            w_expand_by_wildcard(current_position, '?');
        }
        current_position++;
    }

    // ----- End expansion path section -----

    current_position = aux_vector;
    while (*current_position != NULL) {
        if (!(*current_position)->has_wildcard && (*current_position)->checked) {
            os_strdup((*current_position)->path, *paths);
            os_free((*current_position)->path);
            os_free(*current_position);
            paths++;
        } else {
            os_free((*current_position)->path);
            os_free(*current_position);
        }
        current_position++;
    }

    //Release memory before leaves function
    os_free(*current_position);
    os_free(aux_vector);
}

char* get_subkey(char* key) {
    char* remaining_key = NULL;
    char* subkey        = NULL;

    os_strdup(strchr(key, '\\') + 1, remaining_key);
    os_calloc(OS_SIZE_128, sizeof(char), subkey);

    char* aux_token;

    aux_token = strtok(remaining_key, "\\");
    while (aux_token !=NULL && !(strchr(aux_token, '?') || strchr(aux_token, '*'))) {
        strcat(subkey, aux_token);
        aux_token = strtok(NULL, "\\");
        strcat(subkey, "\\");
    }
    int path_len = strlen(subkey) - 1;
    os_free(remaining_key);
    if (path_len > 0) {
        if (subkey[path_len] == '\\') {
            subkey[path_len] = '\0';
        }
        return subkey;
    } else {
        os_free(subkey);
        return strdup("");
    }
}

int w_is_still_a_wildcard(reg_path_struct **array_struct) {
    while (*array_struct) {
        if ((*array_struct)->has_wildcard && !(*array_struct)->checked) {
            return 1;
        }
        array_struct++;
    }
    return 0;
}

char** w_list_all_keys(HKEY root_key, char* str_subkey) {
    HKEY keyhandle;
    char** key_list = NULL;
    if (RegOpenKeyEx(root_key, str_subkey, 0, KEY_READ | KEY_WOW64_64KEY, &keyhandle) == ERROR_SUCCESS) {
        TCHAR    achKey[OS_SIZE_256];
        DWORD    cbName;
        TCHAR    achClass[OS_SIZE_256] = TEXT("");
        DWORD    cchClassName = OS_SIZE_256;
        DWORD    cSubKeys = 0;
        DWORD    cbMaxSubKey;
        DWORD    cchMaxClass;
        DWORD    cValues;
        DWORD    cchMaxValue;
        DWORD    cbMaxValueData;
        DWORD    cbSecurityDescriptor;
        FILETIME ftLastWriteTime;

        DWORD i, retCode;

        // Get the class name and the value count.
        retCode = RegQueryInfoKey(
            keyhandle,               // key handle
            achClass,                // buffer for class name
            &cchClassName,           // size of class string
            NULL,                    // reserved
            &cSubKeys,               // number of subkeys
            &cbMaxSubKey,            // longest subkey size
            &cchMaxClass,            // longest class string
            &cValues,                // number of values for this key
            &cchMaxValue,            // longest value name
            &cbMaxValueData,         // longest value data
            &cbSecurityDescriptor,   // security descriptor
            &ftLastWriteTime);       // last write time

        if (retCode == ERROR_SUCCESS) {
            if (cSubKeys) {
            os_calloc(cSubKeys + 1, sizeof(char*), key_list);
            for (i = 0; i < cSubKeys; i++) {
                cbName = OS_SIZE_256;
                retCode = RegEnumKeyEx(keyhandle, i,
                    achKey,
                    &cbName,
                    NULL,
                    NULL,
                    NULL,
                    &ftLastWriteTime);
                if (retCode == ERROR_SUCCESS) {
                    os_strdup(achKey, *(key_list + i));
                    }
                }
                *(key_list + i) = NULL;
            }
        }
    }
    RegCloseKey(keyhandle);
    return key_list;
}

void w_expand_by_wildcard(reg_path_struct **array_struct, char wildcard_chr) {
    // ----- Begin setup variables section -----
    char* wildcard_str          = NULL;
    os_calloc(2, sizeof(char), wildcard_str);
    wildcard_str[0]             = wildcard_chr;
    wildcard_str[1]             = '\0';

    char** first_position       = NULL;

    char* matcher               = NULL; //Only used when wildcard is ?.

    //Create a copy of the path to be able to modify it.
    char* aux_path              = NULL;
    os_strdup((*array_struct)->path, aux_path);

    //Take the first part of the wildcard, splitting by wildcard. Clean any chars after a slash bar.
    char* first_part            = strtok(aux_path, wildcard_str);
    for (int letter = strlen(first_part) - 1; letter >= 0; letter--) {
        if (first_part[letter] != '\\') {
            first_part[letter] = '\0';
        }
        else {
            break;
        }
    }

    if (wildcard_chr == '?') {
        //Usar strtok_r
        char* temp          = NULL;
        char* aux_matcher   = NULL;
        os_strdup((*array_struct)->path, temp);

        //Search through all tokens until you find the one that has the wildcard
        aux_matcher = strtok(temp, "\\");
        while (!strchr(aux_matcher, '?')) {
            aux_matcher = strtok(NULL, "\\");
        }
        os_strdup(aux_matcher,matcher);
        os_free(temp);
    }

    //Take the remainder part of the path.
    char* second_part       = NULL;
    if ((*array_struct)->path != NULL) {
        second_part         = strchr(strchr((*array_struct)->path, wildcard_chr), '\\');
    }

    //Duplicate key part
    char* temp = NULL;
    os_strdup(first_part,temp);

    char* str_root_key          = NULL;
    //Obtain the subkey. If it's empty, it's a NULL value.
    char* subkey                = get_subkey((*array_struct)->path);

    os_strdup(strtok(temp, "\\"), str_root_key);
    os_free(temp);

    HKEY root_key               = w_switch_root_key(str_root_key);

    // ----- End setup variables section -----

    (*array_struct)->checked    = 1; //Mark path as checked.

    //Get first empty position of the vector.
    int first_empty             = 0;
    while (array_struct[first_empty] != NULL) {
        first_empty++;
    }
    //----------------------------------------

    //There is two possibles branches to take depending of the wildcard.
    if (wildcard_chr=='?') {
        if (root_key != NULL && matcher != NULL) {
            //Get all keys from Windows API.
            char** query_keys = w_list_all_keys(root_key, subkey);
            first_position = query_keys;
            if (query_keys) {
                //Itarate over string vector.
                while (*query_keys != NULL) {
                    //Use Windows API and check wildcar coincidences.
                    if (PathMatchSpecA(*query_keys, matcher)) {
                        // ----- Begin final path variable section -----

                        char* full_path = NULL;
                        os_calloc(OS_SIZE_256, sizeof(char), full_path);

                        //Copy first part.
                        strcpy(full_path, first_part);

                        //Add key result.
                        strcat(full_path, *query_keys);

                        //Copy second part.
                        second_part != NULL ? strcat(full_path, second_part) : strcat(full_path,"\0");

                        // ----- End final path variable section -----

                        //Create new struct and add it to vector.
                        reg_path_struct* new_struct = NULL;
                        os_calloc(1, sizeof(reg_path_struct), new_struct);

                        int path_length             = strlen(full_path);
                        if(full_path[path_length - 1] == '\\'){
                            full_path[path_length - 1] = '\0';
                        }

                        new_struct->path            = full_path;
                        new_struct->has_wildcard    = (check_wildcard(full_path)) && !(check_wildcard(*query_keys)) ? 1 : 0;
                        new_struct->checked         = 1 & !new_struct->has_wildcard;
                        array_struct[first_empty]   = new_struct;

                        //Increment pointers.
                        first_empty++;
                    }
                    //Increment pointers.
                    query_keys++;
                    }
                }
            //Release memory before leaves function.
            os_free(matcher);
        }
    } else {
        if (root_key != NULL) {
            //Get all keys from Windows API.
            char** query_keys = w_list_all_keys(root_key, subkey);
            first_position    = query_keys;
            if (query_keys) {
                //Itarate over string vector.
                while (*query_keys != NULL) {

                    // ----- Begin final path variable section -----

                    char* full_path = NULL;
                    os_calloc(OS_SIZE_256, sizeof(char), full_path);

                    //Copy first part.
                    strcpy(full_path, first_part);

                    //Add key result.
                    strcat(full_path, *query_keys);

                    //Copy second part.
                    second_part != NULL ? strcat(full_path, second_part) : strcat(full_path, "\0");

                    // ----- End final path variable section -----

                    //Create new struct and add it to vector.
                    reg_path_struct* new_struct = NULL;
                    os_calloc(1, sizeof(reg_path_struct), new_struct);

                    int path_length             = strlen(full_path);
                    if(full_path[path_length - 1] == '\\') {
                        full_path[path_length - 1] = '\0';
                    }

                    new_struct->path            = full_path;
                    new_struct->has_wildcard    = (check_wildcard(full_path)) && !(check_wildcard(*query_keys)) ? 1 : 0;
                    new_struct->checked         = 1 & !new_struct->has_wildcard;
                    array_struct[first_empty]   = new_struct;

                    //Increment pointers.
                    first_empty++;
                    query_keys++;
                }
            }
        }
    }

    //Release memory after leaves function. Common variables
    os_free(wildcard_str);
    os_free(aux_path);
    os_free(str_root_key);
    os_free(subkey);
    free_strarray(first_position);
    os_free(matcher);
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

void make_mask_readable (cJSON *ace_json, int mask, char *ace_type) {
    int i;
    int perm_bits[] = {
        GENERIC_READ,
        GENERIC_WRITE,
        GENERIC_EXECUTE,
        GENERIC_ALL,
        DELETE,
        READ_CONTROL,
        WRITE_DAC,
        WRITE_OWNER,
        SYNCHRONIZE,
        FILE_READ_DATA,
        FILE_WRITE_DATA,
        FILE_APPEND_DATA,
        FILE_READ_EA,
        FILE_WRITE_EA,
        FILE_EXECUTE,
        FILE_READ_ATTRIBUTES,
        FILE_WRITE_ATTRIBUTES,
        0
    };

    static const char * const perm_strings[] = {
        "generic_read",
        "generic_write",
        "generic_execute",
        "generic_all",
        "delete",
        "read_control",
        "write_dac",
        "write_owner",
        "synchronize",
        "read_data",
        "write_data",
        "append_data",
        "read_ea",
        "write_ea",
        "execute",
        "read_attributes",
        "write_attributes",
        NULL
    };

    cJSON *perm_array = cJSON_CreateArray();
    if (perm_array == NULL) {
        mwarn(FIM_CJSON_ERROR_CREATE_ITEM);
        return;
    }

    for (i = 0; perm_bits[i]; i++) {
        if (mask & perm_bits[i]) {
            cJSON_AddItemToArray(perm_array, cJSON_CreateString(perm_strings[i]));
        }
    }

    cJSON_ReplaceItemInObject(ace_json, ace_type, perm_array);
}

void decode_win_acl_json (cJSON *acl_json) {
    cJSON *json_object = NULL;
    cJSON *allowed_item = NULL;
    cJSON *denied_item = NULL;

    assert(acl_json != NULL);

    cJSON_ArrayForEach(json_object, acl_json) {
        allowed_item = cJSON_GetObjectItem(json_object, "allowed");
        if (allowed_item) {
            make_mask_readable(json_object, allowed_item->valueint, "allowed");
        }
        denied_item = cJSON_GetObjectItem(json_object, "denied");
        if (denied_item) {
            make_mask_readable(json_object, denied_item->valueint, "denied");
        }
    }
}
