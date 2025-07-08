/*
 * Shared functions for Syscheck events decoding
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef SYSCHECK_OP_H
#define SYSCHECK_OP_H

#ifndef WIN32

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

// Windows file attributes
#define FILE_ATTRIBUTE_READONLY                 0x00000001
#define FILE_ATTRIBUTE_HIDDEN                   0x00000002
#define FILE_ATTRIBUTE_SYSTEM                   0x00000004
#define FILE_ATTRIBUTE_DIRECTORY                0x00000010
#define FILE_ATTRIBUTE_ARCHIVE                  0x00000020
#define FILE_ATTRIBUTE_DEVICE                   0x00000040
#define FILE_ATTRIBUTE_NORMAL                   0x00000080
#define FILE_ATTRIBUTE_TEMPORARY                0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE              0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT            0x00000400
#define FILE_ATTRIBUTE_COMPRESSED               0x00000800
#define FILE_ATTRIBUTE_OFFLINE                  0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED      0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED                0x00004000
#define FILE_ATTRIBUTE_VIRTUAL                  0x00010000

// Permissions
// Generic rights
#define GENERIC_READ                            0x80000000
#define GENERIC_WRITE                           0x40000000
#define GENERIC_EXECUTE                         0x20000000
#define GENERIC_ALL                             0x10000000
// Standard rights
#define DELETE                                  0x00010000
#define READ_CONTROL                            0x00020000
#define WRITE_DAC                               0x00040000
#define WRITE_OWNER                             0x00080000
#define SYNCHRONIZE                             0x00100000

// Specific rights
#define FILE_READ_DATA                          0x00000001
#define FILE_WRITE_DATA                         0x00000002
#define FILE_APPEND_DATA                        0x00000004
#define FILE_READ_EA                            0x00000008
#define FILE_WRITE_EA                           0x00000010
#define FILE_EXECUTE                            0x00000020
#define FILE_READ_ATTRIBUTES                    0x00000080
#define FILE_WRITE_ATTRIBUTES                   0x00000100

#else

#include "shared.h"
#include "aclapi.h"
#include <sddl.h>
#include <winreg.h>

#define BUFFER_LEN 1024

//Windows registers
#define STR_HKEY_CLASSES_ROOT                   "HKEY_CLASSES_ROOT"
#define STR_HKEY_CURRENT_CONFIG                 "HKEY_CURRENT_CONFIG"
#define STR_HKEY_CURRENT_USER                   "HKEY_CURRENT_USER"
#define STR_HKEY_LOCAL_MACHINE                  "HKEY_LOCAL_MACHINE"
#define STR_HKEY_PERFORMANCE_DATA               "HKEY_PERFORMANCE_DATA"
#define STR_HKEY_USERS                          "HKEY_USERS"
#define check_wildcard(x)                       strchr(x,'*') || strchr(x,'?')

/* Fields for paths */
typedef struct _reg_path_struct {
    char* path;
    int has_wildcard;
    int checked;
} reg_path_struct;

#endif

#include "../syscheckd/include/syscheck.h"
#include "../os_net/os_net.h"

#define FILE_ATTRIBUTE_INTEGRITY_STREAM         0x00008000
#define FILE_ATTRIBUTE_NO_SCRUB_DATA            0x00020000
#define FILE_ATTRIBUTE_RECALL_ON_OPEN           0x00040000
#define FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS    0x00400000

#define MAX_WIN_PERM_SIZE OS_SIZE_20480

/* Fields for rules */
typedef enum fim_fields {
    FIM_FILE,
    FIM_HARD_LINKS,
    FIM_MODE,
    FIM_SIZE,
    FIM_SIZE_BEFORE,
    FIM_PERM,
    FIM_PERM_BEFORE,
    FIM_UID,
    FIM_UID_BEFORE,
    FIM_GID,
    FIM_GID_BEFORE,
    FIM_MD5,
    FIM_MD5_BEFORE,
    FIM_SHA1,
    FIM_SHA1_BEFORE,
    FIM_UNAME,
    FIM_UNAME_BEFORE,
    FIM_GNAME,
    FIM_GNAME_BEFORE,
    FIM_MTIME,
    FIM_MTIME_BEFORE,
    FIM_INODE,
    FIM_INODE_BEFORE,
    FIM_SHA256,
    FIM_SHA256_BEFORE,
    FIM_DIFF,
    FIM_ATTRS,
    FIM_ATTRS_BEFORE,
    FIM_CHFIELDS,
    FIM_USER_ID,
    FIM_USER_NAME,
    FIM_GROUP_ID,
    FIM_GROUP_NAME,
    FIM_PROC_NAME,
    FIM_PROC_PNAME,
    FIM_AUDIT_CWD,
    FIM_AUDIT_PCWD,
    FIM_AUDIT_ID,
    FIM_AUDIT_NAME,
    FIM_EFFECTIVE_UID,
    FIM_EFFECTIVE_NAME,
    FIM_PPID,
    FIM_PROC_ID,
    FIM_TAG,
    FIM_SYM_PATH,
    FIM_REGISTRY_ARCH,
    FIM_REGISTRY_VALUE_NAME,
    FIM_REGISTRY_VALUE_TYPE,
    FIM_REGISTRY_HASH,
    FIM_ENTRY_TYPE,
    FIM_EVENT_TYPE,
    FIM_NFIELDS
} fim_fields;

typedef struct __sdb {
    char comment[OS_MAXSTR + 1];
    char size[OS_FLSIZE + 1];
    char perm[OS_FLSIZE + 1];
    char owner[OS_FLSIZE + 1];
    char gowner[OS_FLSIZE + 1];
    char md5[OS_FLSIZE + 1];
    char sha1[OS_FLSIZE + 1];
    char sha256[OS_FLSIZE + 1];
    char mtime[OS_FLSIZE + 1];
    char inode[OS_FLSIZE + 1];
    char attrs[OS_SIZE_1024 + 1];
    char sym_path[OS_FLSIZE + 1];

    // Whodata fields
    char user_id[OS_FLSIZE + 1];
    char user_name[OS_FLSIZE + 1];
    char group_id[OS_FLSIZE + 1];
    char group_name[OS_FLSIZE + 1];
    char process_name[OS_FLSIZE + 1];
    char audit_uid[OS_FLSIZE + 1];
    char audit_name[OS_FLSIZE + 1];
    char effective_uid[OS_FLSIZE + 1];
    char effective_name[OS_FLSIZE + 1];
    char ppid[OS_FLSIZE + 1];
    char process_id[OS_FLSIZE + 1];

    int db_err;
    int socket;
} _sdb; /* syscheck db information */

typedef struct sk_sum_wdata {
    char *user_id;
    char *user_name;
    char *group_id;
    char *group_name;
    char *process_name;
    char *cwd;
    char *audit_uid;
    char *audit_name;
    char *effective_uid;
    char *effective_name;
    char *parent_name;
    char *parent_cwd;
    char *ppid;
    char *process_id;
} sk_sum_wdata;

/* File sum structure */
typedef struct sk_sum_t {
    char *size;
    int perm;
    char *win_perm;
    char *uid;
    char *gid;
    char *md5;
    char *sha1;
    char *sha256;
    char *attributes;
    char *uname;
    char *gname;
    long mtime;
    long inode;
    char *tag;
    char *symbolic_path;
    sk_sum_wdata wdata;
    int changes;
    char silent;
    long date_alert;
} sk_sum_t;

/**
 * @brief Parse c_sum string
 *
 * @param [out] sum
 * @param [in] c_sum
 * @param [in] w_sum
 * @return 0 if success, 1 when c_sum denotes a deleted file, -1 on failure
 */
int sk_decode_sum(sk_sum_t *sum, char *c_sum, char *w_sum);

/**
 * @brief Parse fields changes and date_alert only provide for wazuh_db
 *
 * @param [out] sum
 * @param [in] c_sum
 * @return 0 if success, -1 on failure
 */
int sk_decode_extradata(sk_sum_t *sum, char *c_sum);

/**
 * @brief Fill an event with specific data
 *
 * @param [out] lf Event to be filled
 * @param [in] f_name File name for the event
 * @param [in] sum File sum used to fill the event
 */
/*****************************************************************************************
 TODO-LEGACY-ANALYSISD-FIM: Delete this function when the new system is ready
 Should not depend on analsysid code
void sk_fill_event(Eventinfo *lf, const char *f_name, const sk_sum_t *sum);
 ****************************************************************************************/

/**
 * @brief Fills a buffer with a specific file sum
 *
 * @param [in] sum File sum used to fill the buffer
 * @param [out] output The output buffer to be written
 * @param [in] size Size in bytes to be written into output
 * @return 0 on success, -1 on failure
 */
int sk_build_sum(const sk_sum_t *sum, char *output, size_t size);

/**
 * @brief Delete from path to parent all empty folders
 *
 * @param path The path from which to delete
 * @return 0 on success, -1 on failure
 */
int remove_empty_folders(const char *path);

/**
 * @brief Frees from memory a sk_sum_t structure
 *
 * @param [out] sum The sk_sum_t object to be freed
 */
void sk_sum_clean(sk_sum_t *sum);

/**
 * @brief Change in Windows paths all slashes for backslashes for compatibility
 *
 * @param [out] path The path of the file to be normalized
 */
void normalize_path(char *path);

/**
 * @brief Escape characteres '!', ':', ' ' from incomming string
 *
 * @param field Syscheck checksum string
 * @return A string with escaped characters
 */
char *escape_syscheck_field(char *field);
#ifndef CLIENT
char *unescape_syscheck_field(char *sum);
#endif

#ifndef WIN32

/**
 * @brief Retrieves the user name from a user ID in UNIX
 *
 * @param uid The user ID
 * @return The user name on success, NULL on failure
 */
char *get_user(int uid);

/**
 * @brief Retrieves the group name from a group ID in UNIX
 *
 * @param gid The group ID
 * @return The group name on success, an empty string on failure
 */
char *get_group(int gid);


#else

/**
 * @brief Retrieves the user name of the owner of a registry in Windows.
 * Also sets the ID associated to that user.
 *
 * @post *sid is always allocated and must be freed after usage.
 *
 * @param path Registry path to check the owner of.
 * @param sid The user ID associated to the user.
 * @param hndl Handle for the registry to check the owner of.
 *
 * @return The user name on success, an empty string on failure.
 */
char *get_registry_user(const char *path, char **sid, HANDLE hndl);

/**
 * @brief Retrieves the user name of the owner of a file in Windows.
 * Also sets the ID associated to that user.
 *
 * @post *sid is always allocated and must be freed after usage.
 *
 * @param path File path to check the owner of.
 * @param sid The user ID associated to the user.
 *
 * @return The user name on success, an empty string on failure.
 */
char *get_file_user(const char *path, char **sid);

/**
 * @brief Retrieves the user name of the owner of a file or registry in Windows.
 * Also sets the ID associated to that user.
 *
 * @post *sid is always allocated and must be freed after usage.
 *
 * @param path File or registry path to check the owner of.
 * @param sid The user ID associated to the user.
 * @param hndl Handle of the file or registry to check the owner of.
 * @param object_type Type of the object to check the owner of (SE_FILE_OBJECT or SE_REGISTRY_KEY).
 *
 * @return The user name on success, an empty string on failure.
 */
char *get_user(const char *path, char **sid, HANDLE hndl, SE_OBJECT_TYPE object_type);

/**
 * @brief Check if a directory exists
 *
 * @param path Path of the directory to check
 * @return The FILE_ATTRIBUTE_DIRECTORY bit mask on success, 0 on failure
 */
unsigned int w_directory_exists(const char *path);

/**
 * @brief Retrieves the attributes of a specific file (Windows)
 *
 * @param file_path The path of the file to check the attributes of
 * @return The bit mask of the file attributes on success, 0 on failure
 */
unsigned int w_get_file_attrs(const char *file_path);

/**
 * @brief Retrieves the permissions of a specific file (Windows)
 *
 * @param [in] file_path The path of the file from which to check permissions
 * @param [out] output_acl A cJSON pointer to an object holding the ACL of the file.
 * @retval 0 on success.
 * @retval -1 if the cJSON object could not be initialized.
 * @retval An error code retrieved from `GetLastError` otherwise.
 */
int w_get_file_permissions(const char *file_path, cJSON **output_acl);

/**
 * @brief Retrieves the group name from a group ID in windows
 *
 * @return The group name on success, an empty string on failure
 */
char *get_group(__attribute__((unused)) int gid);

/**
 * @brief Retrieves the group name and gid of a registry key.
 * Also sets the group ID associated to that group.
 *
 * @param sid The user ID associated to the group.
 * @param hndl Handle for the registry to check the group of.
 *
 * @return The user name on success, NULL on failure.
*/
char *get_registry_group(char **sid, HANDLE hndl);

/**
 * @brief Retrieves the permissions of a registry key.
 *
 * @param [in] hndl Handle for the registry key to check the permissions of.
 * @param [out] output_acl A cJSON pointer to an object holding the ACL of the file.
 * @retval 0 on success.
 * @retval -1 if the cJSON object could not be initialized.
 * @retval An error code retrieved from `GetLastError` otherwise.
*/
DWORD get_registry_permissions(HKEY hndl, cJSON **output_acl);

/**
 * @brief Get last modification time from registry key.
 *
 * @param hndl Handle for the registry key to check the permissions of.
 *
 * @return Last modification time of registry key in POSIX format.
*/
unsigned int get_registry_mtime(HKEY hndl);

/**
 * @brief Retrieves the account information (name and domain) from SID
 *
 * @param [in] sid SID from which retrieve the information
 * @param [out] account_name Buffer in which the account name is written
 * @param [out] account_domain Buffer in which the account domain is written
 * @return 0 on success, error code on failure
 */
int w_get_account_info(SID *sid, char **account_name, char **account_domain);

/**
 * @brief Checks if at least one structure exists whose path has a wildcard  (Windows)
 *
 * @param [in] array_struct Arrangement of structures.
 * @retval 1 on success.
 * @retval 0 if there is not more wildcards.
 */
int w_is_still_a_wildcard(reg_path_struct **array_struct);

/**
 * @brief Returns the HKEY corresponding to the root key name  (Windows)
 *
 * @param [in] str_rootkey String that represents the root key.
 * @retval HKEY on success.
 * @retval NULL if there is not match.
 */
HKEY w_switch_root_key(char* str_rootkey);

/**
 * @brief Return all keys based on a root key and subkey  (Windows)
 *
 * @param [in] root_key HKEY that represents the root key.
 * @param [in] str_subkey String that represents the main subkey, this could be NULL.
 * @retval A non empty array of string on success.
 */
char** w_list_all_keys(HKEY root_key, char* str_subkey);

/**
 * @brief Generate all valid paths that contains a * or ? (Windows)
 *
 * @param [in] array_struct Array of all possible paths.
 * @param [out] array_struct Array of paths with tag checked in 1 and has_wildcard in 0.
 */
void w_expand_by_wildcard(reg_path_struct **array_struct, char wildcard_chr);


/**
 * @brief Extract the subkey from path (Windows)
 *
 * @param [in] key String path that contains the key and subkey.
 * @return Allocated subkey or NULL if there is not one.
 */
char* get_subkey(char* key);

/**
 * @brief Return all possible paths based in a entry  (Windows)
 *
 * @param [in] entry Raw entry read from config file.
 * @param [out] paths Array of paths expanded with tag checked in 1 and has_wildcard in 0.
 */
void expand_wildcard_registers(char* entry, char** paths);

#endif

/**
 * @brief Converts a bit mask into a human readable format
 *
 * @param [out] str Buffer to be written
 * @param [in] attrs Bit mask to be converted
 */
void decode_win_attributes(char *str, unsigned int attrs);

/**
 * @brief Decodes a permission string and converts it to a human readable format
 *
 * @param [in] raw_perm A raw string with the permissions
 * @return A string in human readable format with the Windows permission
 */
char *decode_win_permissions(char *raw_perm);

/**
 * @brief Compares 2 Windows ACLs in JSON format
 *
 * @param [in] acl1 A cJSON object holding a Windows ACL
 * @param [in] acl2 A cJSON object holding a Windows ACL
 * @return `true` if ACLs are equal to each other, `false` otherwise
 */
bool compare_win_permissions(const cJSON * const acl1, const cJSON * const acl2);

/**
 * @brief Decodes a permission string and converts it to a human readable format
 *
 * @param [out] acl_json A cJSON with the permissions to decode
 */
void decode_win_acl_json(cJSON *acl_json);

/**
 * @brief Transforms a bit mask of attributes into a human readable cJSON
 *
 * @param attributes A string with the Windows attributes
 * @return A cJSON with the attributes
 */
cJSON *attrs_to_json(const char *attributes);

/**
 * @brief Transforms a string of permissions into a human readable cJSON
 *
 * @param permissions Permissions string
 * @return A cJSON with the permissions
 */
cJSON *win_perm_to_json(char *permissions);

/**
 * @brief Send a one-way message to Syscheck
 *
 * @param message Payload.
 */
void ag_send_syscheck(char * message);

#endif /* SYSCHECK_OP_H */
