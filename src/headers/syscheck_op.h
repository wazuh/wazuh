/*
 * Shared functions for Syscheck events decoding
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __SYSCHECK_OP_H
#define __SYSCHECK_OP_H

#include "analysisd/eventinfo.h"

#ifndef WIN32

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#define PATH_SEP '/'

// ATTRS
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
#define FILE_ATTRIBUTE_INTEGRITY_STREAM         0x00008000
#define FILE_ATTRIBUTE_VIRTUAL                  0x00010000
#define FILE_ATTRIBUTE_NO_SCRUB_DATA            0x00020000
#define FILE_ATTRIBUTE_RECALL_ON_OPEN           0x00040000
#define FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS    0x00400000

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

#define BUFFER_LEN 1024
#define PATH_SEP '\\'

#endif

// Number of attributes in checksum
#define FIM_NATTR 11
// Number of options in checksum hash table
#define FIM_NOPTS 10

/* Fields for rules */
typedef enum sk_syscheck {
    SK_FILE,
    SK_SIZE,
    SK_PERM,
    SK_UID,
    SK_GID,
    SK_MD5,
    SK_SHA1,
    SK_UNAME,
    SK_GNAME,
    SK_INODE,
    SK_SHA256,
    SK_ATTRS,
    SK_MTIME,
    SK_CHFIELDS,
    SK_USER_ID,
    SK_USER_NAME,
    SK_GROUP_ID,
    SK_GROUP_NAME,
    SK_PROC_NAME,
    SK_AUDIT_ID,
    SK_AUDIT_NAME,
    SK_EFFECTIVE_UID,
    SK_EFFECTIVE_NAME,
    SK_PPID,
    SK_PROC_ID,
    SK_TAG,
    SK_NFIELDS
} sk_syscheck;

typedef struct __sdb {
    char comment[OS_MAXSTR + 1];
    char size[OS_FLSIZE + 1];
    char perm[OS_SIZE_20480 + 1];
    char owner[OS_FLSIZE + 1];
    char gowner[OS_FLSIZE + 1];
    char md5[OS_FLSIZE + 1];
    char sha1[OS_FLSIZE + 1];
    char sha256[OS_FLSIZE + 1];
    char mtime[OS_FLSIZE + 1];
    char inode[OS_FLSIZE + 1];
    char attrs[OS_SIZE_1024 + 1];

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
    char *audit_uid;
    char *audit_name;
    char *effective_uid;
    char *effective_name;
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
    unsigned int attrs;
    char *uname;
    char *gname;
    long mtime;
    long inode;
    char *tag;
    sk_sum_wdata wdata;
    int changes;
    long date_alert;
} sk_sum_t;

/* Parse c_sum string. Returns 0 if success, 1 when c_sum denotes a deleted file
   or -1 on failure. */
int sk_decode_sum(sk_sum_t *sum, char *c_sum, char *w_sum);

// Parse fields changes and date_alert only provide for wazuh_db
int sk_decode_extradata(sk_sum_t *sum, char *c_sum);

void sk_fill_event(Eventinfo *lf, const char *f_name, const sk_sum_t *sum);

int sk_build_sum(const sk_sum_t * sum, char * output, size_t size);

/* Delete from path to parent all empty folders */
int remove_empty_folders(const char *path);

/* Delete path file and all empty folders above */
int delete_target_file(const char *path);

void sk_sum_clean(sk_sum_t * sum);

int fim_find_child_depth(const char *parent, const char *child);

//Change in Windows paths all slashes for backslashes for compatibility agent<3.4 with manager>=3.4
void normalize_path(char *path);

//Return an attr from checksum
char *get_attr_from_checksum(char *checksum, int attr);

#ifndef WIN32

const char *get_user(__attribute__((unused)) const char *path, int uid, __attribute__((unused)) char **sid);
const char *get_group(int gid);
void decode_win_attributes(char *str, unsigned int attrs);
int decode_win_permissions(char *str, int str_size, char *raw_perm, char seq, cJSON *perm_array);
cJSON *attrs_to_json(unsigned int attributes);
cJSON *perm_to_json(char *permissions);

#else

char *get_user(const char *path, __attribute__((unused)) int uid, char **sid);
unsigned int w_get_file_attrs(const char *file_path);
int w_get_file_permissions(const char *file_path, char *permissions, int perm_size);
const char *get_group(__attribute__((unused)) int gid);
char *escape_perm_sum(char *sum);


#endif

#endif
