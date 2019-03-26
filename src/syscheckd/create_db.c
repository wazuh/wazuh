/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#include "os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"
#include "syscheck_op.h"
#include "wazuh_modules/wmodules.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/sha256/sha256_op.h"
#include "syscheck.h"
#include "syscheck_op.h"

/* Prototypes */
static int read_file(const char *dir_name, int dir_position, whodata_evt *evt, int max_depth)  __attribute__((nonnull(1)));

static int read_dir_diff(char *dir_name);

pthread_mutex_t lastcheck_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Global variables */
static int __counter = 0;

static int read_dir_diff(char *dir_name) {
    size_t dir_size;
    char *f_name = NULL;
    char *file_name = NULL;
    char *local_dir = NULL;
    int retval = -1;

    os_calloc(PATH_MAX + 2, sizeof(char), f_name);
    os_calloc(PATH_MAX, sizeof(char), file_name);
    os_calloc(PATH_MAX, sizeof(char), local_dir);

    snprintf(local_dir, PATH_MAX - 1, "%s%clocal", DIFF_DIR_PATH, PATH_SEP);

    DIR *dp;
    struct dirent *entry;

    /* Directory should be valid */
    if ((dir_name == NULL) || ((dir_size = strlen(dir_name)) > PATH_MAX)) {
        merror(NULL_ERROR);
        goto end;
    }

    /* Open the directory given */
    dp = opendir(dir_name);
    if (!dp) {
        if (errno == ENOTDIR || (errno == ENOENT && !strcmp(dir_name, local_dir))) {
            retval = 0;
            goto end;
        } else {
            mwarn(FIM_WARN_ACCESS, dir_name, errno, strerror(errno));
            goto end;
        }
    }

    int ret_add;
    while ((entry = readdir(dp)) != NULL) {
        char *s_name;

        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) ||
            (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        strncpy(f_name, dir_name, PATH_MAX);
        s_name = f_name;
        s_name += dir_size;

        /* Check if the file name is already null terminated */
        if (*(s_name - 1) != PATH_SEP) {
            *s_name++ = PATH_SEP;
        }

        *s_name = '\0';
        strncpy(s_name, entry->d_name, PATH_MAX - dir_size - 2);

        if (strcmp(DIFF_GZ_FILE, s_name) == 0) {
            memset(file_name, 0, strlen(file_name));
            memmove(file_name, f_name, strlen(f_name) - strlen(s_name) - 1);
            if (ret_add = OSHash_Add(syscheck.local_hash, file_name, NULL), ret_add != 2) {
                merror(FIM_ERROR_ADD_FILE, file_name);
            }
        } else {
            read_dir_diff(f_name);
        }
    }

    closedir(dp);
    retval = 0;
end:
    free(f_name);
    free(file_name);
    free(local_dir);
    return retval;
}


void remove_local_diff(){

    /* Fill hash table with the content of DIFF_DIR_PATH/local */
    const char LOCALDIR[] = {PATH_SEP, 'l', 'o', 'c', 'a', 'l', '\0'};
    char *local_path = NULL;
    os_calloc(PATH_MAX, sizeof(char), local_path);

    strcpy(local_path, DIFF_DIR_PATH);
    strcat(local_path, LOCALDIR);

    read_dir_diff(local_path);

    unsigned int i = 0;

    /* Delete all monitored files from hash table */
    OSHashNode *curr_node_local, *internal_node;
    OSHashNode *curr_node_fp;

    char *full_path = NULL;
    os_calloc(OS_SIZE_8192, sizeof(char), full_path);

    for (i = 0; i <= syscheck.fp->rows; i++) {
        curr_node_fp = syscheck.fp->table[i];
        if (curr_node_fp && curr_node_fp->key) {
            do {
                *full_path='\0';
                wm_strcat(&full_path, local_path, '\0');
#ifdef WIN32
                char *windows_path;
                windows_path = strchr(curr_node_fp->key, ':');
                wm_strcat(&full_path, windows_path+1, '\0');
#else
                wm_strcat(&full_path, curr_node_fp->key, '\0');
#endif
                if (!OSHash_Get_ex(syscheck.local_hash, full_path)) {
                    mdebug2(FIM_LOCALDIFF_DELETE, full_path);
                    OSHash_Delete_ex(syscheck.local_hash, full_path);
                }
                curr_node_fp=curr_node_fp->next;
            } while(curr_node_fp && curr_node_fp->key);
        }
    }
    free(full_path);

    /* Delete local files that aren't monitored */
    for (i = 0; i <= syscheck.local_hash->rows; i++) {
        curr_node_local = syscheck.local_hash->table[i];
        if (curr_node_local && curr_node_local->key) {
            do{
                internal_node = curr_node_local->next;
                mdebug2(FIM_LOCAL_DIFF_DELETE, curr_node_local->key);
                if (rmdir_ex(curr_node_local->key) != 0) {
                    mwarn(FIM_WARN_DELETE, curr_node_local->key);
                }
                remove_empty_folders(curr_node_local->key);
                if (OSHash_Delete_ex(syscheck.local_hash, curr_node_local->key) != 0) {
                    mwarn(FIM_WARN_DELETE_HASH_TABLE, curr_node_local->key);
                }
                curr_node_local = internal_node;
            }
            while(curr_node_local && curr_node_local->key);
        }
    }

    free(local_path);
}

/* Read and generate the integrity data of a file */
static int read_file(const char *file_name, int dir_position, whodata_evt *evt, int max_depth)
{
    int opts;
    OSMatch *restriction;
    char *buf;
    syscheck_node *s_node;
    struct stat statbuf;
    char str_size[50], str_mtime[50], str_inode[50];
    char *wd_sum = NULL;
    char *alert_msg = NULL;
    char *c_sum = NULL;
    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wd_sum);
#ifdef WIN32
    char *sid = NULL;
    char *user = NULL;
    char *str_perm = NULL;
#else
    char str_owner[50], str_group[50], str_perm[50];
    char *hash_file_name;
#endif


    opts = syscheck.opts[dir_position];
    restriction = syscheck.filerestrict[dir_position];

    if (fim_check_ignore (file_name) == 1) {
        os_free(wd_sum);
        return (0);
    }

#ifdef WIN32
    /* Win32 does not have lstat */
    if (stat(file_name, &statbuf) < 0)
#else
    if (lstat(file_name, &statbuf) < 0)
#endif
    {
        os_calloc(OS_SIZE_6144, sizeof(char), alert_msg);

        switch (errno) {
        case ENOENT:
            mdebug2(FIM_CANNOT_ACCESS_FILE, file_name);
            /* Fallthrough */

        case ENOTDIR:
            /*Deletion message sending*/
            mdebug1(FIM_FILE_MSG_DELETE, file_name);
            snprintf(alert_msg, OS_SIZE_6144, "-1!:::::::::::%s %s", syscheck.tag[dir_position] ? syscheck.tag[dir_position] : "", file_name);
            send_syscheck_msg(alert_msg);

#ifndef WIN32
            fim_delete_hashes(strdup(file_name));
#else
            // Delete from hash table
            if (s_node = OSHash_Delete_ex(syscheck.fp, file_name), s_node) {
                os_free(s_node->checksum);
                os_free(s_node);
            }
#endif
            os_free(alert_msg);
            os_free(wd_sum);
            return (0);

        default:
            merror(FIM_ERROR_ACCESING, file_name, strerror(errno), errno);
            os_free(alert_msg);
            os_free(wd_sum);
            return (-1);
        }
    }

    if (S_ISDIR(statbuf.st_mode)) {
#ifdef WIN32
        /* Directory links are not supported */
        if (GetFileAttributes(file_name) & FILE_ATTRIBUTE_REPARSE_POINT) {
            mwarn(FIM_WARN_SYMLINKS_UNSUPPORTED, file_name);
            os_free(wd_sum);
            os_free(alert_msg);
            return (-1);
        }
#endif
        os_free(wd_sum);
        os_free(alert_msg);
        return (read_dir(file_name, dir_position, NULL, max_depth-1, 0));

    }

    if (fim_check_restrict (file_name, restriction) == 1) {
        mdebug1(FIM_FILE_IGNORE_RESTRICT, file_name);
        os_free(wd_sum);
        os_free(alert_msg);
        return (0);
    }

    /* No S_ISLNK on Windows */
#ifdef WIN32
    if (S_ISREG(statbuf.st_mode))
#else
    struct stat statbuf_lnk;

    if (S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode))
#endif
    {
        mdebug1(FIM_SCANNING_FILE, file_name);
        os_md5 mf_sum = {'\0'};
        os_sha1 sf_sum = {'\0'};
        os_sha256 sf256_sum = {'\0'};

        /* Generate checksums */
        if ((opts & CHECK_MD5SUM) || (opts & CHECK_SHA1SUM) || (opts & CHECK_SHA256SUM)) {
            /* If it is a link, check if dest is valid */
#ifndef WIN32
            if (S_ISLNK(statbuf.st_mode)) {
                if (stat(file_name, &statbuf_lnk) == 0) {
                    if (S_ISREG(statbuf_lnk.st_mode)) {
                        if (OS_MD5_SHA1_SHA256_File(file_name, syscheck.prefilter_cmd, mf_sum,sf_sum, sf256_sum, OS_BINARY) < 0) {
                            strncpy(mf_sum, "n/a", 4);
                            strncpy(sf_sum, "n/a", 4);
                            strncpy(sf256_sum, "n/a", 4);
                        }
                    } else if (S_ISDIR(statbuf_lnk.st_mode)) { /* This points to a directory */
                        if (!(opts & CHECK_FOLLOW)) {
                            mdebug2(FIM_SIMBOLIC_LINK_DISABLE);
                            os_free(alert_msg);
                            os_free(wd_sum);
                            return 0;
                        } else {
                            os_free(alert_msg);
                            os_free(wd_sum);
                            return (read_dir(file_name, dir_position, NULL, max_depth-1, 1));
                        }
                    }
                } else {
                    if (opts & CHECK_FOLLOW) {
                        mwarn(FIM_WARN_STAT_BROKEN_LINK, strerror(errno), file_name);
                    }
                    os_free(wd_sum);
                    os_free(alert_msg);
                    return -1;
                }
            } else if (OS_MD5_SHA1_SHA256_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, sf256_sum, OS_BINARY) < 0)
#else
            if (OS_MD5_SHA1_SHA256_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, sf256_sum, OS_BINARY) < 0)
#endif
            {
                snprintf(mf_sum, 4, "n/a");
                snprintf(sf_sum, 4, "n/a");
                snprintf(sf256_sum, 4, "n/a");
            }
        }

        if (s_node = (syscheck_node *) OSHash_Get_ex(syscheck.fp, file_name), !s_node) {
            os_calloc(OS_MAXSTR + 1, sizeof(char), alert_msg);

            char * alertdump = NULL;

            if (opts & CHECK_SEECHANGES) {
                alertdump = seechanges_addfile(file_name);
            }
#ifdef WIN32
            // Get the user name and its id
            if (opts & CHECK_OWNER) {
                user = get_user(file_name, statbuf.st_uid, &sid);
            }

            // Get the file permissions
            if (opts & CHECK_PERM) {
                int error;
                char perm_unescaped[OS_SIZE_6144 + 1];
                if (error = w_get_file_permissions(file_name, perm_unescaped, OS_SIZE_6144), error) {
                    merror(FIM_ERROR_EXTRACT_PERM, file_name, error);
                } else {
                    str_perm = escape_perm_sum(perm_unescaped);
                }
            }

            if (opts & CHECK_SIZE) {
                sprintf(str_size,"%ld",(long)statbuf.st_size);
            } else {
                *str_size = '\0';
            }

            if (opts & CHECK_MTIME) {
                sprintf(str_mtime,"%ld",(long)statbuf.st_mtime);
            } else {
                *str_mtime = '\0';
            }

            if (opts & CHECK_INODE) {
                sprintf(str_inode,"%ld",(long)statbuf.st_ino);
            } else {
                *str_inode = '\0';
            }

            snprintf(alert_msg, OS_MAXSTR, "%c%c%c%c%c%c%c%c%c%c%c%s:%s:%s::%s:%s:%s:%s:%s:%s:%s:%u",
                    opts & CHECK_SIZE ? '+' : '-',
                    opts & CHECK_PERM ? '+' : '-',
                    opts & CHECK_OWNER ? '+' : '-',
                    opts & CHECK_GROUP ? '+' : '-',
                    opts & CHECK_MD5SUM ? '+' : '-',
                    opts & CHECK_SHA1SUM ? '+' : '-',
                    opts & CHECK_MTIME ? '+' : '-',
                    opts & CHECK_INODE ? '+' : '-',
                    opts & CHECK_SHA256SUM ? '+' : '-',
                    opts & CHECK_ATTRS ? '+' : '-',
                    opts & CHECK_SEECHANGES ? '+' : '-',
                    str_size,
                    str_perm ? str_perm : "",
                    (opts & CHECK_OWNER) && sid ? sid : "",
                    opts & CHECK_MD5SUM ? mf_sum : "",
                    opts & CHECK_SHA1SUM ? sf_sum : "",
                    user ? user : "",
                    opts & CHECK_GROUP ? get_group(statbuf.st_gid) : "",
                    str_mtime,
                    str_inode,
                    opts & CHECK_SHA256SUM ? sf256_sum : "",
                    opts & CHECK_ATTRS ? w_get_file_attrs(file_name) : 0);

#else
            if (opts & CHECK_SIZE) {
                if (opts & CHECK_FOLLOW) {
                    if (S_ISLNK(statbuf.st_mode)) {
                        sprintf(str_size,"%ld",(long)statbuf_lnk.st_size);
                    } else {
                        sprintf(str_size,"%ld",(long)statbuf.st_size);
                    }
                } else {
                    sprintf(str_size,"%ld",(long)statbuf.st_size);
                }
            } else {
                *str_size = '\0';
            }

            if (opts & CHECK_PERM) {
                if (S_ISLNK(statbuf.st_mode)) {
                    sprintf(str_perm,"%d",(int)statbuf_lnk.st_mode);
                } else {
                    sprintf(str_perm,"%d",(int)statbuf.st_mode);
                }
            } else {
                *str_perm = '\0';
            }

            if (opts & CHECK_OWNER) {
                if (S_ISLNK(statbuf.st_mode)) {
                    sprintf(str_owner,"%d",(int)statbuf_lnk.st_uid);
                } else {
                    sprintf(str_owner,"%d",(int)statbuf.st_uid);
                }
            } else {
                *str_owner = '\0';
            }

            if (opts & CHECK_GROUP) {
                if (S_ISLNK(statbuf.st_mode)) {
                    sprintf(str_group,"%d",(int)statbuf_lnk.st_gid);
                } else {
                    sprintf(str_group,"%d",(int)statbuf.st_gid);
                }
            } else {
                *str_group = '\0';
            }

            if (opts & CHECK_MTIME) {
                if (opts & CHECK_FOLLOW) {
                    if (S_ISLNK(statbuf.st_mode)) {
                        sprintf(str_mtime,"%ld",(long)statbuf_lnk.st_mtime);
                    } else {
                        sprintf(str_mtime,"%ld",(long)statbuf.st_mtime);
                    }
                } else {
                    sprintf(str_mtime,"%ld",(long)statbuf.st_mtime);
                }
            } else {
                *str_mtime = '\0';
            }

            if (opts & CHECK_FOLLOW) {
                if (S_ISLNK(statbuf.st_mode)) {
                    sprintf(str_inode,"%ld",(long)statbuf_lnk.st_ino);
                } else {
                    sprintf(str_inode,"%ld",(long)statbuf.st_ino);
                }
            } else {
                sprintf(str_inode,"%ld",(long)statbuf.st_ino);
            }

            snprintf(alert_msg, OS_MAXSTR, "%c%c%c%c%c%c%c%c%c%c%c%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%u",
                    opts & CHECK_SIZE ? '+' : '-',
                    opts & CHECK_PERM ? '+' : '-',
                    opts & CHECK_OWNER ? '+' : '-',
                    opts & CHECK_GROUP ? '+' : '-',
                    opts & CHECK_MD5SUM ? '+' : '-',
                    opts & CHECK_SHA1SUM ? '+' : '-',
                    opts & CHECK_MTIME ? '+' : '-',
                    opts & CHECK_INODE ? '+' : '-',
                    opts & CHECK_SHA256SUM ? '+' : '-',
                    opts & CHECK_ATTRS ? '+' : '-',
                    opts & CHECK_SEECHANGES ? '+' : '-',
                    str_size,
                    str_perm,
                    str_owner,
                    str_group,
                    opts & CHECK_MD5SUM ? mf_sum : "",
                    opts & CHECK_SHA1SUM ? sf_sum : "",
                    opts & CHECK_OWNER ? get_user(file_name, S_ISLNK(statbuf.st_mode) ? statbuf_lnk.st_uid : statbuf.st_uid, NULL) : "",
                    opts & CHECK_GROUP ? get_group(S_ISLNK(statbuf.st_mode) ? statbuf_lnk.st_gid : statbuf.st_gid) : "",
                    str_mtime,
                    opts & CHECK_INODE ? str_inode : "",
                    opts & CHECK_SHA256SUM ? sf256_sum : "",
                    0);
#endif

            os_calloc(1, sizeof(syscheck_node), s_node);
            s_node->checksum = strdup(alert_msg);
            s_node->dir_position = dir_position;

            if (OSHash_Add_ex(syscheck.fp, file_name, s_node) != 2) {
                os_free(s_node->checksum);
                os_free(s_node);
                merror(FIM_ERROR_ADD_FILE, file_name);
            }
#ifndef WIN32
            hash_file_name = strdup(file_name);
            int ret = OSHash_Add_ex(syscheck.inode_hash, str_inode, hash_file_name);
            char * inode_path;

            switch (ret) {
            case 0:
                os_free(hash_file_name);
                mdebug2(FIM_HASH_ADD_FAIL, file_name, str_inode);
                break;
            case 1:
                if (inode_path = OSHash_Get_ex(syscheck.inode_hash, str_inode), inode_path) {
                    if(strcmp(inode_path, file_name)) {
                        mdebug2(FIM_HASH_UPDATE, file_name, inode_path, str_inode);
                        OSHash_Update_ex(syscheck.inode_hash, str_inode, (void*)hash_file_name);
                        read_file(inode_path, dir_position, evt, max_depth);
                        os_free(inode_path);
                    }
                    else {
                        os_free(hash_file_name);
                    }
                }
                else {
                    os_free(hash_file_name);
                }
            }
#endif
            /* Send the new checksum to the analysis server */
            alert_msg[OS_MAXSTR] = '\0';

            /* Extract the whodata sum here to not include it in the hash table */
            if (extract_whodata_sum(evt, wd_sum, OS_SIZE_6144)) {
                merror(FIM_ERROR_WHODATA_SUM_MAX, file_name);
            }

#ifdef WIN32
            if (opts & CHECK_SIZE) {
                sprintf(str_size,"%ld",(long)statbuf.st_size);
            } else {
                *str_size = '\0';
            }

            if (opts & CHECK_MTIME) {
                sprintf(str_mtime,"%ld",(long)statbuf.st_mtime);
            } else {
                *str_mtime = '\0';
            }

            if (opts & CHECK_INODE) {
                sprintf(str_inode,"%ld",(long)statbuf.st_ino);
            } else {
                *str_inode = '\0';
            }

            snprintf(alert_msg, OS_MAXSTR, "%s:%s:%s::%s:%s:%s:%s:%s:%s:%s:%u!%s:%s %s%s%s",
                str_size,
                str_perm ? str_perm : "",
                (opts & CHECK_OWNER) && sid ? sid : "",
                opts & CHECK_MD5SUM ? mf_sum : "",
                opts & CHECK_SHA1SUM ? sf_sum : "",
                user ? user : "",
                opts & CHECK_GROUP ? get_group(statbuf.st_gid) : "",
                str_mtime,
                str_inode,
                opts & CHECK_SHA256SUM ? sf256_sum : "",
                opts & CHECK_ATTRS ? w_get_file_attrs(file_name) : 0,
                wd_sum,
                syscheck.tag[dir_position] ? syscheck.tag[dir_position] : "",
                file_name,
                alertdump ? "\n" : "",
                alertdump ? alertdump : "");

            os_free(user);
#else
            if (opts & CHECK_SIZE) {
                if (opts & CHECK_FOLLOW) {
                    if (S_ISLNK(statbuf.st_mode)) {
                        sprintf(str_size,"%ld",(long)statbuf_lnk.st_size);
                    } else {
                        sprintf(str_size,"%ld",(long)statbuf.st_size);
                    }
                } else {
                    sprintf(str_size,"%ld",(long)statbuf.st_size);
                }
            } else {
                *str_size = '\0';
            }

            if (opts & CHECK_PERM) {
                if (S_ISLNK(statbuf.st_mode)) {
                    sprintf(str_perm,"%d",(int)statbuf_lnk.st_mode);
                } else {
                    sprintf(str_perm,"%d",(int)statbuf.st_mode);
                }
            } else {
                *str_perm = '\0';
            }

            if (opts & CHECK_OWNER) {
                if (S_ISLNK(statbuf.st_mode)) {
                    sprintf(str_owner,"%d",(int)statbuf_lnk.st_uid);
                } else {
                    sprintf(str_owner,"%d",(int)statbuf.st_uid);
                }
            } else {
                *str_owner = '\0';
            }

            if (opts & CHECK_GROUP) {
                if (S_ISLNK(statbuf.st_mode)) {
                    sprintf(str_group,"%d",(int)statbuf_lnk.st_gid);
                } else {
                    sprintf(str_group,"%d",(int)statbuf.st_gid);
                }
            } else {
                *str_group = '\0';
            }

            if (opts & CHECK_MTIME) {
                if (opts & CHECK_FOLLOW) {
                    if (S_ISLNK(statbuf.st_mode)) {
                        sprintf(str_mtime,"%ld",(long)statbuf_lnk.st_mtime);
                    } else {
                        sprintf(str_mtime,"%ld",(long)statbuf.st_mtime);
                    }
                } else {
                    sprintf(str_mtime,"%ld",(long)statbuf.st_mtime);
                }
            } else {
                *str_mtime = '\0';
            }

            if (opts & CHECK_INODE) {
                if (opts & CHECK_FOLLOW) {
                    if (S_ISLNK(statbuf.st_mode)) {
                        sprintf(str_inode,"%ld",(long)statbuf_lnk.st_ino);
                    } else {
                        sprintf(str_inode,"%ld",(long)statbuf.st_ino);
                    }
                } else {
                    sprintf(str_inode,"%ld",(long)statbuf.st_ino);
                }
            } else {
                *str_inode = '\0';
            }

            snprintf(alert_msg, OS_MAXSTR, "%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%u!%s:%s %s%s%s",
                str_size,
                str_perm,
                str_owner,
                str_group,
                opts & CHECK_MD5SUM ? mf_sum : "",
                opts & CHECK_SHA1SUM ? sf_sum : "",
                opts & CHECK_OWNER ? get_user(file_name, S_ISLNK(statbuf.st_mode) ? statbuf_lnk.st_uid : statbuf.st_uid, NULL) : "",
                opts & CHECK_GROUP ? get_group(S_ISLNK(statbuf.st_mode) ? statbuf_lnk.st_gid : statbuf.st_gid) : "",
                str_mtime,
                str_inode,
                opts & CHECK_SHA256SUM ? sf256_sum : "",
                0,
                wd_sum,
                syscheck.tag[dir_position] ? syscheck.tag[dir_position] : "",
                file_name,
                alertdump ? "\n" : "",
                alertdump ? alertdump : "");
#endif
            if(max_depth <= syscheck.max_depth){
                send_syscheck_msg(alert_msg);
            }

            os_free(alert_msg);
            os_free(alertdump);
        } else {
            os_calloc(OS_MAXSTR + 1, sizeof(char), alert_msg);
            os_calloc(OS_MAXSTR + 1, sizeof(char), c_sum);

            buf = s_node->checksum;

            /* If it returns < 0, we have already alerted */
            if (c_read_file(file_name, buf, c_sum, NULL) < 0) {
              goto end;
            }

            w_mutex_lock(&lastcheck_mutex);
            OSHash_Delete(syscheck.last_check, file_name);
            w_mutex_unlock(&lastcheck_mutex);

            if (strcmp(c_sum, buf + SK_DB_NATTR)) {
                // Extract the whodata sum here to not include it in the hash table
                if (extract_whodata_sum(evt, wd_sum, OS_SIZE_6144)) {
                    merror(FIM_ERROR_WHODATA_SUM_MAX, file_name);
                }
                // Update database
                snprintf(alert_msg, OS_MAXSTR, "%.*s%.*s", SK_DB_NATTR, buf, (int)strcspn(c_sum, " "), c_sum);
                s_node->checksum = strdup(alert_msg);

                /* Send the new checksum to the analysis server */
                alert_msg[OS_MAXSTR] = '\0';
                char *fullalert = NULL;
                if (buf[SK_DB_REPORT_CHANG] == '+') {
                    fullalert = seechanges_addfile(file_name);
                    if (fullalert) {
                        snprintf(alert_msg, OS_MAXSTR, "%s!%s:%s %s\n%s",
                                c_sum, wd_sum, syscheck.tag[dir_position] ? syscheck.tag[dir_position] : "", file_name, fullalert);
                        os_free(fullalert);
                        fullalert = NULL;
                    } else {
                        snprintf(alert_msg, OS_MAXSTR, "%s!%s:%s %s",
                                c_sum, wd_sum, syscheck.tag[dir_position] ? syscheck.tag[dir_position] : "", file_name);
                    }
                } else {
                    snprintf(alert_msg, OS_MAXSTR, "%s!%s:%s %s",
                            c_sum, wd_sum, syscheck.tag[dir_position] ? syscheck.tag[dir_position] : "", file_name);
                }
                os_free(buf);
                send_syscheck_msg(alert_msg);
            }
            os_free(alert_msg);
            os_free(c_sum);
        }

        /* Sleep here too */
        if (__counter >= (syscheck.sleep_after)) {
            sleep(syscheck.tsleep);
            __counter = 0;
        }
        __counter++;
    } else {
        mdebug1(FIM_SCANNING_IRREGFILE, file_name);
    }


end:
    os_free(wd_sum);
    os_free(alert_msg);
    os_free(c_sum);
#ifdef WIN32
    if (sid) {
        LocalFree(sid);
    }
    os_free(str_perm);
#endif
    return 0;
}

int read_dir(const char *dir_name, int dir_position, whodata_evt *evt, int max_depth, __attribute__((unused))unsigned int is_link)
{
    char *f_name;
    short is_nfs;
    DIR *dp;
    struct dirent *entry;
    int opts;
    size_t dir_size;

    if(max_depth < 0) {
        mdebug1(FIM_MAX_RECURSION_LEVEL, dir_name);
        return 0;
    }

    // 3.8 - We can't follow symlinks in Windows
#ifndef WIN32
    switch(read_links(dir_name, dir_position, max_depth, is_link)) {
    case 2:
        mdebug2(FIM_SYMBOLIC_LINK_DISCARDED
                dir_name);
        return 0;
    case 1:
        mdebug1(FIM_SYMBOLIC_LINK_ADD, dir_name);
        return 0;
    case 0:
        break;
    default:
        return -1;
    }
#endif

    os_calloc(PATH_MAX + 2, sizeof(char), f_name);
    opts = syscheck.opts[dir_position];

    /* Directory should be valid */
    if ((dir_name == NULL) || ((dir_size = strlen(dir_name)) > PATH_MAX)) {
        free(f_name);
        merror(NULL_ERROR);
        return (-1);
    }

    /* Open the directory given */
    dp = opendir(dir_name);

    /* Should we check for NFS? */
    if (syscheck.skip_nfs && dp) {
        is_nfs = IsNFS(dir_name);
        if (is_nfs != 0) {
            // Error will be -1, and 1 means skipped
            free(f_name);
            closedir(dp);
            return (is_nfs);
        }
    }

    if (!dp) {
        if (errno == ENOTDIR || errno == ENOENT) {
            if (read_file(dir_name, dir_position, evt, max_depth) == 0) {
                free(f_name);
                return (0);
            }
        }

#ifdef WIN32
        int di = 0;
        char *(defaultfilesn[]) = {
            "C:\\autoexec.bat",
            "C:\\config.sys",
            "C:\\WINDOWS/System32/eventcreate.exe",
            "C:\\WINDOWS/System32/eventtriggers.exe",
            "C:\\WINDOWS/System32/tlntsvr.exe",
            "C:\\WINDOWS/System32/Tasks",
            NULL
        };

        while (defaultfilesn[di] != NULL) {
            if (strcmp(defaultfilesn[di], dir_name) == 0) {
                break;
            }
            di++;
        }

#ifdef WIN_WHODATA
        if (defaultfilesn[di] == NULL && !(evt && evt->ignore_not_exist)) {
#else
        if (defaultfilesn[di] == NULL) {
#endif
            mdebug1("Cannot open '%s': %s ", dir_name, strerror(errno));
        } else {
            free(f_name);
            return 0;
        }
#else
        mdebug1("Cannot open '%s': %s ", dir_name, strerror(errno));

#endif /* WIN32 */
        free(f_name);
        return (-1);
    }

    /* Check for real time flag */
    if (opts & CHECK_REALTIME || opts & CHECK_WHODATA) {
#ifdef INOTIFY_ENABLED
        realtime_adddir(dir_name, opts & CHECK_WHODATA);
#else
#ifndef WIN32
        mwarn(FIM_WARN_REALTIME_UNSUPPORTED, dir_name);
#endif
#endif
    }

    while ((entry = readdir(dp)) != NULL) {
        char *s_name;

        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        strncpy(f_name, dir_name, PATH_MAX);
        s_name =  f_name;
        s_name += dir_size;

        /* Check if the file name is already null terminated */
#ifdef WIN32
        if (*(s_name - 1) != '\\') {
            *s_name++ = '\\';
        }
#else
        if (*(s_name - 1) != '/') {
            *s_name++ = '/';
        }
#endif

        *s_name = '\0';
        strncpy(s_name, entry->d_name, PATH_MAX - dir_size - 2);

#ifdef WIN32
        str_lowercase(f_name);
#endif
        /* Check integrity of the file */

        read_file(f_name, dir_position, evt, max_depth);
    }

    os_free(f_name);
    closedir(dp);
    return (0);
}

int run_dbcheck()
{
    unsigned int i = 0;
    char *alert_msg = NULL;
    OSHash *last_backup;
    int pos;

    os_calloc(OS_SIZE_6144, sizeof(char), alert_msg);

    __counter = 0;
    while (syscheck.dir[i] != NULL) {
#ifdef WIN_WHODATA
        if (syscheck.wdata.dirs_status[i].status & WD_CHECK_REALTIME) {
            // At this point the directories in whodata mode that have been deconfigured are added to realtime
            syscheck.wdata.dirs_status[i].status &= ~WD_CHECK_REALTIME;
            if (realtime_adddir(syscheck.dir[i], 0) != 1) {
                merror(FIM_ERROR_REALTIME_ADDDIR_FAILED, syscheck.dir[i]);
            } else {
                mdebug1(FIM_REALTIME_MONITORING, syscheck.dir[i]);
            }
        }
#endif
        read_dir(syscheck.dir[i], i, NULL, syscheck.recursion_level[i], 0);
        i++;
    }

    if (syscheck.dir[0]) {
        // Check for deleted files
        w_mutex_lock(&lastcheck_mutex);
        last_backup = syscheck.last_check;

        // Prepare last_check for next scan
        syscheck.last_check = OSHash_Duplicate_ex(syscheck.fp);
        w_mutex_unlock(&lastcheck_mutex);

        // Send messages for deleted files
        OSHashNode *curr_node;
        unsigned int *i;

        os_calloc(1, sizeof(unsigned int), i);

        for (curr_node = OSHash_Begin(last_backup, i); curr_node && curr_node->data; curr_node = OSHash_Next(last_backup, i, curr_node)) {
            pos = find_dir_pos(curr_node->key, 1, 0, 0);

            mdebug1(FIM_FILE_MSG_DELETE, curr_node->key);
            snprintf(alert_msg, OS_SIZE_6144 - 1, "-1!:::::::::::%s %s", syscheck.tag[pos] ? syscheck.tag[pos] : "", curr_node->key);
            send_syscheck_msg(alert_msg);
#ifndef WIN32
            fim_delete_hashes(strdup(curr_node->key));
#endif
            OSHash_Delete_ex(syscheck.last_check, curr_node->key);
        }
        os_free(i);

        last_backup->free_data_function = NULL;
        OSHash_Free(last_backup);

        // Check and delete backup local/diff
        remove_local_diff();
    }

    free(alert_msg);

    return (0);
}

int create_db()
{
    int i = 0;
#ifdef WIN_WHODATA
    int enable_who_scan = 0;
    HANDLE t_hdle;
    long unsigned int t_id;
#endif

    if (!syscheck.fp) {
        merror_exit("Unable to create syscheck database. Exiting.");
    }

    if (!OSHash_setSize_ex(syscheck.fp, 2048)) {
        merror(LIST_ERROR);
        return (0);
    }
    if (!OSHash_setSize(syscheck.local_hash, 2048)) {
        merror(LIST_ERROR);
        return (0);
    }
#ifndef WIN32
    if (!OSHash_setSize(syscheck.inode_hash, 2048)) {
        merror(LIST_ERROR);
        return (0);
    }
#endif

    if ((syscheck.dir == NULL) || (syscheck.dir[0] == NULL)) {
        merror(FIM_ERROR_NOTHING_TOCKECK);
        return (-1);
    }

    /* Read all available directories */
    __counter = 0;
    do {
        if (read_dir(syscheck.dir[i], i, NULL, syscheck.recursion_level[i], 0) == 0) {
            mdebug2(FIM_FREQUENCY_DIRECTORY, syscheck.dir[i]);
        }
#ifdef WIN32
        if (syscheck.opts[i] & CHECK_WHODATA) {
#ifdef WIN_WHODATA
            realtime_adddir(syscheck.dir[i], i + 1);
            if (!enable_who_scan) {
                enable_who_scan = 1;
            }
#endif
        } else if (syscheck.opts[i] & CHECK_REALTIME) {
            realtime_adddir(syscheck.dir[i], 0);
        }
#else
#ifndef INOTIFY_ENABLED
        // Realtime mode on Linux requires inotify
        if (syscheck.opts[i] & CHECK_REALTIME) {
            mwarn(FIM_WARN_REALTIME_UNSUPPORTED, syscheck.dir[i]);
        }
#endif
#endif
        i++;
    } while (syscheck.dir[i] != NULL);

    remove_local_diff();

    w_mutex_lock(&lastcheck_mutex);
    OSHash_Free(syscheck.last_check);
    /* Duplicate hash table to check for deleted files */
    syscheck.last_check = OSHash_Duplicate(syscheck.fp);
    w_mutex_unlock(&lastcheck_mutex);

#ifdef WIN_WHODATA
    if (enable_who_scan && !run_whodata_scan()) {
        minfo(FIM_WHODATA_START);
        if (t_hdle = CreateThread(NULL, 0, state_checker, NULL, 0, &t_id), !t_hdle) {
            merror(FIM_ERROR_CHECK_THREAD);
        }
    }
#endif

    return (0);
}

int extract_whodata_sum(whodata_evt *evt, char *wd_sum, int size) {
    int retval = 0;
    if (!evt) {
        if (snprintf(wd_sum, size, "::::::::::") >= size) {
            retval = 1;
        }
    } else {
        char *process_esc = NULL;
        char *name_esc = evt->user_name;
        char *esc_it = NULL;

        // Escape process
        esc_it = wstr_replace(evt->process_name, ":", "\\:");
        process_esc = wstr_replace(esc_it, " ", "\\ ");

#ifdef WIN32
        // Only Windows agents can have spaces in their names
        name_esc = wstr_replace(evt->user_name, " ", "\\ ");
#endif
        if (snprintf(wd_sum, size, "%s:%s:%s:%s:%s:%s:%s:%s:%s:%i:%lli",
                (evt->user_id)?evt->user_id:"",
                (name_esc)?name_esc:"",
                (evt->group_id)?evt->group_id:"",
                (evt->group_name)?evt->group_name:"",
                (process_esc)?process_esc:"",
                (evt->audit_uid)?evt->audit_uid:"",
                (evt->audit_name)?evt->audit_name:"",
                (evt->effective_uid)?evt->effective_uid:"",
                (evt->effective_name)?evt->effective_name:"",
                evt->ppid,
                (long long unsigned int) evt->process_id
            ) >= size) {
            retval = 1;
            snprintf(wd_sum, size, "::::::::::");
        }

#ifdef WIN32
        free(name_esc);
#endif
        free(process_esc);
        free(esc_it);
    }
    return retval;
}

int fim_check_ignore (const char *file_name) {
    /* Check if the file should be ignored */
    if (syscheck.ignore) {
        int i = 0;
        while (syscheck.ignore[i] != NULL) {
            if (strncasecmp(syscheck.ignore[i], file_name, strlen(syscheck.ignore[i])) == 0) {
                mdebug1(FIM_IGNORE_ENTRY, "file", file_name, syscheck.ignore[i]);
                return (1);
            }
            i++;
        }
    }

    /* Check in the regex entry */
    if (syscheck.ignore_regex) {
        int i = 0;
        while (syscheck.ignore_regex[i] != NULL) {
            if (OSMatch_Execute(file_name, strlen(file_name), syscheck.ignore_regex[i])) {
                mdebug1(FIM_IGNORE_SREGEX, "file", file_name, syscheck.ignore_regex[i]->raw);
                return (1);
            }
            i++;
        }
    }

    return (0);
}

int fim_check_restrict (const char *file_name, OSMatch *restriction) {
    /* Restrict file types */
    if (restriction) {
        if (!OSMatch_Execute(file_name, strlen(file_name), restriction)) {
            return (1);
        }
    }

    return (0);
}

#ifndef WIN32
// Only Linux follow symlinks
int read_links(const char *dir_name, int dir_position, int max_depth, unsigned int is_link) {
    char *dir_name_full;
    char *real_path;
    int opts;

    os_calloc(PATH_MAX + 2, sizeof(char), real_path);
    os_calloc(PATH_MAX + 2, sizeof(char), dir_name_full);

    if (is_link) {
        if (realpath(dir_name, real_path) == NULL) {
            mdebug1(FIM_CHECK_LINK_REALPATH, dir_name);
            free(real_path);
            free(dir_name_full);
            return -1;
        }
        strcat(real_path, "/");
        opts = syscheck.opts[dir_position];

        unsigned int i = 0;
        while (syscheck.dir[i] != NULL) {
            strncpy(dir_name_full, syscheck.dir[i], PATH_MAX);
            strcat(dir_name_full, "/");
                if (strstr(real_path, dir_name_full) != NULL) {
                    free(real_path);
                    free(dir_name_full);
                    return 2;
            }
            i++;
        }
        real_path[strlen(real_path) - 1] = '\0';
        if(syscheck.filerestrict[dir_position]) {
            dump_syscheck_entry(&syscheck,
                                real_path,
                                opts,
                                0,
                                syscheck.filerestrict[dir_position]->raw,
                                max_depth, syscheck.tag[dir_position],
                                -1);
        } else {
            dump_syscheck_entry(&syscheck,
                                real_path,
                                opts,
                                0,
                                NULL,
                                max_depth, syscheck.tag[dir_position],
                                -1);
        }
        /* Check for real time flag */
        if (opts & CHECK_REALTIME || opts & CHECK_WHODATA) {
#ifdef INOTIFY_ENABLED
            realtime_adddir(real_path, opts & CHECK_WHODATA);
#else
            mwarn(FIM_WARN_REALTIME_UNSUPPORTED, dir_name);
#endif
        }

        free(real_path);
        free(dir_name_full);
        return 1;
    }

    free(real_path);
    free(dir_name_full);
    return 0;
}

int fim_delete_hashes(char *file_name) {
    char *checksum_inode;
    char *inode_str;
    char *w_inode;
    OSHashNode *s_inode;
    char * inode_path;
    syscheck_node *data;

    if (data = OSHash_Delete_ex(syscheck.fp, file_name), data) {
        os_strdup(data->checksum, checksum_inode);

        if(inode_str = get_attr_from_checksum(checksum_inode, SK_INODE), !inode_str || *inode_str == '\0') {
            unsigned int *inode_it;
            os_calloc(1, sizeof(unsigned int), inode_it);

            //Looking for inode if check_inode = no
            for (s_inode = OSHash_Begin(syscheck.inode_hash, inode_it); s_inode && s_inode->data; s_inode = OSHash_Next(syscheck.inode_hash, inode_it, s_inode)) {
                if(!strcmp(s_inode->data, file_name)){
                    inode_str = s_inode->key;
                    break;
                }
            }
            os_free(inode_it);
        }

        if(inode_str) {
            if (inode_path = OSHash_Get_ex(syscheck.inode_hash, inode_str), inode_path) {
                if(!strcmp(inode_path, file_name)) {
                    if (w_inode = OSHash_Delete_ex(syscheck.inode_hash, inode_str), w_inode) {
                        os_free(w_inode);
                    }
                }
            }
        }

        os_free(checksum_inode);
        os_free(data->checksum);
        os_free(data);
    }
    os_free(file_name);

    return 0;
}

#endif
