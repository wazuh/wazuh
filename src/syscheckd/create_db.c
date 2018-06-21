/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "syscheck.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/sha256/sha256_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#include "os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"
#include "syscheck_op.h"

/* Prototypes */
static int read_file(const char *dir_name, int opts, OSMatch *restriction)  __attribute__((nonnull(1)));

/* Global variables */
static int __counter = 0;


/* Read and generate the integrity data of a file */
static int read_file(const char *file_name, int opts, OSMatch *restriction)
{
    char *buf;
    char sha1s = '-';
    char sha256s = '-';
    struct stat statbuf;

    /* Check if the file should be ignored */
    if (syscheck.ignore) {
        int i = 0;
        while (syscheck.ignore[i] != NULL) {
            if (strncasecmp(syscheck.ignore[i], file_name,
                            strlen(syscheck.ignore[i])) == 0) {
                return (0);
            }
            i++;
        }
    }

    /* Check in the regex entry */
    if (syscheck.ignore_regex) {
        int i = 0;
        while (syscheck.ignore_regex[i] != NULL) {
            if (OSMatch_Execute(file_name, strlen(file_name),
                                syscheck.ignore_regex[i])) {
                return (0);
            }
            i++;
        }
    }

#ifdef WIN32
    /* Win32 does not have lstat */
    if (stat(file_name, &statbuf) < 0)
#else
    if (lstat(file_name, &statbuf) < 0)
#endif
    {
        if(errno == ENOTDIR){
		/*Deletion message sending*/
        char * buf;
		char alert_msg[PATH_MAX+4];
		alert_msg[PATH_MAX + 3] = '\0';
		snprintf(alert_msg, PATH_MAX + 4, "-1 %s", file_name);
		send_syscheck_msg(alert_msg);

        // Update database

        if (buf = (char *) OSHash_Get(syscheck.fp, file_name), buf) {
            snprintf(alert_msg, sizeof(alert_msg), "%.*s -1", SK_DB_NATTR, buf);
            free(buf);

            if (!OSHash_Update(syscheck.fp, file_name, strdup(alert_msg))) {
                merror("Unable to update file to db: %s", file_name);
            }
        }

		return (0);
	}else{
		merror("Error accessing '%s'.", file_name);
		return (-1);
	}
    }

    if (S_ISDIR(statbuf.st_mode)) {
#ifdef DEBUG
        minfo("Reading dir: %s\n", file_name);
#endif

#ifdef WIN32
        /* Directory links are not supported */
        if (GetFileAttributes(file_name) & FILE_ATTRIBUTE_REPARSE_POINT) {
            mwarn("Links are not supported: '%s'", file_name);
            return (-1);
        }
#endif
        return (read_dir(file_name, opts, restriction));
    }

    /* Restrict file types */
    if (restriction) {
        if (!OSMatch_Execute(file_name, strlen(file_name),
                             restriction)) {
            return (0);
        }
    }

    /* No S_ISLNK on Windows */
#ifdef WIN32
    if (S_ISREG(statbuf.st_mode))
#else
    if (S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode))
#endif
    {
        os_md5 mf_sum;
        os_sha1 sf_sum;
        os_sha1 sf_sum2;
        os_sha1 sf_sum3;
        os_sha256 sf256_sum;

        /* Clean sums */
        strncpy(mf_sum,  "xxx", 4);
        strncpy(sf_sum,  "xxx", 4);
        strncpy(sf_sum2, "xxx", 4);
        strncpy(sf_sum3, "xxx", 4);
        strncpy(sf256_sum, "xxx", 4);

        if (opts & CHECK_SHA1SUM) {
            sha1s = '+';
        }
        if (opts & CHECK_SHA256SUM) {
            sha256s = '+';
        }

        /* Generate checksums */
        if ((opts & CHECK_MD5SUM) || (opts & CHECK_SHA1SUM) || (opts & CHECK_SHA256SUM)) {
            /* If it is a link, check if dest is valid */
#ifndef WIN32
            if (S_ISLNK(statbuf.st_mode)) {
                struct stat statbuf_lnk;
                if (stat(file_name, &statbuf_lnk) == 0) {
                    if (S_ISREG(statbuf_lnk.st_mode)) {
                        if (OS_MD5_SHA1_SHA256_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, sf256_sum, OS_BINARY) < 0) {
                            strncpy(mf_sum, "n/a", 4);
                            strncpy(sf_sum, "n/a", 4);
                            strncpy(sf256_sum, "n/a", 4);
                        }
                    }
                }
            } else if (OS_MD5_SHA1_SHA256_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, sf256_sum, OS_BINARY) < 0)
#else
            if (OS_MD5_SHA1_SHA256_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, sf256_sum, OS_BINARY) < 0)
#endif
            {
                strncpy(mf_sum, "n/a", 4);
                strncpy(sf_sum, "n/a", 4);
                strncpy(sf256_sum, "n/a", 4);
            }

            if (opts & CHECK_SEECHANGES) {
                sha1s = 's';
                sha256s = 's';
            }
        } else {
            if (opts & CHECK_SEECHANGES) {
                sha1s = 'n';
                sha256s = 'n';
            } else {
                sha1s = '-';
                sha256s = '-';
            }
        }

        buf = (char *) OSHash_Get(syscheck.fp, file_name);
        if (!buf) {
            char alert_msg[1172 + 1];    /* to accommodate a long */
            alert_msg[1172] = '\0';
            char * alertdump = NULL;

            if (opts & CHECK_SEECHANGES) {
                alertdump = seechanges_addfile(file_name);
            }
#ifdef WIN32
            snprintf(alert_msg, 1172, "%c%c%c%c%c%c%c%c%c%ld:%d:::%s:%s:%s:%s:%s:%ld:%ld",
                     opts & CHECK_SIZE ? '+' : '-',
                     opts & CHECK_PERM ? '+' : '-',
                     opts & CHECK_OWNER ? '+' : '-',
                     opts & CHECK_GROUP ? '+' : '-',
                     opts & CHECK_MD5SUM ? '+' : '-',
                     sha1s,
                     opts & CHECK_MTIME ? '+' : '-',
                     opts & CHECK_INODE ? '+' : '-',
                     sha256s,
                     opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                     opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                     opts & CHECK_MD5SUM ? mf_sum : "xxx",
                     opts & CHECK_SHA1SUM ? sf_sum : "xxx",
                     opts & CHECK_OWNER ? get_user(file_name, statbuf.st_uid) : "",
                     opts & CHECK_GROUP ? get_group(statbuf.st_gid) : "",
                     opts & CHECK_MTIME ? (long)statbuf.st_mtime : 0,
                     opts & CHECK_INODE ? (long)statbuf.st_ino : 0,
                     opts & CHECK_SHA256SUM ? sf256_sum : "xxx");
#else
            snprintf(alert_msg, 1172, "%c%c%c%c%c%c%c%c%c%ld:%d:%d:%d:%s:%s:%s:%s:%s:%ld:%ld",
                     opts & CHECK_SIZE ? '+' : '-',
                     opts & CHECK_PERM ? '+' : '-',
                     opts & CHECK_OWNER ? '+' : '-',
                     opts & CHECK_GROUP ? '+' : '-',
                     opts & CHECK_MD5SUM ? '+' : '-',
                     sha1s,
                     opts & CHECK_MTIME ? '+' : '-',
                     opts & CHECK_INODE ? '+' : '-',
                     sha256s,
                     opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                     opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                     opts & CHECK_OWNER ? (int)statbuf.st_uid : 0,
                     opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                     opts & CHECK_MD5SUM ? mf_sum : "xxx",
                     opts & CHECK_SHA1SUM ? sf_sum : "xxx",
                     opts & CHECK_OWNER ? get_user(file_name, statbuf.st_uid) : "",
                     opts & CHECK_GROUP ? get_group(statbuf.st_gid) : "",
                     opts & CHECK_MTIME ? (long)statbuf.st_mtime : 0,
                     opts & CHECK_INODE ? (long)statbuf.st_ino : 0,
                     opts & CHECK_SHA256SUM ? sf256_sum : "xxx");

            if (OSHash_Add(syscheck.fp, file_name, strdup(alert_msg)) <= 0) {
                merror("Unable to add file to db: %s", file_name);
            }

            /* Send the new checksum to the analysis server */
            alert_msg[1172] = '\0';

#ifdef WIN32
            snprintf(alert_msg, 1172, "%ld:%d:::%s:%s:%s:%s:%ld:%ld:%s %s%s%s",
                opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                opts & CHECK_MD5SUM ? mf_sum : "xxx",
                opts & CHECK_SHA1SUM ? sf_sum : "xxx",
                opts & CHECK_OWNER ? get_user(file_name, statbuf.st_uid) : "",
                opts & CHECK_GROUP ? get_group(statbuf.st_gid) : "",
                opts & CHECK_MTIME ? (long)statbuf.st_mtime : 0,
                opts & CHECK_INODE ? (long)statbuf.st_ino : 0,
                opts & CHECK_SHA256SUM ? sf256_sum : "xxx",
                file_name,
                alertdump ? "\n" : "",
                alertdump ? alertdump : "");
#else
            snprintf(alert_msg, 1172, "%ld:%d:%d:%d:%s:%s:%s:%s:%ld:%ld:%s %s%s%s",
                opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                opts & CHECK_OWNER ? (int)statbuf.st_uid : 0,
                opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                opts & CHECK_MD5SUM ? mf_sum : "xxx",
                opts & CHECK_SHA1SUM ? sf_sum : "xxx",
                opts & CHECK_OWNER ? get_user(file_name, statbuf.st_uid) : "",
                opts & CHECK_GROUP ? get_group(statbuf.st_gid) : "",
                opts & CHECK_MTIME ? (long)statbuf.st_mtime : 0,
                opts & CHECK_INODE ? (long)statbuf.st_ino : 0,
                opts & CHECK_SHA256SUM ? sf256_sum : "xxx",
                file_name,
                alertdump ? "\n" : "",
                alertdump ? alertdump : "");
#endif
            send_syscheck_msg(alert_msg);
            free(alertdump);
        } else {
            char alert_msg[OS_MAXSTR + 1];
            char c_sum[512 + 2];

            c_sum[0] = '\0';
            c_sum[512] = '\0';
            alert_msg[0] = '\0';
            alert_msg[OS_MAXSTR] = '\0';

            /* If it returns < 0, we have already alerted */
            if (c_read_file(file_name, buf, c_sum) < 0) {
                return (0);
            }

            OSHash_Delete(syscheck.last_check, file_name);

            if (strcmp(c_sum, buf + SK_DB_NATTR) != 0) {
                // Update database
                snprintf(alert_msg, sizeof(alert_msg), "%.*s%.*s", SK_DB_NATTR, buf, (int)strcspn(c_sum, " "), c_sum);
                free(buf);

                if (!OSHash_Update(syscheck.fp, file_name, strdup(alert_msg))) {
                    merror("Unable to update file to db: %s", file_name);
                }

                /* Send the new checksum to the analysis server */
                alert_msg[OS_MAXSTR] = '\0';
                char *fullalert = NULL;
                if (buf[5] == 's' || buf[5] == 'n') {
                    fullalert = seechanges_addfile(file_name);
                    if (fullalert) {
                        snprintf(alert_msg, OS_MAXSTR, "%s %s\n%s", c_sum, file_name, fullalert);
                        free(fullalert);
                        fullalert = NULL;
                    } else {
                        snprintf(alert_msg, 1172, "%s %s", c_sum, file_name);
                    }
                } else {
                    snprintf(alert_msg, 1172, "%s %s", c_sum, file_name);
                }
                send_syscheck_msg(alert_msg);
            }
        }

        /* Sleep here too */
        if (__counter >= (syscheck.sleep_after)) {
            sleep(syscheck.tsleep);
            __counter = 0;
        }
        __counter++;

#ifdef DEBUG
        minfo("File '%s %s'", file_name, mf_sum);
#endif
    } else {
#ifdef DEBUG
        minfo("*** IRREG file: '%s'\n", file_name);
#endif
    }

    return (0);
}

int read_dir(const char *dir_name, int opts, OSMatch *restriction)
{
    size_t dir_size;
    char f_name[PATH_MAX + 2];
    short is_nfs;

    DIR *dp;
    struct dirent *entry;

    f_name[PATH_MAX + 1] = '\0';

    /* Directory should be valid */
    if ((dir_name == NULL) || ((dir_size = strlen(dir_name)) > PATH_MAX)) {
        merror(NULL_ERROR);
        return (-1);
    }

    /* Should we check for NFS? */
    if(syscheck.skip_nfs)
    {
        is_nfs = IsNFS(dir_name);
        if(is_nfs != 0)
        {
            // Error will be -1, and 1 means skipped
            return(is_nfs);
        }
    }


    /* Open the directory given */
    dp = opendir(dir_name);
    if (!dp) {
        if (errno == ENOTDIR) {
            if (read_file(dir_name, opts, restriction) == 0) {
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

        if (defaultfilesn[di] == NULL) {
            mwarn("Error opening directory: '%s': %s ", dir_name, strerror(errno));
        }
#else
        mwarn("Error opening directory: '%s': %s ", dir_name, strerror(errno));
#endif /* WIN32 */
        return (-1);
    }

    /* Check for real time flag */
    if (opts & CHECK_REALTIME) {
#ifdef INOTIFY_ENABLED
        realtime_adddir(dir_name);
#else
#ifndef WIN32
        mwarn("realtime monitoring request on unsupported system for '%s'", dir_name);
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
        if (*(s_name - 1) != '/') {
            *s_name++ = '/';
        }

        *s_name = '\0';
        strncpy(s_name, entry->d_name, PATH_MAX - dir_size - 2);

        /* Check integrity of the file */
        read_file(f_name, opts, restriction);
    }

    closedir(dp);
    return (0);
}

int run_dbcheck()
{
    unsigned int i = 0;
    OSHashNode *curr_node;
    char alert_msg[PATH_MAX+4];

    __counter = 0;
    while (syscheck.dir[i] != NULL) {
        read_dir(syscheck.dir[i], syscheck.opts[i], syscheck.filerestrict[i]);
        i++;
    }

    if (syscheck.dir[0]) {
        /* Check for deleted files */
        for (i = 0; i <= syscheck.last_check->rows; i++) {
            curr_node = syscheck.last_check->table[i];
            if(curr_node && curr_node->key) {
                mdebug2("Sending delete msg for file: %s", curr_node->key);
                snprintf(alert_msg, PATH_MAX + 4, "-1 %s", curr_node->key);
                send_syscheck_msg(alert_msg);
                OSHash_Delete(syscheck.fp, curr_node->key);
            }
        }
        /* Duplicate hash table to check for deleted files */
        syscheck.last_check = OSHash_Duplicate(syscheck.fp);
    }

    return (0);
}

int create_db()
{
    int i = 0;

    /* Create store data */
    syscheck.fp = OSHash_Create();
    syscheck.last_check = OSHash_Create();
    if (!syscheck.fp || !syscheck.last_check) {
        merror_exit("Unable to create syscheck database. Exiting.");
    }

    if (!OSHash_setSize(syscheck.fp, 2048)) {
        merror(LIST_ERROR);
        return (0);
    }

    if ((syscheck.dir == NULL) || (syscheck.dir[0] == NULL)) {
        merror("No directories to check.");
        return (-1);
    }

    minfo("Starting syscheck database (pre-scan).");

    /* Read all available directories */
    __counter = 0;
    do {
        if (read_dir(syscheck.dir[i], syscheck.opts[i], syscheck.filerestrict[i]) == 0) {
            mdebug2("Directory loaded from syscheck db: %s", syscheck.dir[i]);
        }
        /* Check for real time flag on windows*/
        if (syscheck.opts[i] & CHECK_REALTIME) {
#ifdef WIN32
            realtime_adddir(syscheck.dir[i]);
#else
#ifndef INOTIFY_ENABLED
            mwarn("realtime monitoring request on unsupported system for '%s'", syscheck.dir[i]);
#endif
#endif
        }
        i++;
    } while (syscheck.dir[i] != NULL);

    /* Duplicate hash table to check for deleted files */
    syscheck.last_check = OSHash_Duplicate(syscheck.fp);

#if defined (INOTIFY_ENABLED) || defined (WIN32)
    if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
        minfo("Real time file monitoring engine started.");
    }
#endif
    minfo("Finished creating syscheck database (pre-scan completed).");
    return (0);
}
