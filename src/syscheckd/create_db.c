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
#include "os_crypto/md5_sha1/md5_sha1_op.h"

/* Prototypes */
static int read_file(const char *dir_name, int opts, OSMatch *restriction)  __attribute__((nonnull(1)));
static int read_dir(const char *dir_name, int opts, OSMatch *restriction) __attribute__((nonnull(1)));

/* Global variables */
static int __counter = 0;


/* Read and generate the integrity data of a file */
static int read_file(const char *file_name, int opts, OSMatch *restriction)
{
    char *buf;
    char sha1s = '+';
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
		char alert_msg[PATH_MAX+4];
		alert_msg[PATH_MAX + 3] = '\0';
		snprintf(alert_msg, PATH_MAX + 4, "-1 %s", file_name);
		send_syscheck_msg(alert_msg);
		return (0);
	}else{
		merror("%s: Error accessing '%s'.", ARGV0, file_name);
		return (-1);
	}
    }

    if (S_ISDIR(statbuf.st_mode)) {
#ifdef DEBUG
        verbose("%s: Reading dir: %s\n", ARGV0, file_name);
#endif

#ifdef WIN32
        /* Directory links are not supported */
        if (GetFileAttributes(file_name) & FILE_ATTRIBUTE_REPARSE_POINT) {
            merror("%s: WARN: Links are not supported: '%s'", ARGV0, file_name);
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

        /* Clean sums */
        strncpy(mf_sum,  "xxx", 4);
        strncpy(sf_sum,  "xxx", 4);
        strncpy(sf_sum2, "xxx", 4);
        strncpy(sf_sum3, "xxx", 4);

        /* Generate checksums */
        if ((opts & CHECK_MD5SUM) || (opts & CHECK_SHA1SUM)) {
            /* If it is a link, check if dest is valid */
#ifndef WIN32
            if (S_ISLNK(statbuf.st_mode)) {
                struct stat statbuf_lnk;
                if (stat(file_name, &statbuf_lnk) == 0) {
                    if (S_ISREG(statbuf_lnk.st_mode)) {
                        if (OS_MD5_SHA1_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, OS_BINARY) < 0) {
                            strncpy(mf_sum, "xxx", 4);
                            strncpy(sf_sum, "xxx", 4);
                        }
                    }
                }
            } else if (OS_MD5_SHA1_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, OS_BINARY) < 0)
#else
            if (OS_MD5_SHA1_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, OS_BINARY) < 0)
#endif
            {
                strncpy(mf_sum, "xxx", 4);
                strncpy(sf_sum, "xxx", 4);
            }

            if (opts & CHECK_SEECHANGES) {
                sha1s = 's';
            }
        } else {
            if (opts & CHECK_SEECHANGES) {
                sha1s = 'n';
            } else {
                sha1s = '-';
            }
        }

        buf = (char *) OSHash_Get(syscheck.fp, file_name);
        if (!buf) {
            char alert_msg[916 + 1];    /* to accommodate a long */
            alert_msg[916] = '\0';

            #ifndef WIN32
            if (opts & CHECK_SEECHANGES) {
                char *alertdump = seechanges_addfile(file_name);
                if (alertdump) {
                    free(alertdump);
                    alertdump = NULL;
                }
            }
            #endif

            snprintf(alert_msg, 916, "%c%c%c%c%c%c%ld:%d:%d:%d:%s:%s",
                     opts & CHECK_SIZE ? '+' : '-',
                     opts & CHECK_PERM ? '+' : '-',
                     opts & CHECK_OWNER ? '+' : '-',
                     opts & CHECK_GROUP ? '+' : '-',
                     opts & CHECK_MD5SUM ? '+' : '-',
                     sha1s,
                     opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                     opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                     opts & CHECK_OWNER ? (int)statbuf.st_uid : 0,
                     opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                     opts & CHECK_MD5SUM ? mf_sum : "xxx",
                     opts & CHECK_SHA1SUM ? sf_sum : "xxx");

            if (OSHash_Add(syscheck.fp, file_name, strdup(alert_msg)) <= 0) {
                merror("%s: ERROR: Unable to add file to db: %s", ARGV0, file_name);
            }

            /* Send the new checksum to the analysis server */
            alert_msg[916] = '\0';

            snprintf(alert_msg, 916, "%ld:%d:%d:%d:%s:%s %s",
                     opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                     opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                     opts & CHECK_OWNER ? (int)statbuf.st_uid : 0,
                     opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                     opts & CHECK_MD5SUM ? mf_sum : "xxx",
                     opts & CHECK_SHA1SUM ? sf_sum : "xxx",
                     file_name);
            send_syscheck_msg(alert_msg);
        } else {
            char alert_msg[OS_MAXSTR + 1];
            char c_sum[256 + 2];

            c_sum[0] = '\0';
            c_sum[256] = '\0';
            alert_msg[0] = '\0';
            alert_msg[OS_MAXSTR] = '\0';

            /* If it returns < 0, we have already alerted */
            if (c_read_file(file_name, buf, c_sum) < 0) {
                return (0);
            }

            if (strcmp(c_sum, buf + 6) != 0) {
                /* Send the new checksum to the analysis server */
                alert_msg[OS_MAXSTR] = '\0';
                #ifdef WIN32
                snprintf(alert_msg, 916, "%s %s", c_sum, file_name);
                #else
                char *fullalert = NULL;
                if (buf[5] == 's' || buf[5] == 'n') {
                    fullalert = seechanges_addfile(file_name);
                    if (fullalert) {
                        snprintf(alert_msg, OS_MAXSTR, "%s %s\n%s", c_sum, file_name, fullalert);
                        free(fullalert);
                        fullalert = NULL;
                    } else {
                        snprintf(alert_msg, 916, "%s %s", c_sum, file_name);
                    }
                } else {
                    snprintf(alert_msg, 916, "%s %s", c_sum, file_name);
                }
                #endif
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
        verbose("%s: file '%s %s'", ARGV0, file_name, mf_sum);
#endif
    } else {
#ifdef DEBUG
        verbose("%s: *** IRREG file: '%s'\n", ARGV0, file_name);
#endif
    }

    return (0);
}

static int read_dir(const char *dir_name, int opts, OSMatch *restriction)
{
    size_t dir_size;
    char f_name[PATH_MAX + 2];
    short is_nfs;

    DIR *dp;
    struct dirent *entry;

    f_name[PATH_MAX + 1] = '\0';

    /* Directory should be valid */
    if ((dir_name == NULL) || ((dir_size = strlen(dir_name)) > PATH_MAX)) {
        merror(NULL_ERROR, ARGV0);
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
            merror("%s: WARN: Error opening directory: '%s': %s ",
                   ARGV0, dir_name, strerror(errno));
        }
#else
        merror("%s: WARN: Error opening directory: '%s': %s ",
               ARGV0,
               dir_name,
               strerror(errno));
#endif /* WIN32 */
        return (-1);
    }

    /* Check for real time flag */
    if (opts & CHECK_REALTIME) {
#ifdef INOTIFY_ENABLED
        realtime_adddir(dir_name);
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
    int i = 0;

    __counter = 0;
    while (syscheck.dir[i] != NULL) {
        read_dir(syscheck.dir[i], syscheck.opts[i], syscheck.filerestrict[i]);
        i++;
    }

    return (0);
}

int create_db()
{
    int i = 0;

    /* Create store data */
    syscheck.fp = OSHash_Create();
    if (!syscheck.fp) {
        ErrorExit("%s: Unable to create syscheck database."
                  ". Exiting.", ARGV0);
    }

    if (!OSHash_setSize(syscheck.fp, 2048)) {
        merror(LIST_ERROR, ARGV0);
        return (0);
    }

    if ((syscheck.dir == NULL) || (syscheck.dir[0] == NULL)) {
        merror("%s: No directories to check.", ARGV0);
        return (-1);
    }

    merror("%s: INFO: Starting syscheck database (pre-scan).", ARGV0);

    /* Read all available directories */
    __counter = 0;
    do {
        if (read_dir(syscheck.dir[i], syscheck.opts[i], syscheck.filerestrict[i]) == 0) {
#ifdef WIN32
            if (syscheck.opts[i] & CHECK_REALTIME) {
                realtime_adddir(syscheck.dir[i]);
            }
#endif
        }
        i++;
    } while (syscheck.dir[i] != NULL);

#if defined (INOTIFY_ENABLED) || defined (WIN32)
    if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
        verbose("%s: INFO: Real time file monitoring started.", ARGV0);
    }
#endif
    merror("%s: INFO: Finished creating syscheck database (pre-scan "
           "completed).", ARGV0);
    return (0);
}

