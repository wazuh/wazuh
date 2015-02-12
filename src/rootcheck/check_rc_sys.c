/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rootcheck.h"

/* Prototypes */
static int read_sys_file(const char *file_name, int do_read);
static int read_sys_dir(const char *dir_name, int do_read);

/* Global variables */
static int   _sys_errors;
static int   _sys_total;
static dev_t did;
static FILE *_wx;
static FILE *_ww;
static FILE *_suid;


static int read_sys_file(const char *file_name, int do_read)
{
    struct stat statbuf;

    _sys_total++;

#ifdef WIN32
    /* Check for NTFS ADS on Windows */
    os_check_ads(file_name);
#endif
    if (lstat(file_name, &statbuf) < 0) {
#ifndef WIN32
        char op_msg[OS_SIZE_1024 + 1];
        snprintf(op_msg, OS_SIZE_1024, "Anomaly detected in file '%s'. "
                 "Hidden from stats, but showing up on readdir. "
                 "Possible kernel level rootkit.",
                 file_name);
        notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
        _sys_errors++;
#endif
        return (-1);
    }

    /* If directory, read the directory */
    else if (S_ISDIR(statbuf.st_mode)) {
        /* Make Darwin happy. For some reason,
         * when I read /dev/fd, it goes forever on
         * /dev/fd5, /dev/fd6, etc.. weird
         */
        if (strstr(file_name, "/dev/fd") != NULL) {
            return (0);
        }

        /* Ignore the /proc directory (it has size 0) */
        if (statbuf.st_size == 0) {
            return (0);
        }

        return (read_sys_dir(file_name, do_read));
    }

    /* Check if the size from stats is the same as when we read the file */
    if (S_ISREG(statbuf.st_mode) && do_read) {
        char buf[OS_SIZE_1024];
        int fd;
        ssize_t nr;
        long int total = 0;

        fd = open(file_name, O_RDONLY, 0);

        /* It may not necessarily open */
        if (fd >= 0) {
            while ((nr = read(fd, buf, sizeof(buf))) > 0) {
                total += nr;
            }
            close(fd);

            if (strcmp(file_name, "/dev/bus/usb/.usbfs/devices") == 0) {
                /* Ignore .usbfs/devices */
            } else if (total != statbuf.st_size) {
                struct stat statbuf2;

                if ((lstat(file_name, &statbuf2) == 0) &&
                        (total != statbuf2.st_size) &&
                        (statbuf.st_size == statbuf2.st_size)) {
                    char op_msg[OS_SIZE_1024 + 1];
                    snprintf(op_msg, OS_SIZE_1024, "Anomaly detected in file "
                             "'%s'. File size doesn't match what we found. "
                             "Possible kernel level rootkit.",
                             file_name);
                    notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
                    _sys_errors++;
                }
            }
        }
    }

    /* If has OTHER write and exec permission, alert */
#ifndef WIN32
    if ((statbuf.st_mode & S_IWOTH) == S_IWOTH && S_ISREG(statbuf.st_mode)) {
        if ((statbuf.st_mode & S_IXUSR) == S_IXUSR) {
            if (_wx) {
                fprintf(_wx, "%s\n", file_name);
            }

            _sys_errors++;
        } else {
            if (_ww) {
                fprintf(_ww, "%s\n", file_name);
            }
        }

        if (statbuf.st_uid == 0) {
            char op_msg[OS_SIZE_1024 + 1];
#ifdef OSSECHIDS
            snprintf(op_msg, OS_SIZE_1024, "File '%s' is owned by root "
                     "and has written permissions to anyone.", file_name);
#else
            snprintf(op_msg, OS_SIZE_1024, "File '%s' is: \n"
                     "          - owned by root,\n"
                     "          - has write permissions to anyone.",
                     file_name);
#endif
            notify_rk(ALERT_SYSTEM_CRIT, op_msg);

        }
        _sys_errors++;
    } else if ((statbuf.st_mode & S_ISUID) == S_ISUID) {
        if (_suid) {
            fprintf(_suid, "%s\n", file_name);
        }
    }
#endif /* WIN32 */
    return (0);
}

static int read_sys_dir(const char *dir_name, int do_read)
{
    int i = 0;
    unsigned int entry_count = 0;
    int did_changed = 0;
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;

#ifndef WIN32
    const char *(dirs_to_doread[]) = { "/bin", "/sbin", "/usr/bin",
                                       "/usr/sbin", "/dev", "/etc",
                                       "/boot", NULL
                                     };
#endif

    if ((dir_name == NULL) || (strlen(dir_name) > PATH_MAX)) {
        merror("%s: Invalid directory given.", ARGV0);
        return (-1);
    }

    /* Ignore user-supplied list */
    if (rootcheck.ignore) {
        while (rootcheck.ignore[i]) {
            if (strcmp(dir_name, rootcheck.ignore[i]) == 0) {
                return (1);
            }
            i++;
        }
        i = 0;
    }

    /* Get the number of nodes. The total number on opendir must be the same. */
    if (lstat(dir_name, &statbuf) < 0) {
        return (-1);
    }

    /* Current device id */
    if (did != statbuf.st_dev) {
        if (did != 0) {
            did_changed = 1;
        }
        did = statbuf.st_dev;
    }

    if (!S_ISDIR(statbuf.st_mode)) {
        return (-1);
    }

#ifndef WIN32
    /* Check if the do_read is valid for this directory */
    while (dirs_to_doread[i]) {
        if (strcmp(dir_name, dirs_to_doread[i]) == 0) {
            do_read = 1;
            break;
        }
        i++;
    }
#else
    do_read = 0;
#endif

    /* Open the directory */
    dp = opendir(dir_name);
    if (!dp) {
        if ((strcmp(dir_name, "") == 0) &&
                (dp = opendir("/"))) {
            /* ok */
        } else {
            return (-1);
        }
    }

    /* Read every entry in the directory */
    while ((entry = readdir(dp)) != NULL) {
        char f_name[PATH_MAX + 2];
        struct stat statbuf_local;

        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            entry_count++;
            continue;
        }

        /* Create new file + path string */
        if (strcmp(dir_name, "/") == 0) {
            snprintf(f_name, PATH_MAX + 1, "/%s", entry->d_name);
        } else {
            snprintf(f_name, PATH_MAX + 1, "%s/%s", dir_name, entry->d_name);
        }

        /* Check if file is a directory */
        if (lstat(f_name, &statbuf_local) == 0) {
            /* On all the systems except Darwin, the
             * link count is only increased on directories
             */
#ifndef Darwin
            if (S_ISDIR(statbuf_local.st_mode))
#else
            if (S_ISDIR(statbuf_local.st_mode) ||
                    S_ISREG(statbuf_local.st_mode) ||
                    S_ISLNK(statbuf_local.st_mode))
#endif
            {
                entry_count++;
            }
        }

        /* Check every file against the rootkit database */
        for (i = 0; i <= rk_sys_count; i++) {
            if (!rk_sys_file[i]) {
                break;
            }

            if (strcmp(rk_sys_file[i], entry->d_name) == 0) {
                char op_msg[OS_SIZE_1024 + 1];

                _sys_errors++;
                snprintf(op_msg, OS_SIZE_1024, "Rootkit '%s' detected "
                         "by the presence of file '%s/%s'.",
                         rk_sys_name[i], dir_name, rk_sys_file[i]);

                notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            }
        }

        /* Ignore the /proc and /sys filesystems */
        if ((strcmp(f_name, "/proc") == 0) || (strcmp(f_name, "/sys") == 0)) {
            continue;
        }

        read_sys_file(f_name, do_read);
    }

    /* Entry count for directory different than the actual
     * link count from stats
     */
    if ((entry_count != (unsigned) statbuf.st_nlink) &&
            ((did_changed == 0) || ((entry_count + 1) != (unsigned) statbuf.st_nlink))) {
#ifndef WIN32
        struct stat statbuf2;
        char op_msg[OS_SIZE_1024 + 1];

        if ((lstat(dir_name, &statbuf2) == 0) &&
                (statbuf2.st_nlink != entry_count)) {
            snprintf(op_msg, OS_SIZE_1024, "Files hidden inside directory "
                     "'%s'. Link count does not match number of files "
                     "(%d,%d).",
                     dir_name, entry_count, (int)statbuf.st_nlink);

            /* Solaris /boot is terrible :) */
#ifdef SOLARIS
            if (strncmp(dir_name, "/boot", strlen("/boot")) != 0) {
                notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
                _sys_errors++;
            }
#elif defined(Darwin) || defined(FreeBSD)
            if (strncmp(dir_name, "/dev", strlen("/dev")) != 0) {
                notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
                _sys_errors++;
            }
#else
            notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            _sys_errors++;
#endif
        }
#endif /* WIN32 */
    }

    closedir(dp);

    return (0);
}

/* Scan the whole filesystem looking for possible issues */
void check_rc_sys(const char *basedir)
{
    char file_path[OS_SIZE_1024 + 1];

    debug1("%s: DEBUG: Starting on check_rc_sys", ARGV0);

    _sys_errors = 0;
    _sys_total = 0;
    did = 0; /* device id */

    snprintf(file_path, OS_SIZE_1024, "%s", basedir);

    /* Open output files */
    if (rootcheck.notify != QUEUE) {
        _wx = fopen("rootcheck-rw-rw-rw-.txt", "w");
        _ww = fopen("rootcheck-rwxrwxrwx.txt", "w");
        _suid = fopen("rootcheck-suid-files.txt", "w");
    } else {
        _wx = NULL;
        _ww = NULL;
        _suid = NULL;
    }

    if (rootcheck.scanall) {
        /* Scan the whole file system -- may be slow */
#ifndef WIN32
        snprintf(file_path, 3, "%s", "/");
#endif
        read_sys_dir(file_path, rootcheck.readall);
    } else {
        /* Scan only specific directories */
        int _i;
#ifndef WIN32
        const char *(dirs_to_scan[]) = {"/bin", "/sbin", "/usr/bin",
                                        "/usr/sbin", "/dev", "/lib",
                                        "/etc", "/root", "/var/log",
                                        "/var/mail", "/var/lib", "/var/www",
                                        "/usr/lib", "/usr/include",
                                        "/tmp", "/boot", "/usr/local",
                                        "/var/tmp", "/sys", NULL
                                       };

#else
        const char *(dirs_to_scan[]) = {"C:\\WINDOWS", "C:\\Program Files", NULL};
#endif

        _i = 0;
        while (dirs_to_scan[_i] != NULL) {
#ifndef WIN32
            snprintf(file_path, OS_SIZE_1024, "%s%s",
                     basedir,
                     dirs_to_scan[_i]);
            read_sys_dir(file_path, rootcheck.readall);

#else
            read_sys_dir(dirs_to_scan[_i], rootcheck.readall);
#endif

            _i++;
        }
    }

    if (_sys_errors == 0) {
        char op_msg[OS_SIZE_1024 + 1];
        snprintf(op_msg, OS_SIZE_1024, "No problem found on the system."
                 " Analyzed %d files.", _sys_total);
        notify_rk(ALERT_OK, op_msg);
    }

    else if (_wx && _ww && _suid) {
        char op_msg[OS_SIZE_1024 + 1];
        snprintf(op_msg, OS_SIZE_1024, "Check the following files for more "
                 "information:\n%s%s%s",
                 (ftell(_wx) == 0) ? "" :
                 "       rootcheck-rw-rw-rw-.txt (list of world writable files)\n",
                 (ftell(_ww) == 0) ? "" :
                 "       rootcheck-rwxrwxrwx.txt (list of world writtable/executable files)\n",
                 (ftell(_suid) == 0) ? "" :
                 "       rootcheck-suid-files.txt (list of suid files)");

        notify_rk(ALERT_SYSTEM_ERR, op_msg);
    }

    if (_wx) {
        if (ftell(_wx) == 0) {
            unlink("rootcheck-rw-rw-rw-.txt");
        }
        fclose(_wx);
    }

    if (_ww) {
        if (ftell(_ww) == 0) {
            unlink("rootcheck-rwxrwxrwx.txt");
        }
        fclose(_ww);
    }

    if (_suid) {
        if (ftell(_suid) == 0) {
            unlink("rootcheck-suid-files.txt");
        }
        fclose(_suid);
    }

    return;
}

