/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include "string_op.h"
#include "shared.h"
#include "syscheck.h"

volatile int audit_thread_active;
volatile int whodata_alerts;
volatile int audit_db_consistency_flag;

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>
#endif

#include "fs_op.h"
#include "hash_op.h"
#include "debug_op.h"
#include "syscheck.h"
#include "syscheck_op.h"

pthread_mutex_t adddir_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Prototypes */
int realtime_checksumfile(const char *file_name, whodata_evt *evt) __attribute__((nonnull(1)));

/* Checksum of the realtime file being monitored */
int realtime_checksumfile(const char *file_name, whodata_evt *evt)
{
    char *buf;
    syscheck_node *s_node;

    s_node = (syscheck_node *) OSHash_Get_ex(syscheck.fp, file_name);

    if (s_node != NULL) {
        char c_sum[OS_MAXSTR + 1];
        size_t c_sum_size;

        buf = s_node->checksum;
        c_sum[0] = '\0';
        c_sum[OS_MAXSTR] = '\0';


        // If it returns < 0, we've already alerted the deleted file
        if (c_read_file(file_name, buf, c_sum, evt) < 0) {

            return (0);
        }


        c_sum_size = strlen(buf + SK_DB_NATTR);
        if (strncmp(c_sum, buf + SK_DB_NATTR, c_sum_size)) {
            char alert_msg[OS_MAXSTR + 1];
            char wd_sum[OS_SIZE_6144 + 1];

            // Extract the whodata sum here to not include it in the hash table
            if (extract_whodata_sum(evt, wd_sum, OS_SIZE_6144)) {
                merror("The whodata sum for '%s' file could not be included in the alert as it is too large.", file_name);
            }

            /* Find tag position for the evaluated file name */
            int pos = find_dir_pos(file_name, 1, 0, 0);

            // Update database
            snprintf(alert_msg, sizeof(alert_msg), "%.*s%.*s", SK_DB_NATTR, buf, (int)strcspn(c_sum, " "), c_sum);
            s_node->checksum = strdup(alert_msg);

            alert_msg[OS_MAXSTR] = '\0';
            char *fullalert = NULL;

            if (buf[SK_DB_REPORT_CHANG] == '+') {
                fullalert = seechanges_addfile(file_name);
                if (fullalert) {
                    snprintf(alert_msg, OS_MAXSTR, "%s!%s:%s %s\n%s", c_sum, wd_sum, syscheck.tag[pos] ? syscheck.tag[pos] : "", file_name, fullalert);
                    free(fullalert);
                    fullalert = NULL;
                } else {
                    snprintf(alert_msg, OS_MAXSTR, "%s!%s:%s %s", c_sum, wd_sum, syscheck.tag[pos] ? syscheck.tag[pos] : "", file_name);
                }
            } else {
                snprintf(alert_msg, OS_MAXSTR, "%s!%s:%s %s", c_sum, wd_sum, syscheck.tag[pos] ? syscheck.tag[pos] : "", file_name);
            }

            send_syscheck_msg(alert_msg);
            struct timeval timeout = {0, syscheck.rt_delay * 1000};
            select(0, NULL, NULL, NULL, &timeout);

            free(buf);

            return (1);
        } else {
            mdebug2("Inotify event with same checksum for file: '%s'. Ignoring it.", file_name);
        }

        return (0);
    } else {
        /* New file */
        int pos;
#ifdef WIN_WHODATA
        if (evt) {
            pos = evt->dir_position;
        } else {
#endif
        pos = find_dir_pos(file_name, 1, 0, 0);
#ifdef WIN_WHODATA
        }
#endif
        if (pos >= 0) {
            mdebug1("Scanning new file '%s' with options for directory '%s'.", file_name, syscheck.dir[pos]);
            int diff = fim_find_child_depth(syscheck.dir[pos], file_name);
            int depth = syscheck.recursion_level[pos] - diff+1;

            if(check_path_type(file_name) == 2){
                depth = depth - 1;
            }
#ifndef WIN32
            struct stat statbuf;
            if (lstat(file_name, &statbuf) < 0) {
                mdebug2("Stat() function failed on: %s. File may have been deleted", file_name);
                return -1;
            }
            if S_ISLNK(statbuf.st_mode) {
                read_dir(file_name, pos, evt, depth, 1);
            } else
#endif
            {
                read_dir(file_name, pos, evt, depth, 0);
            }
        }

    }


    return (0);
}

/* Find container directory */
int find_dir_pos(const char *filename, int full_compare, int check_find, int deep_search) {
    char buf[PATH_MAX];
    int i;
    char *c;
    int retval = -1;
    int path_length = PATH_MAX;

    if (full_compare) {
        snprintf(buf, strlen(filename) + 2, "%s%c", filename, PATH_SEP);
    } else {
        snprintf(buf, strlen(filename) + 1, "%s", filename);
    }

    while (c = strrchr(buf, PATH_SEP), c && c != buf) {
        *c = '\0';

        for (i = 0; syscheck.dir[i]; i++) {
            if (check_find && !(syscheck.opts[i] & check_find)) {
                continue;
            }
            if (!strcmp(syscheck.dir[i], buf)) {
                // If deep_search is activated we will continue searching for parent directories
                if (deep_search) {
                    int buf_len = strlen(buf);
                    if (buf_len < path_length) {
                        path_length = buf_len;
                        retval = i;
                    }
                } else {
                    retval = i;
                }
                break;
            }
        }

        if (!deep_search && syscheck.dir[i]) {
            // The directory has been found
            break;
        }
    }

    return retval;
}

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>

#define REALTIME_MONITOR_FLAGS  IN_MODIFY|IN_ATTRIB|IN_MOVED_FROM|IN_MOVED_TO|IN_CREATE|IN_DELETE|IN_DELETE_SELF
#define REALTIME_EVENT_SIZE     (sizeof (struct inotify_event))
#define REALTIME_EVENT_BUFFER   (2048 * (REALTIME_EVENT_SIZE + 16))

/* Start real time monitoring using inotify */
int realtime_start()
{
    minfo("Initializing real time file monitoring engine.");

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    if (syscheck.realtime == NULL) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }
    syscheck.realtime->dirtb = OSHash_Create();
    if (syscheck.realtime->dirtb == NULL) merror_exit(MEM_ERROR, errno, strerror(errno));
    
    syscheck.realtime->fd = -1;

#ifdef INOTIFY_ENABLED
    syscheck.realtime->fd = inotify_init();
    if (syscheck.realtime->fd < 0) {
        merror("Unable to initialize inotify.");
        return (-1);
    }
#endif

    return (1);
}

/* Add a directory to real time checking */
int realtime_adddir(const char *dir, __attribute__((unused)) int whodata)
{
    if (whodata && audit_thread_active) {
        mdebug1("Monitoring with Audit: '%s'.", dir);

        // Save dir into saved rules list
        w_mutex_lock(&audit_mutex);
        W_Vector_insert(audit_added_dirs, dir);
        w_mutex_unlock(&audit_mutex);

    } else {

        if (!syscheck.realtime) {
            realtime_start();
        }

        /* Check if it is ready to use */
        if (syscheck.realtime->fd < 0) {
            return (-1);
        } else {
            int wd = 0;

            if(syscheck.skip_nfs) {
                short is_nfs = IsNFS(dir);
                if( is_nfs == 1 ) {
                    merror("%s NFS Directories do not support iNotify.", dir);
                	return(-1);
                }
                else {
                    mdebug2("syscheck.skip_nfs=%d, %s::is_nfs=%d", syscheck.skip_nfs, dir, is_nfs);
                }
            }

            wd = inotify_add_watch(syscheck.realtime->fd,
                                   dir,
                                   REALTIME_MONITOR_FLAGS);
            if (wd < 0) {
                merror("Unable to add directory to real time monitoring: '%s'. %d %d", dir, wd, errno);
            } else {
                char wdchar[32 + 1];
                wdchar[32] = '\0';
                snprintf(wdchar, 32, "%d", wd);

                /* Entry not present */
                if (!OSHash_Get_ex(syscheck.realtime->dirtb, wdchar)) {
                    char *ndir;

                    ndir = strdup(dir);
                    if (ndir == NULL) {
                        merror_exit("Out of memory. Exiting.");
                    }

                    if (!OSHash_Add_ex(syscheck.realtime->dirtb, wdchar, ndir)) merror_exit("Out of memory. Exiting.");
                    mdebug1("Directory added for real time monitoring: '%s'.", ndir);
                }
            }
        }
    }

    return (1);
}

/* Process events in the real time queue */
int realtime_process()
{
    ssize_t len;
    size_t i = 0;
    char buf[REALTIME_EVENT_BUFFER + 1];
    struct inotify_event *event;

    buf[REALTIME_EVENT_BUFFER] = '\0';

    len = read(syscheck.realtime->fd, buf, REALTIME_EVENT_BUFFER);
    if (len < 0) {
        merror("Unable to read from real time buffer.");
    } else if (len > 0) {
        while (i < (size_t) len) {
            event = (struct inotify_event *) (void *) &buf[i];

            if (event->len) {
                char wdchar[32 + 1];
                char final_name[MAX_LINE + 1];

                wdchar[32] = '\0';
                final_name[MAX_LINE] = '\0';

                snprintf(wdchar, 32, "%d", event->wd);

                snprintf(final_name, MAX_LINE, "%s/%s",
                         (char *)OSHash_Get(syscheck.realtime->dirtb, wdchar),
                         event->name);

                /* Need a sleep here to avoid triggering on vim
                * (and finding the file removed)
                */

                struct timeval timeout = {0, syscheck.rt_delay * 1000};
                select(0, NULL, NULL, NULL, &timeout);

                realtime_checksumfile(final_name, NULL);
            }

            i += REALTIME_EVENT_SIZE + event->len;
        }
    }

    return (0);
}

int run_whodata_scan(void) {
    return 0;
}


#elif defined(WIN32)
typedef struct _win32rtfim {
    HANDLE h;
    OVERLAPPED overlap;

    char *dir;
    TCHAR buffer[65536];
} win32rtfim;

int realtime_win32read(win32rtfim *rtlocald);

void CALLBACK RTCallBack(DWORD dwerror, DWORD dwBytes, LPOVERLAPPED overlap)
{
    int lcount;
    size_t offset = 0;
    char wdchar[260 + 1];
    char final_path[MAX_LINE + 1];
    win32rtfim *rtlocald;
    PFILE_NOTIFY_INFORMATION pinfo;
    TCHAR finalfile[MAX_PATH];

    if (dwBytes == 0) {
        mwarn("Real time process: no data. Probably buffer overflow.");
    }

    if (dwerror != ERROR_SUCCESS) {
        LPSTR messageBuffer = NULL;
        LPSTR end;

        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwerror, 0, (LPTSTR) &messageBuffer, 0, NULL);

        if (end = strchr(messageBuffer, '\r'), end) {
            *end = '\0';
        }

        merror("Real time process: %s (%lx).", messageBuffer, dwerror);
        LocalFree(messageBuffer);

        return;
    }

    /* Get hash to parse the data */
    wdchar[260] = '\0';
    snprintf(wdchar, 260, "%s", (char*)overlap->Pointer);
    rtlocald = OSHash_Get(syscheck.realtime->dirtb, wdchar);
    if (rtlocald == NULL) {
        merror("real time call back called, but hash is empty.");
        return;
    }

    if (dwBytes) {
        do {
            pinfo = (PFILE_NOTIFY_INFORMATION) &rtlocald->buffer[offset];
            offset += pinfo->NextEntryOffset;

            lcount = WideCharToMultiByte(CP_ACP, 0, pinfo->FileName,
                                         pinfo->FileNameLength / sizeof(WCHAR),
                                         finalfile, MAX_PATH - 1, NULL, NULL);
            finalfile[lcount] = TEXT('\0');

            final_path[MAX_LINE] = '\0';
            snprintf(final_path, MAX_LINE, "%s\\%s", rtlocald->dir, finalfile);

            /* Check the change */
            str_lowercase(final_path);
            realtime_checksumfile(final_path, NULL);
        } while (pinfo->NextEntryOffset != 0);
    }

    realtime_win32read(rtlocald);
    return;
}

void free_win32rtfim_data(win32rtfim *data) {
    if (!data) return;
    if (data->h != NULL && data->h != INVALID_HANDLE_VALUE) CloseHandle(data->h);
    if (data->overlap.Pointer) free(data->overlap.Pointer);
    if (data->dir) free(data->dir);
    free(data);
}

int realtime_start()
{
    minfo("Initializing real time file monitoring engine.");
    os_calloc(1, sizeof(rtfim), syscheck.realtime);
    
    syscheck.realtime->dirtb = OSHash_Create();
    if (syscheck.realtime->dirtb == NULL) merror_exit(MEM_ERROR, errno, strerror(errno));
    
    OSHash_SetFreeDataPointer(syscheck.realtime->dirtb, (void (*)(void *))free_win32rtfim_data);
    
    syscheck.realtime->fd = -1;
    syscheck.realtime->evt = CreateEvent(NULL, TRUE, FALSE, NULL);

    return (0);
}

int realtime_win32read(win32rtfim *rtlocald)
{
    int rc;

    rc = ReadDirectoryChangesW(rtlocald->h,
                               rtlocald->buffer,
                               sizeof(rtlocald->buffer) / sizeof(TCHAR),
                               TRUE,
                               FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE |
                               FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SECURITY,
                               0,
                               &rtlocald->overlap,
                               RTCallBack);
    if (rc == 0) {
        merror("Unable to set directory for monitoring: %s", rtlocald->dir);
        sleep(2);
    }

    return (0);
}

// In Windows the whodata parameter contains the directory position + 1 to be able to reference it
int realtime_adddir(const char *dir, int whodata)
{
    char wdchar[260 + 1];
    win32rtfim *rtlocald;

    if (whodata) {
#ifdef WIN_WHODATA
        int type;

        if (!syscheck.wdata.fd && whodata_audit_start()) {
            merror_exit("At realtime_adddir(): OSHash_Create() failed");
        }

        // This parameter is used to indicate if the file is going to be monitored in Whodata mode,
        // regardless of it was checked in the initial configuration (CHECK_WHODATA in opts)
        syscheck.wdata.dirs_status[whodata - 1].status |= WD_CHECK_WHODATA;
        syscheck.wdata.dirs_status[whodata - 1].status &= ~WD_CHECK_REALTIME;

        // Check if the file or directory exists
        if (type = check_path_type(dir), type == 2) {
            syscheck.wdata.dirs_status[whodata - 1].object_type = WD_STATUS_DIR_TYPE;
            syscheck.wdata.dirs_status[whodata - 1].status |= WD_STATUS_EXISTS;
        } else if (type == 1) {
            syscheck.wdata.dirs_status[whodata - 1].object_type = WD_STATUS_FILE_TYPE;
            syscheck.wdata.dirs_status[whodata - 1].status |= WD_STATUS_EXISTS;
        } else {
            mwarn("'%s' does not exist. Monitoring discarded.", dir);
            syscheck.wdata.dirs_status[whodata - 1].object_type = WD_STATUS_UNK_TYPE;
            syscheck.wdata.dirs_status[whodata - 1].status &= ~WD_STATUS_EXISTS;
            return 0;
        }

        GetSystemTime(&syscheck.wdata.dirs_status[whodata - 1].last_check);
        if (set_winsacl(dir, whodata - 1)) {
            merror("Unable to add directory to whodata monitoring: '%s'.", dir);
            return 0;
        }
        return 1;
#endif
    }

    if (!syscheck.realtime) {
        realtime_start();
    }

    w_mutex_lock(&adddir_mutex);

    /* Maximum limit for realtime on Windows */
    if (syscheck.realtime->fd > syscheck.max_fd_win_rt) {
        merror("Unable to add directory to real time monitoring: '%s' - Maximum size permitted.", dir);
        return (0);
    }

    /* Set key for hash */
    wdchar[260] = '\0';
    snprintf(wdchar, 260, "%s", dir);
    if(OSHash_Get_ex(syscheck.realtime->dirtb, wdchar)) {
        mdebug2("Entry '%s' already exists in the RT hash.", wdchar);
        w_mutex_unlock(&adddir_mutex);
    }
    else {
        os_calloc(1, sizeof(win32rtfim), rtlocald);

        rtlocald->h = CreateFile(dir,
                                FILE_LIST_DIRECTORY,
                                FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                                NULL);


        if (rtlocald->h == INVALID_HANDLE_VALUE || rtlocald->h == NULL) {
            free(rtlocald);
            rtlocald = NULL;
            merror("Unable to add directory to real time monitoring: '%s'.", dir);
            return (0);
        }
        syscheck.realtime->fd++;
        w_mutex_unlock(&adddir_mutex);

        /* Add final elements to the hash */
        os_strdup(dir, rtlocald->dir);
        os_strdup(dir, rtlocald->overlap.Pointer);
        if (!OSHash_Add_ex(syscheck.realtime->dirtb, wdchar, rtlocald)) merror_exit("Out of memory. Exiting.");

        /* Add directory to be monitored */
        realtime_win32read(rtlocald);
    }

    return (1);
}

#else /* !WIN32 */

int run_whodata_scan() {
    return 0;
}

int realtime_start()
{
    merror("Unable to initialize real time file monitoring.");

    return (0);
}

int realtime_adddir(__attribute__((unused)) const char *dir, __attribute__((unused))int whodata)
{
    return (0);
}

int realtime_process()
{
    return (0);
}

#endif /* WIN32 */
