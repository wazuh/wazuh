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

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>

#define REALTIME_MONITOR_FLAGS  IN_MODIFY|IN_ATTRIB|IN_MOVED_FROM|IN_MOVED_TO|IN_CREATE|IN_DELETE|IN_DELETE_SELF
#define REALTIME_EVENT_SIZE     (sizeof (struct inotify_event))
#define REALTIME_EVENT_BUFFER   (2048 * (REALTIME_EVENT_SIZE + 16))

void free_syscheck_dirtb_data(char *data) {
    if (!data) {
        return;
    }
    os_free(data);
}

/* Start real time monitoring using inotify */
// TODO: check differences between dirtb and fp of realtime
int realtime_start()
{

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    if (syscheck.realtime == NULL) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }
    syscheck.realtime->dirtb = OSHash_Create();
    if (syscheck.realtime->dirtb == NULL) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    OSHash_SetFreeDataPointer(syscheck.realtime->dirtb, (void (*)(void *))free_syscheck_dirtb_data);

    syscheck.realtime->fd = -1;

    syscheck.realtime->fd = inotify_init();
    if (syscheck.realtime->fd < 0) {
        merror(FIM_ERROR_INOTIFY_INITIALIZE);
        return (-1);
    }

    return (1);
}

/* Add a directory to real time checking */
// TODO: develop and test whodata mode
int realtime_adddir(const char *dir, __attribute__((unused)) int whodata)
{
        if (whodata && audit_thread_active) {

        // Save dir into saved rules list
        w_mutex_lock(&audit_mutex);

        if(!W_Vector_insert_unique(audit_added_dirs, dir)){
            mdebug1(FIM_WHODATA_NEWDIRECTORY, dir);
        }

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
                    merror(FIM_ERROR_NFS_INOTIFY, dir);
                	return(-1);
                }
                else {
                    mdebug2(FIM_SKIP_NFS, syscheck.skip_nfs, dir, is_nfs);
                }
            }

            wd = inotify_add_watch(syscheck.realtime->fd,
                                   dir,
                                   REALTIME_MONITOR_FLAGS);
            if (wd < 0) {
                merror(FIM_ERROR_INOTIFY_ADD_WATCH, dir, wd, errno);
            } else {
                char wdchar[32 + 1];
                wdchar[32] = '\0';
                snprintf(wdchar, 32, "%d", wd);
                // TODO: refactor the following code. Consider to move the char* above but careful with memleaks and invalid reads/writes
                /* Entry not present */
                if (!OSHash_Get_ex(syscheck.realtime->dirtb, wdchar)) {
                    char *ndir;
                    ndir = strdup(dir);
                    if (ndir == NULL) {
                        merror_exit(FIM_CRITICAL_ERROR_OUT_MEM);
                    }

                    if (!OSHash_Add_ex(syscheck.realtime->dirtb, wdchar, ndir)) {
                        merror_exit(FIM_CRITICAL_ERROR_OUT_MEM);
                    }
                    mdebug1(FIM_REALTIME_NEWDIRECTORY, ndir);
                } else {
                    char *ndir;
                    ndir = strdup(dir);
                    if (ndir == NULL) {
                        merror_exit(FIM_CRITICAL_ERROR_OUT_MEM);
                    }
                    if (OSHash_Update(syscheck.realtime->dirtb, wdchar, ndir) == 0) {
                        merror("Unable to update 'dirtb'. Dir not found: '%s'", ndir);
                        return (-1);
                    }
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
        merror(FIM_ERROR_REALTIME_READ_BUFFER);
    } else if (len > 0) {
        while (i < (size_t) len) {
            event = (struct inotify_event *) (void *) &buf[i];

            if (event->len) {
                char wdchar[32 + 1];
                char final_name[MAX_LINE + 1];

                wdchar[32] = '\0';
                final_name[MAX_LINE] = '\0';

                snprintf(wdchar, 32, "%d", event->wd);

                char *entry;
                char *it;
                // TODO: check another solution (maybe strlen()) or verify this one
                entry = (char *)OSHash_Get(syscheck.realtime->dirtb, wdchar);
                it = entry;
                while(*it) {
                    it++;
                }
                if(*(it - 1) == PATH_SEP) {
                    *(it - 1) = '\0';
                }
                snprintf(final_name, MAX_LINE, "%s/%s",
                         (char *)OSHash_Get(syscheck.realtime->dirtb, wdchar),
                         event->name);

                /* Need a sleep here to avoid triggering on vim
                * (and finding the file removed)
                */

                struct timeval timeout = {0, syscheck.rt_delay * 1000};
                select(0, NULL, NULL, NULL, &timeout);

                fim_process_event(final_name, FIM_REALTIME, NULL);
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
        mwarn(FIM_WARN_REALTIME_OVERFLOW);
    }

    if (dwerror != ERROR_SUCCESS) {
        LPSTR messageBuffer = NULL;
        LPSTR end;

        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwerror, 0, (LPTSTR) &messageBuffer, 0, NULL);

        if (end = strchr(messageBuffer, '\r'), end) {
            *end = '\0';
        }

        merror(FIM_ERROR_REALTIME_WINDOWS_CALLBACK, messageBuffer, dwerror);
        LocalFree(messageBuffer);

        return;
    }

    /* Get hash to parse the data */
    wdchar[260] = '\0';
    snprintf(wdchar, 260, "%s", (char*)overlap->Pointer);
    rtlocald = OSHash_Get(syscheck.realtime->dirtb, wdchar);
    if (rtlocald == NULL) {
        merror(FIM_ERROR_REALTIME_WINDOWS_CALLBACK_EMPTY);
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
            // TODO: Consider if we should change '\\' to '\'
            snprintf(final_path, MAX_LINE, "%s\\%s", rtlocald->dir, finalfile);

            /* Check the change */
            str_lowercase(final_path);
            fim_process_event(final_path, FIM_REALTIME, NULL);
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
    os_calloc(1, sizeof(rtfim), syscheck.realtime);

    syscheck.realtime->dirtb = OSHash_Create();
    if (syscheck.realtime->dirtb == NULL) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }
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
        merror(FIM_ERROR_REALTIME_DIRECTORYCHANGES, rtlocald->dir);
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

    if (!syscheck.wdata.whodata_setup) {
        syscheck.wdata.whodata_setup = 1;
    }
    int type;

    if (!syscheck.wdata.fd && whodata_audit_start()) {
        merror_exit(FIM_CRITICAL_ERROR_HASH_CREATE, "realtime_adddir()", strerror(errno));
    }

    // This parameter is used to indicate if the file is going to be monitored in Whodata mode,
    // regardless of it was checked in the initial configuration (WHODATA_ACTIVE in opts)
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
        mwarn(FIM_WARN_REALTIME_OPENFAIL, dir);
        syscheck.wdata.dirs_status[whodata - 1].object_type = WD_STATUS_UNK_TYPE;
        syscheck.wdata.dirs_status[whodata - 1].status &= ~WD_STATUS_EXISTS;
        return 0;
    }

    GetSystemTime(&syscheck.wdata.dirs_status[whodata - 1].last_check);
    if (set_winsacl(dir, whodata - 1)) {
        merror(FIM_ERROR_WHODATA_ADD_DIRECTORY, dir);
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
        merror(FIM_ERROR_REALTIME_MAXNUM_WATCHES, dir);
        w_mutex_unlock(&adddir_mutex);
        return (0);
    }

    /* Set key for hash */
    wdchar[260] = '\0';
    snprintf(wdchar, 260, "%s", dir);
    if(OSHash_Get_ex(syscheck.realtime->dirtb, wdchar)) {
        mdebug2(FIM_REALTIME_HASH_DUP, wdchar);
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
            merror(FIM_ERROR_REALTIME_ADD, dir);
            w_mutex_unlock(&adddir_mutex);
            return (0);
        }
        syscheck.realtime->fd++;
        w_mutex_unlock(&adddir_mutex);

        /* Add final elements to the hash */
        os_strdup(dir, rtlocald->dir);
        os_strdup(dir, rtlocald->overlap.Pointer);
        if (!OSHash_Add_ex(syscheck.realtime->dirtb, wdchar, rtlocald)) {
            merror_exit(FIM_CRITICAL_ERROR_OUT_MEM);
        }
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
    merror(FIM_ERROR_REALTIME_INITIALIZE);

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
