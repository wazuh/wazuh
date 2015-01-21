/* Copyright (C) 2009 Trend Micro Inc.
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

#ifdef WIN32
#define sleep(x) Sleep(x * 1000)
#define os_calloc(x,y,z) (z = calloc(x,y))?(void)1:ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno))
#define os_strdup(x,y) (y = strdup(x))?(void)1:ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno))
#endif

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>
#define OS_SIZE_6144    6144
#define OS_MAXSTR       OS_SIZE_6144    /* Size for logs, sockets, etc */
#else
#include "shared.h"
#endif

#include "hash_op.h"
#include "debug_op.h"
#include "syscheck.h"
#include "error_messages/error_messages.h"

/* Prototypes */
int realtime_checksumfile(const char *file_name) __attribute__((nonnull));


/* Checksum of the realtime file being monitored */
int realtime_checksumfile(const char *file_name)
{
    char *buf;

    buf = (char *) OSHash_Get(syscheck.fp, file_name);
    if (buf != NULL) {
        char c_sum[256 + 2];

        c_sum[0] = '\0';
        c_sum[255] = '\0';

        /* If it returns < 0, we have already alerted */
        if (c_read_file(file_name, buf, c_sum) < 0) {
            return (0);
        }

        if (strcmp(c_sum, buf + 6) != 0) {
            char *fullalert = NULL;
            char alert_msg[OS_MAXSTR + 1];

            alert_msg[OS_MAXSTR] = '\0';

            if (buf[5] == 's' || buf[5] == 'n') {
                fullalert = seechanges_addfile(file_name);
                if (fullalert) {
                    snprintf(alert_msg, OS_MAXSTR, "%s %s\n%s", c_sum, file_name, fullalert);
                    free(fullalert);
                    fullalert = NULL;
                } else {
                    snprintf(alert_msg, 912, "%s %s", c_sum, file_name);
                }
            } else {
                snprintf(alert_msg, 912, "%s %s", c_sum, file_name);
            }
            send_syscheck_msg(alert_msg);

            return (1);
        }
        return (0);
    }
    return (0);
}

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>

#define REALTIME_MONITOR_FLAGS  IN_MODIFY|IN_ATTRIB|IN_MOVED_FROM|IN_MOVED_TO|IN_CREATE|IN_DELETE|IN_DELETE_SELF
#define REALTIME_EVENT_SIZE     (sizeof (struct inotify_event))
#define REALTIME_EVENT_BUFFER   (2048 * (REALTIME_EVENT_SIZE + 16))

/* Start real time monitoring using inotify */
int realtime_start()
{
    verbose("%s: INFO: Initializing real time file monitoring (not started).", ARGV0);

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    if (syscheck.realtime == NULL) {
        ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
    }
    syscheck.realtime->dirtb = OSHash_Create();
    syscheck.realtime->fd = -1;

#ifdef INOTIFY_ENABLED
    syscheck.realtime->fd = inotify_init();
    if (syscheck.realtime->fd < 0) {
        merror("%s: ERROR: Unable to initialize inotify.", ARGV0);
        return (-1);
    }
#endif

    return (1);
}

/* Add a directory to real time checking */
int realtime_adddir(const char *dir)
{
    if (!syscheck.realtime) {
        realtime_start();
    }

    /* Check if it is ready to use */
    if (syscheck.realtime->fd < 0) {
        return (-1);
    } else {
        int wd = 0;

        wd = inotify_add_watch(syscheck.realtime->fd,
                               dir,
                               REALTIME_MONITOR_FLAGS);
        if (wd < 0) {
            merror("%s: ERROR: Unable to add directory to real time "
                   "monitoring: '%s'. %d %d", ARGV0, dir, wd, errno);
        } else {
            char wdchar[32 + 1];
            wdchar[32] = '\0';
            snprintf(wdchar, 32, "%d", wd);

            /* Entry not present */
            if (!OSHash_Get(syscheck.realtime->dirtb, wdchar)) {
                char *ndir;

                ndir = strdup(dir);
                if (ndir == NULL) {
                    ErrorExit("%s: ERROR: Out of memory. Exiting.", ARGV0);
                }

                OSHash_Add(syscheck.realtime->dirtb, wdchar, ndir);
                debug1("%s: DEBUG: Directory added for real time monitoring: "
                       "'%s'.", ARGV0, ndir);
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
        merror("%s: ERROR: Unable to read from real time buffer.", ARGV0);
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
                realtime_checksumfile(final_name);
            }

            i += REALTIME_EVENT_SIZE + event->len;
        }
    }

    return (0);
}

#elif defined(WIN32)
typedef struct _win32rtfim {
    HANDLE h;
    OVERLAPPED overlap;

    char *dir;
    TCHAR buffer[12288];
} win32rtfim;

int realtime_win32read(win32rtfim *rtlocald);

void CALLBACK RTCallBack(DWORD dwerror, DWORD dwBytes, LPOVERLAPPED overlap)
{
    int lcount;
    size_t offset = 0;
    char *ptfile;
    char wdchar[32 + 1];
    char final_path[MAX_LINE + 1];
    win32rtfim *rtlocald;
    PFILE_NOTIFY_INFORMATION pinfo;
    TCHAR finalfile[MAX_PATH];

    if (dwBytes == 0) {
        merror("%s: ERROR: real time call back called, but 0 bytes.", ARGV0);
        return;
    }

    if (dwerror != ERROR_SUCCESS) {
        merror("%s: ERROR: real time call back called, but error is set.",
               ARGV0);
        return;
    }

    /* Get hash to parse the data */
    wdchar[32] = '\0';
    snprintf(wdchar, 32, "%d", (int)overlap->Offset);
    rtlocald = OSHash_Get(syscheck.realtime->dirtb, wdchar);
    if (rtlocald == NULL) {
        merror("%s: ERROR: real time call back called, but hash is empty.",
               ARGV0);
        return;
    }

    do {
        pinfo = (PFILE_NOTIFY_INFORMATION) &rtlocald->buffer[offset];
        offset += pinfo->NextEntryOffset;

        lcount = WideCharToMultiByte(CP_ACP, 0, pinfo->FileName,
                                     pinfo->FileNameLength / sizeof(WCHAR),
                                     finalfile, MAX_PATH - 1, NULL, NULL);
        finalfile[lcount] = TEXT('\0');

        /* Change forward slashes to backslashes on finalfile */
        ptfile = strchr(finalfile, '\\');
        while (ptfile) {
            *ptfile = '/';
            ptfile++;

            ptfile = strchr(ptfile, '\\');
        }

        final_path[MAX_LINE] = '\0';
        snprintf(final_path, MAX_LINE, "%s/%s", rtlocald->dir, finalfile);

        /* Check the change */
        realtime_checksumfile(final_path);
    } while (pinfo->NextEntryOffset != 0);

    realtime_win32read(rtlocald);

    return;
}

int realtime_start()
{
    verbose("%s: INFO: Initializing real time file monitoring (not started).", ARGV0);

    os_calloc(1, sizeof(rtfim), syscheck.realtime);
    syscheck.realtime->dirtb = (void *)OSHash_Create();
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
                               FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                               0,
                               &rtlocald->overlap,
                               RTCallBack);
    if (rc == 0) {
        merror("%s: ERROR: Unable to set directory for monitoring: %s",
               ARGV0, rtlocald->dir);
        sleep(2);
    }

    return (0);
}

int realtime_adddir(const char *dir)
{
    char wdchar[32 + 1];
    win32rtfim *rtlocald;

    if (!syscheck.realtime) {
        realtime_start();
    }

    /* Maximum limit for realtime on Windows */
    if (syscheck.realtime->fd > 256) {
        merror("%s: ERROR: Unable to add directory to real time "
               "monitoring: '%s' - Maximum size permitted.", ARGV0, dir);
        return (0);
    }

    os_calloc(1, sizeof(win32rtfim), rtlocald);

    rtlocald->h = CreateFile(dir,
                             FILE_LIST_DIRECTORY,
                             FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL,
                             OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                             NULL);


    if (rtlocald->h == INVALID_HANDLE_VALUE ||
            rtlocald->h == NULL) {
        free(rtlocald);
        rtlocald = NULL;
        merror("%s: ERROR: Unable to add directory to real time "
               "monitoring: '%s'.", ARGV0, dir);
        return (0);
    }

    rtlocald->overlap.Offset = ++syscheck.realtime->fd;

    /* Set key for hash */
    wdchar[32] = '\0';
    snprintf(wdchar, 32, "%d", (int)rtlocald->overlap.Offset);

    if (OSHash_Get(syscheck.realtime->dirtb, wdchar)) {
        merror("%s: ERROR: Entry already in the real time hash: %s",
               ARGV0, wdchar);
        CloseHandle(rtlocald->overlap.hEvent);
        free(rtlocald);
        rtlocald = NULL;
        return (0);
    }

    /* Add final elements to the hash */
    os_strdup(dir, rtlocald->dir);
    OSHash_Add(syscheck.realtime->dirtb, strdup(wdchar), rtlocald);

    /* Add directory to be monitored */
    realtime_win32read(rtlocald);

    return (1);
}

#else /* !WIN32 */

int realtime_start()
{
    verbose("%s: ERROR: Unable to initalize real time file monitoring.", ARGV0);

    return (0);
}

int realtime_adddir(__attribute__((unused)) const char *dir)
{
    return (0);
}

int realtime_process()
{
    return (0);
}

#endif /* WIN32 */

