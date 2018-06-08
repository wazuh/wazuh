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
#include "string_op.h"

#ifdef WIN32
#define _WIN32_WINNT 0x600  // Windows Vista or later (must be included in the dll)
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <winevt.h>
#define sleep(x) Sleep(x * 1000)
#endif

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>
#define OS_SIZE_6144    6144
#define OS_MAXSTR       OS_SIZE_6144    /* Size for logs, sockets, etc */
#else
#include "shared.h"
#endif

#include "fs_op.h"
#include "hash_op.h"
#include "debug_op.h"
#include "syscheck.h"
#include "error_messages/error_messages.h"
#include "error_messages/debug_messages.h"

/* Prototypes */
int realtime_checksumfile(const char *file_name, whodata_evt *evt) __attribute__((nonnull(1)));
#ifdef WIN32
int set_winsacl(const char *dir);
int set_privilege(HANDLE hdle, LPCTSTR privilege, int enable);
int whodata_audit_start();
unsigned long WINAPI whodata_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, void *_void, EVT_HANDLE event);
#endif

/* Checksum of the realtime file being monitored */
int realtime_checksumfile(const char *file_name, whodata_evt *evt)
{
    char *buf;

    buf = (char *) OSHash_Get(syscheck.fp, file_name);
    if (buf != NULL) {
        char c_sum[256 + 2];

        c_sum[0] = '\0';
        c_sum[255] = '\0';

        /* If it returns < 0, we have already alerted */
        if (c_read_file(file_name, buf, c_sum) < 0) {
            // Update database
            snprintf(c_sum, sizeof(c_sum), "%.*s -1", SK_DB_NATTR, buf);
            free(buf);

            if (!OSHash_Update(syscheck.fp, file_name, strdup(c_sum))) {
                merror("Unable to update file to db: %s", file_name);
            }

            return (0);
        }

        if (strcmp(c_sum, buf + SK_DB_NATTR) != 0) {
            char alert_msg[OS_MAXSTR + 1];

            // Update database
            snprintf(alert_msg, sizeof(alert_msg), "%.*s%.*s", SK_DB_NATTR, buf, (int)strcspn(c_sum, " "), c_sum);

            if (!OSHash_Update(syscheck.fp, file_name, strdup(alert_msg))) {
                merror("Unable to update file to db: %s", file_name);
            }

            alert_msg[OS_MAXSTR] = '\0';
            char *fullalert = NULL;

            if (buf[6] == 's' || buf[6] == 'n') {
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

            free(buf);

            return (1);
        } else {
            mdebug2("Discarding '%s': checksum already reported.", file_name);
        }

        return (0);
    } else {
        /* New file */
        char *c;
        int i;
        buf = strdup(file_name);

        /* Find container directory */

        while (c = strrchr(buf, '/'), c && c != buf) {
            *c = '\0';

            for (i = 0; syscheck.dir[i]; i++) {
                if (evt && !(syscheck.opts[i] & CHECK_WHODATA)) {
                    continue;
                }
                if (strcmp(syscheck.dir[i], buf) == 0) {
                    mdebug1("Scanning new file '%s' with options for directory '%s'.", file_name, buf);
                    if (syscheck.opts[i] != CHECK_WHODATA) {
                        minfo("~~~~ read_dir() -> '%s' -> '%s'", file_name, syscheck.dir[i]);
                    }
                    read_dir(file_name, syscheck.opts[i], syscheck.filerestrict[i], evt);
                    break;
                }
            }

            if (syscheck.dir[i]) {
                break;
            }
        }

        free(buf);
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
    minfo("Initializing real time file monitoring engine.");

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    if (syscheck.realtime == NULL) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }
    syscheck.realtime->dirtb = OSHash_Create();
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
int realtime_adddir(const char *dir, int whodata)
{
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
            if (!OSHash_Get(syscheck.realtime->dirtb, wdchar)) {
                char *ndir;

                ndir = strdup(dir);
                if (ndir == NULL) {
                    merror_exit("Out of memory. Exiting.");
                }

                OSHash_Add(syscheck.realtime->dirtb, wdchar, ndir);
                mdebug1("Directory added for real time monitoring: '%s'.", ndir);
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

int run_whodata_scan() {
    return 0;
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
    char wdchar[260 + 1];
    char final_path[MAX_LINE + 1];
    win32rtfim *rtlocald;
    PFILE_NOTIFY_INFORMATION pinfo;
    TCHAR finalfile[MAX_PATH];

    if (dwBytes == 0) {
        merror("real time call back called, but 0 bytes.");
        return;
    }

    if (dwerror != ERROR_SUCCESS) {
        merror("real time call back called, but error is set.");
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
        realtime_checksumfile(final_path, NULL);
    } while (pinfo->NextEntryOffset != 0);

    realtime_win32read(rtlocald);

    return;
}

int realtime_start()
{
    minfo("Initializing real time file monitoring engine.");

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
        merror("Unable to set directory for monitoring: %s", rtlocald->dir);
        sleep(2);
    }

    return (0);
}

int realtime_adddir(const char *dir, int whodata)
{
    char wdchar[260 + 1];
    win32rtfim *rtlocald;

    if (!syscheck.realtime) {
        realtime_start();
    }

    if (whodata && !syscheck.wdata && whodata_audit_start()) {
        return -1;
    }

    /* Maximum limit for realtime on Windows */
    if (syscheck.realtime->fd > syscheck.max_fd_win_rt) {
        merror("Unable to add directory to real time monitoring: '%s' - Maximum size permitted.", dir);
        return (0);
    }

    /* Set key for hash */
    wdchar[260] = '\0';
    snprintf(wdchar, 260, "%s", dir);
    if(OSHash_Get(syscheck.realtime->dirtb, wdchar)) {
        mdebug2("Entry '%s' already exists in the RT hash.", wdchar);
    }
    else {
        if (!whodata) {
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

            /* Add final elements to the hash */
            os_strdup(dir, rtlocald->dir);
            os_strdup(dir, rtlocald->overlap.Pointer);
            OSHash_Add(syscheck.realtime->dirtb, wdchar, rtlocald);

            /* Add directory to be monitored */
            realtime_win32read(rtlocald);
        } else {
            if (set_winsacl(dir)) {
                merror("Unable to add directory to whodata monitoring: '%s'.", dir);
                return 0;
            }
        }
    }

    return (1);
}

int set_winsacl(const char *dir) {
    static LPCTSTR priv = "SeSecurityPrivilege";
	DWORD result = 0;
	PACL old_sacl = NULL, new_sacl = NULL;
	PSECURITY_DESCRIPTOR security_descriptor = NULL;
	EXPLICIT_ACCESS entry_access;
	HANDLE hdle;

    // Code for expand the obj dir

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hdle)) {
		merror("OpenProcessToken() failed. Error '%lu'.", GetLastError());
		return 1;
	}

	if (set_privilege(hdle, priv, TRUE)) {
		merror("The privilege could not be activated. Error: '%ld'.", GetLastError());
		return 1;
	}

	if (result = GetNamedSecurityInfo(dir, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &old_sacl, &security_descriptor), result != ERROR_SUCCESS) {
		merror("GetNamedSecurityInfo() failed. Error '%ld'", result);
        goto error;
	}

	// Configure the new ACE
	SecureZeroMemory(&entry_access, sizeof(EXPLICIT_ACCESS));
	entry_access.grfAccessPermissions = GENERIC_WRITE;
	entry_access.grfAccessMode = SET_AUDIT_SUCCESS;
	entry_access.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	entry_access.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
	entry_access.Trustee.ptstrName = "Everyone";

	// Create a new ACL with the ACE
	if (result = SetEntriesInAcl(1, &entry_access, old_sacl, &new_sacl), result != ERROR_SUCCESS) {
		merror("SetEntriesInAcl() failed. Error: '%lu'", result);
        goto error;
	}

	// Set the SACL
	if (result = SetNamedSecurityInfo((char *) dir, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, new_sacl), result != ERROR_SUCCESS) {
		merror("SetNamedSecurityInfo() failed. Error: '%lu'", result);
		goto error;
	}

	// Disable the privilege
	if (set_privilege(hdle, priv, 0)) {
		merror("Failed to disable the privilege. Error '%lu'.", GetLastError());
		return 1;
	}

	CloseHandle(hdle);
	return 0;
error:
    if (security_descriptor) {
        LocalFree((HLOCAL)security_descriptor);
    }

    if (new_sacl) {
        LocalFree((HLOCAL)new_sacl);
    }
    return 1;
}

int set_privilege(HANDLE hdle, LPCTSTR privilege, int enable) {
	TOKEN_PRIVILEGES tp;
	LUID pr_uid;

	// Get the privilege UID
	if (!LookupPrivilegeValue(NULL, privilege, &pr_uid)) {
		merror("Could not find the '%s' privilege. Error: %lu", privilege, GetLastError());
		return 1;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = pr_uid;

	if (enable) {
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	} else {
		tp.Privileges[0].Attributes = 0;
	}

    // Set the privilege to the process
	if (!AdjustTokenPrivileges(hdle, 0, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		merror("AdjustTokenPrivileges() failed. Error: '%lu'", GetLastError());
		return 1;
	}

    if (enable) {
        mdebug2("The '%s' privilege has been added.", privilege);
    } else {
        mdebug2("The '%s' privilege has been removed.", privilege);
    }

	return 0;
}

int run_whodata_scan() {
    if (!EvtSubscribe(NULL, NULL, L"Security", L"Event[(System/EventID = 4656 or System/EventID = 4663 or System/EventID = 4658)]", NULL, NULL, (EVT_SUBSCRIBE_CALLBACK)whodata_callback, EvtSubscribeToFutureEvents)) {
        merror("Event Channel subscription could not be made. Whodata scan is disabled.");
        return 1;
    }
    return 0;
}

unsigned long WINAPI whodata_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, void *_void, EVT_HANDLE event) {
    unsigned int retval;
    int result;
    unsigned long p_count = 0;
    unsigned long used_size;
    EVT_HANDLE context;
    PEVT_VARIANT buffer = NULL;
    whodata_evt *w_evt;
    short event_id;
    char *user_name;
    char *type;
    char *path;
    char *process_name;
    unsigned __int64 process_id;
    unsigned __int64 handle_id;
    unsigned int mask;
    static const wchar_t* event_fields[] = {
        L"Event/System/EventID",
        L"Event/EventData/Data[@Name='SubjectUserName']",
        L"Event/EventData/Data[@Name='ObjectType']",
        L"Event/EventData/Data[@Name='ObjectName']",
        L"Event/EventData/Data[@Name='ProcessName']",
        L"Event/EventData/Data[@Name='ProcessId']",
        L"Event/EventData/Data[@Name='HandleId']",
        L"Event/EventData/Data[@Name='AccessMask']"
    };
    static unsigned int fields_number = sizeof(event_fields) / sizeof(LPWSTR);
    UNREFERENCED_PARAMETER(_void);

    if (action == EvtSubscribeActionDeliver) {
        char hash_id[21];

        // Select the interesting fields
        if (context = EvtCreateRenderContext(fields_number, event_fields, EvtRenderContextValues), !context) {
            wprintf(L"\nError creating the context. Error %lu.", GetLastError());
            return 1;
        }

        // Extract the necessary memory size
        EvtRender(context, event, EvtRenderEventValues, 0, NULL, &used_size, &p_count);
        // We may be taking more memory than we need to
		buffer = (PEVT_VARIANT)malloc(used_size);

        if (!EvtRender(context, event, EvtRenderEventValues, used_size, buffer, &used_size, &p_count)) {
			merror("Error rendering the event. Error %lu.", GetLastError());
            retval = 1;
            goto clean;
		}

        if (fields_number != p_count) {
			merror("Invalid number of rendered parameters.");
            retval = 1;
            goto clean;
        }

        // Check types
        if ((buffer[0].Type != EvtVarTypeUInt16 && buffer[0].Type != EvtVarTypeNull)   ||
            (buffer[1].Type != EvtVarTypeString && buffer[1].Type != EvtVarTypeNull)   ||
            (buffer[2].Type != EvtVarTypeString && buffer[2].Type != EvtVarTypeNull)   ||
            (buffer[3].Type != EvtVarTypeString && buffer[3].Type != EvtVarTypeNull)   ||
            (buffer[4].Type != EvtVarTypeString && buffer[4].Type != EvtVarTypeNull)   ||
            (buffer[5].Type != EvtVarTypeHexInt64 && buffer[5].Type != EvtVarTypeNull) ||
            (buffer[6].Type != EvtVarTypeHexInt64 && buffer[6].Type != EvtVarTypeNull) ||
            (buffer[7].Type != EvtVarTypeHexInt32 && buffer[7].Type != EvtVarTypeNull)) {
            merror("Invalid parameter type after rendering the event.");
            retval = 1;
            goto clean;
        }

        event_id = buffer[0].Int16Val;
        user_name = convert_windows_string(buffer[1].XmlVal);
        type = convert_windows_string(buffer[2].XmlVal);
        path = convert_windows_string(buffer[3].XmlVal);
        process_name = convert_windows_string(buffer[4].XmlVal);
        process_id = buffer[5].UInt64Val;
        handle_id = buffer[6].UInt64Val;
        mask = buffer[7].UInt32Val;

        //minfo("~~~~event_id:'%d'|user_name:'%s'|type:'%s'|path:'%s'|process_name:'%s'|process_id:'%I64x'|handle_id:'%I64x'|mask:'%x'",
			//event_id, user_name, type, path, process_name, process_id, handle_id, mask);

        snprintf(hash_id, 21, "%llu", handle_id);

        switch(event_id) {
            // Open fd
            case 4656:
                if (!strcmp(type, "File")) {
                    os_calloc(1, sizeof(whodata_evt), w_evt);
                    w_evt->user_name = user_name;
                    w_evt->type = type;
                    w_evt->path = path;
                    w_evt->process_name = process_name;
                    w_evt->process_id = process_id;
                    w_evt->handle_id = handle_id;
                    w_evt->mask = 0;

                    user_name = NULL;
                    type = NULL;
                    path = NULL;
                    process_name = NULL;

                    if (result = OSHash_Add(syscheck.wdata->fd, hash_id, w_evt), result != 2) {
                        if (!result) {
                            merror("The event could not be added to the whodata hash table.");
                        } else if (result == 1) {
                            merror("The event could not be added to the whodata hash table because is duplicated.");
                        }
                        retval = 1;
                        goto clean;
                    }
                    minfo("OPEN '%ld'-'%s'-'%s'", GetCurrentThreadId(), hash_id, w_evt->path);
                }
            break;
            // Write fd
            case 4663:
                // Check if the mask is relevant
                if (mask) {
                    if (w_evt = OSHash_Get(syscheck.wdata->fd, hash_id), w_evt) {
                        w_evt->mask |= mask;
                        //minfo("UPDATED '%ld'-'%s'-'%s' to %x", GetCurrentThreadId(), hash_id, w_evt->path, w_evt->mask);
                    } else {
                        // The file was opened before Wazuh started Syscheck.
                    }
                }
            break;
            // Close fd
            case 4658:
                if (w_evt = OSHash_Delete(syscheck.wdata->fd, hash_id), w_evt) {
                    if (w_evt->mask) {
                        unsigned int mask = w_evt->mask;
                        // Valid for a file
                        minfo("'%s' modified. Flags: |write:%d|append:%d|. Mask: %d",
                            w_evt->path,
                            (mask & FILE_WRITE_DATA)? 1 : 0,
                            (mask & FILE_APPEND_DATA)? 1 : 0,
                            mask);
                        realtime_checksumfile(w_evt->path, w_evt);
                    }
                    free(w_evt->user_name);
                    free(w_evt->type);
                    free(w_evt->path);
                    free(w_evt->process_name);
                    free(w_evt);
                } else {
                    // The file was opened before Wazuh started Syscheck.
                }
            break;
            default:
                merror("Invalid EventID. The whodata cannot be extracted.");
                retval = 1;
                goto clean;
        }
    }
    retval = 0;
clean:
    free(user_name);
    free(type);
    free(path);
    free(process_name);
    if (buffer) {
        free(buffer);
    }
    return retval;
}

int whodata_audit_start() {
    os_calloc(1, sizeof(whodata), syscheck.wdata);
    if (syscheck.wdata->fd = OSHash_Create(), !syscheck.wdata->fd) {
        return 1;
    }
    return 0;
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

int realtime_adddir(__attribute__((unused)) const char *dir, int whodata)
{
    return (0);
}

int realtime_process()
{
    return (0);
}

#endif /* WIN32 */
