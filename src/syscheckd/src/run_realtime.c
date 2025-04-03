/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "syscheck.h"

#include "fs_op.h"
#include "hash_op.h"
#include "debug_op.h"
#include "syscheck.h"
#include "syscheck_op.h"

#ifdef WAZUH_UNIT_TESTING
#ifdef WIN32
#include "../../unit_tests/wrappers/windows/fileapi_wrappers.h"
#include "../../unit_tests/wrappers/windows/handleapi_wrappers.h"
#include "../../unit_tests/wrappers/windows/synchapi_wrappers.h"
#include "../../unit_tests/wrappers/windows/winbase_wrappers.h"
#include "../../unit_tests/wrappers/windows/errhandlingapi_wrappers.h"
#endif
#endif

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>

#define REALTIME_MONITOR_FLAGS  IN_MODIFY|IN_ATTRIB|IN_MOVED_FROM|IN_MOVED_TO|IN_CREATE|IN_DELETE|IN_DELETE_SELF|IN_MOVE_SELF
#define REALTIME_EVENT_SIZE     (sizeof (struct inotify_event))
#define REALTIME_EVENT_BUFFER   (2048 * (REALTIME_EVENT_SIZE + 16))

int realtime_start() {
    OSListNode *node_it;
    os_calloc(1, sizeof(rtfim), syscheck.realtime);

    syscheck.realtime->dirtb = OSHash_Create();
    if (syscheck.realtime->dirtb == NULL) {
        merror(MEM_ERROR, errno, strerror(errno));
        goto error;
    }

    OSHash_SetFreeDataPointer(syscheck.realtime->dirtb, (void (*)(void *))free);

    syscheck.realtime->fd = inotify_init();
    if (syscheck.realtime->fd < 0) {
        merror(FIM_ERROR_INOTIFY_INITIALIZE);
        goto error;
    }

    return (0);

error:
    w_rwlock_wrlock(&syscheck.directories_lock);
    OSList_foreach(node_it, syscheck.directories) {
        directory_t *dir_it = node_it->data;

        if (dir_it->options & REALTIME_ACTIVE) {
            dir_it->options &= ~ REALTIME_ACTIVE;
            dir_it->options |= SCHEDULED_ACTIVE;
        }
    }
    w_rwlock_unlock(&syscheck.directories_lock);
    return -1;
}

/* Add a directory to real time checking */
int fim_add_inotify_watch(const char *dir, const directory_t *configuration) {
    /* Check if it is ready to use */
    w_mutex_lock(&syscheck.fim_realtime_mutex);

    if (syscheck.realtime->fd < 0) {
        w_mutex_unlock(&syscheck.fim_realtime_mutex);
        return (-1);
    } else {
        int wd = 0;

        wd =
        inotify_add_watch(syscheck.realtime->fd, dir,
                          (0 == (configuration->options & CHECK_FOLLOW)) ? (REALTIME_MONITOR_FLAGS | IN_DONT_FOLLOW) :
                                                                           REALTIME_MONITOR_FLAGS);
        if (wd < 0) {
            if (errno == 28) {
                merror(FIM_ERROR_INOTIFY_ADD_MAX_REACHED, dir, wd, errno);
            }
            else {
                mdebug1(FIM_INOTIFY_ADD_WATCH, dir, wd, errno, strerror(errno));
            }
        }
        else {
            char wdchar[33];
            char *data;
            int retval;
            snprintf(wdchar, 33, "%d", wd);
            os_strdup(dir, data);
            if (!OSHash_Get_ex(syscheck.realtime->dirtb, wdchar)) {
                if (retval = OSHash_Add_ex(syscheck.realtime->dirtb, wdchar, data), retval == 0) {
                    os_free(data);
                    merror_exit(FIM_CRITICAL_ERROR_OUT_MEM);
                }
                else if (retval == 1) {
                    mdebug2(FIM_REALTIME_HASH_DUP, data);
                    os_free(data);
                }

                mdebug2(FIM_REALTIME_NEWDIRECTORY, dir);
            }
            else {
                if (retval = OSHash_Update_ex(syscheck.realtime->dirtb, wdchar, data), retval == 0) {
                    merror("Unable to update 'dirtb'. Directory not found: '%s'", data);
                    os_free(data);
                    w_mutex_unlock(&syscheck.fim_realtime_mutex);
                    return (-1);
                }
            }
        }
    }
    w_mutex_unlock(&syscheck.fim_realtime_mutex);

    return 1;
}

/* Add a directory to real time checking */
int realtime_adddir(const char *dir, directory_t *configuration) {
    int mode = FIM_MODE(configuration->options);

#ifdef ENABLE_AUDIT
    if ((mode == FIM_WHODATA) && syscheck.whodata_provider == AUDIT_PROVIDER) {
        add_whodata_directory(dir);
        return 1;
    }
#endif

    if (mode == FIM_REALTIME) {
        return fim_add_inotify_watch(dir, configuration);
    }

    // Nothing to do here
    return 1;
}

void fim_realtime_delete_watches(const directory_t *configuration) {
    OSHashNode *hash_node;
    char *data;
    W_Vector * watch_to_delete;
    unsigned int inode_it = 0;
    int deletion_it = 0;
    directory_t *watch_conf;

    assert(configuration != NULL);

    w_mutex_lock(&syscheck.fim_realtime_mutex);
    if (syscheck.realtime == NULL || syscheck.realtime->dirtb == NULL) {
        w_mutex_unlock(&syscheck.fim_realtime_mutex);
        return;
    }

    watch_to_delete = W_Vector_init(1024);

    if (watch_to_delete == NULL) {
        w_mutex_unlock(&syscheck.fim_realtime_mutex);
        return;
    }

    for (hash_node = OSHash_Begin(syscheck.realtime->dirtb, &inode_it); hash_node;
         hash_node = OSHash_Next(syscheck.realtime->dirtb, &inode_it, hash_node)) {
        data = hash_node->data;
        if (data == NULL) {
            continue;
        }
        watch_conf = fim_configuration_directory(data);

        if (configuration == watch_conf) {
            W_Vector_insert(watch_to_delete, hash_node->key);
            deletion_it++;
        }
    }

    deletion_it--;
    while(deletion_it >= 0) {
        const char * wd_str = W_Vector_get(watch_to_delete, deletion_it);
        if (wd_str == NULL) {
            continue;
        }

        inotify_rm_watch(syscheck.realtime->fd, atol(wd_str));
        free(OSHash_Delete_ex(syscheck.realtime->dirtb, wd_str));
        deletion_it--;
    }

    W_Vector_free(watch_to_delete);

    w_mutex_unlock(&syscheck.fim_realtime_mutex);
    return;
}

/* Process events in the real time queue */
void realtime_process() {
    ssize_t len;
    char buf[REALTIME_EVENT_BUFFER + 1];
    struct inotify_event *event;

    buf[REALTIME_EVENT_BUFFER] = '\0';

    w_mutex_lock(&syscheck.fim_realtime_mutex);
    len = read(syscheck.realtime->fd, buf, REALTIME_EVENT_BUFFER);
    w_mutex_unlock(&syscheck.fim_realtime_mutex);

    if (len < 0) {
        merror(FIM_ERROR_REALTIME_READ_BUFFER);
        return;
    }

    if (len == 0) {
        // Nothing to do
        return;
    }

    rb_tree * tree = rbtree_init();
    for (size_t i = 0; i < (size_t) len; i += REALTIME_EVENT_SIZE + event->len) {
        char wdchar[33];
        char final_name[MAX_LINE + 1];
        char *entry;
        final_name[MAX_LINE] = '\0';
        event = (struct inotify_event *) (void *) &buf[i];

        if (event->wd == -1 && event->mask == IN_Q_OVERFLOW) {
            mwarn("Real-time inotify kernel queue is full. Some events may be lost. Next scheduled scan will recover lost data.");
            fim_realtime_set_queue_overflow(true);
            send_log_msg("ossec: Real-time inotify kernel queue is full. Some events may be lost. Next scheduled scan will recover lost data.");
            continue;
        }

        snprintf(wdchar, 33, "%d", event->wd);

        w_mutex_lock(&syscheck.fim_realtime_mutex);
        // The configured paths can end at / or not, we must check it.
        entry = (char *) OSHash_Get_ex(syscheck.realtime->dirtb, wdchar);

        if (entry == NULL) {
            w_mutex_unlock(&syscheck.fim_realtime_mutex);
            continue;
        }

        // Check file entries with realtime
        if (event->len == 0) {
            snprintf(final_name, MAX_LINE, "%s", entry);
        } else {
            // Check directories entries with realtime
            if (entry[strlen(entry) - 1] == PATH_SEP) {
                snprintf(final_name, MAX_LINE, "%s%s", entry, event->name);
            } else {
                snprintf(final_name, MAX_LINE, "%s/%s", entry, event->name);
            }
        }

        if (rbtree_insert(tree, final_name, NULL) == NULL) {
            mdebug2("Duplicate event in real-time buffer: %s", final_name);
        }

        switch(event->mask) {
        case IN_MOVE_SELF:
            delete_subdirectories_watches(entry);
            // fall through
        case IN_DELETE_SELF:
            mdebug2(FIM_INOTIFY_WATCH_DELETED, entry);
            free(OSHash_Delete_ex(syscheck.realtime->dirtb, wdchar));

            break;
        }
        w_mutex_unlock(&syscheck.fim_realtime_mutex);
    }

    char ** paths = rbtree_keys(tree);

    for (int i = 0; paths[i] != NULL; i++) {
        w_rwlock_rdlock(&syscheck.directories_lock);
        fim_realtime_event(paths[i]);
        w_rwlock_unlock(&syscheck.directories_lock);
    }

    free_strarray(paths);
    rbtree_destroy(tree);
}

int realtime_update_watch(const char *wd, const char *dir) {
    int old_wd, new_wd;
    char wdchar[33];
    char *data;
    int retval;
    const directory_t *configuration;

    if (syscheck.realtime->fd < 0) {
        return -1;
    }

    configuration = fim_configuration_directory(dir);

    if (configuration == NULL) {
        mdebug2(FIM_CONFIGURATION_NOTFOUND, "file", dir);
        inotify_rm_watch(syscheck.realtime->fd, atoi(wd));
        free(OSHash_Delete_ex(syscheck.realtime->dirtb, wd));
        return 0;
    }

    old_wd = atoi(wd);
    new_wd =
    inotify_add_watch(syscheck.realtime->fd, dir,
                      (configuration->options & CHECK_FOLLOW) == 0 ? (REALTIME_MONITOR_FLAGS | IN_DONT_FOLLOW) :
                                                                     REALTIME_MONITOR_FLAGS);

    if (new_wd < 0) {
        if (errno == ENOSPC) {
            merror(FIM_ERROR_INOTIFY_ADD_MAX_REACHED, dir, new_wd, errno);
            return -1;
        } else if (errno == ENOENT) {
            mdebug2("Removing watch on non existent directory '%s'", dir);
            inotify_rm_watch(syscheck.realtime->fd, old_wd);
            free(OSHash_Delete_ex(syscheck.realtime->dirtb, wd));
            return 0;
        } else {
            mdebug1(FIM_INOTIFY_ADD_WATCH, dir, new_wd, errno, strerror(errno));
            return -1;
        }
    }

    if (new_wd == old_wd) {
        return -1;
    }

    snprintf(wdchar, 33, "%d", new_wd);
    os_strdup(dir, data);

    // Remove the old wd entry
    free(OSHash_Delete_ex(syscheck.realtime->dirtb, wd));

    if (!OSHash_Get_ex(syscheck.realtime->dirtb, wdchar)) {
        if (retval = OSHash_Add_ex(syscheck.realtime->dirtb, wdchar, data), retval == 0) {
            os_free(data);
            merror(FIM_CRITICAL_ERROR_OUT_MEM);
            return -1;
        }

        mdebug2(FIM_REALTIME_NEWDIRECTORY, data);
    } else if (retval = OSHash_Update_ex(syscheck.realtime->dirtb, wdchar, data), retval == 0) {
        merror("Unable to update 'dirtb'. Directory not found: '%s'", data);
        os_free(data);
    }
    return 0;
}

void delete_subdirectories_watches(char *dir) {
    OSHashNode *hash_node;
    char *data;
    unsigned int inode_it = 0;
    char *dir_slash = NULL;
    int dir_len = strlen(dir) + 1;


    // If the directory already ends with an slash, there is no need for adding an extra one
    if (dir[dir_len - 1] != '/') {
        os_calloc(dir_len + 2, sizeof(char), dir_slash);  // Length of dir plus an extra slash

        // Copy the content of dir into dir_slash and add an extra slash
        snprintf(dir_slash, dir_len + 2, "%s/", dir);
    }
    else {
        os_calloc(dir_len, sizeof(char), dir_slash);
        snprintf(dir_slash, dir_len, "%s", dir);
    }

    if(syscheck.realtime->fd) {
        hash_node = OSHash_Begin(syscheck.realtime->dirtb, &inode_it);

        while(hash_node) {
            data = hash_node->data;

            if (strncmp(dir_slash, data, strlen(dir_slash)) == 0) {
                char * data_node = OSHash_Delete_ex(syscheck.realtime->dirtb, hash_node->key);
                mdebug2(FIM_INOTIFY_WATCH_DELETED, data);
                os_free(data_node);

                /*
                    If an element of the hash table is deleted, it needs to start from the
                    beginning again to prevent going out of boundaries.
                */
                hash_node = OSHash_Begin(syscheck.realtime->dirtb, &inode_it);
                continue;
            }

            hash_node = OSHash_Next(syscheck.realtime->dirtb, &inode_it, hash_node);
        }
    }

    os_free(dir_slash);
}

void realtime_sanitize_watch_map() {
    OSHashNode *hash_node;
    unsigned int inode_it = 0;
    struct timespec start;
    struct timespec end;

    w_rwlock_rdlock(&syscheck.directories_lock);
    w_mutex_lock(&syscheck.fim_realtime_mutex);

    gettime(&start);
    hash_node = OSHash_Begin(syscheck.realtime->dirtb, &inode_it);

    while (hash_node) {
        if (realtime_update_watch(hash_node->key, hash_node->data) == 0) {
            hash_node = OSHash_Begin(syscheck.realtime->dirtb, &inode_it);
            continue;
        }

        hash_node = OSHash_Next(syscheck.realtime->dirtb, &inode_it, hash_node);
    }

    gettime(&end);
    mdebug2("Time spent sanitizing wd hashmap: %.3f seconds", time_diff(&start, &end));

    w_mutex_unlock(&syscheck.fim_realtime_mutex);
    w_rwlock_unlock(&syscheck.directories_lock);
}

#elif defined(WIN32)

void free_win32rtfim_data(win32rtfim *data);
int realtime_win32read(win32rtfim *rtlocald);
int fim_check_realtime_directory(win32rtfim *rtlocald);

void CALLBACK RTCallBack(DWORD dwerror, DWORD dwBytes, LPOVERLAPPED overlap)
{
    int lcount;
    size_t offset = 0;
    char wdchar[260 + 1] = {0};
    char final_path[MAX_LINE + 1];
    win32rtfim *rtlocald;
    PFILE_NOTIFY_INFORMATION pinfo;
    TCHAR finalfile[MAX_PATH];

    memset(final_path, '\0', MAX_LINE + 1);

    if (dwerror != ERROR_SUCCESS) {
        LPSTR messageBuffer = NULL;
        LPSTR end;

        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwerror, 0, (LPTSTR) &messageBuffer, 0, NULL);

        if (messageBuffer) {
            if (end = strchr(messageBuffer, '\r'), end) {
                *end = '\0';
            }

            merror(FIM_ERROR_REALTIME_WINDOWS_CALLBACK, messageBuffer, dwerror);
            LocalFree(messageBuffer);
        }
        return;
    }

    /* Get hash to parse the data */
    w_rwlock_rdlock(&syscheck.directories_lock);
    w_mutex_lock(&syscheck.fim_realtime_mutex);
    snprintf(wdchar, 260, "%s", (char*)overlap->hEvent);
    rtlocald = OSHash_Get_ex(syscheck.realtime->dirtb, wdchar);
    if (rtlocald == NULL) {
        merror(FIM_ERROR_REALTIME_WINDOWS_CALLBACK_EMPTY);
        w_mutex_unlock(&syscheck.fim_realtime_mutex);
        w_rwlock_unlock(&syscheck.directories_lock);
        return;
    }

    if(rtlocald->watch_status == FIM_RT_HANDLE_CLOSED) {
        rtlocald = OSHash_Delete_ex(syscheck.realtime->dirtb, wdchar);
        free_win32rtfim_data(rtlocald);
        mdebug2(FIM_REALTIME_CALLBACK, wdchar);
        w_mutex_unlock(&syscheck.fim_realtime_mutex);
        w_rwlock_unlock(&syscheck.directories_lock);
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

            if (rtlocald->dir) {
                if (rtlocald->dir[strlen(rtlocald->dir) - 1] == PATH_SEP) {
                    snprintf(final_path, MAX_LINE, "%s%s",
                            rtlocald->dir,
                            finalfile);
                } else {
                    snprintf(final_path, MAX_LINE, "%s\\%s",
                            rtlocald->dir,
                            finalfile);
                }
            }
            str_lowercase(final_path);

            directory_t *index = fim_configuration_directory(wdchar);
            directory_t *file_index = fim_configuration_directory(final_path);

            if (index == file_index) {
                /* Check the change */
                fim_realtime_event(final_path);
            }

        } while (pinfo->NextEntryOffset != 0);
    }
    else {
        mwarn(FIM_WARN_REALTIME_OVERFLOW);
    }

    realtime_win32read(rtlocald);
    w_mutex_unlock(&syscheck.fim_realtime_mutex);
    w_rwlock_unlock(&syscheck.directories_lock);
    return;
}

void free_win32rtfim_data(win32rtfim *data) {
    if (!data) return;
    os_free(data->overlap.hEvent);
    os_free(data->dir);
    os_free(data);
}

static unsigned int _get_realtime_watches() {
    if (syscheck.realtime != NULL) {
        return OSHash_Get_Elem_ex(syscheck.realtime->dirtb);
    }
    return 0;
}

unsigned int get_realtime_watches() {
    unsigned int n_elements = 0;

    w_mutex_lock(&syscheck.fim_realtime_mutex);
    n_elements = _get_realtime_watches();
    w_mutex_unlock(&syscheck.fim_realtime_mutex);

    return n_elements;
}

int realtime_start() {
    os_calloc(1, sizeof(rtfim), syscheck.realtime);

    syscheck.realtime->dirtb = OSHash_Create();
    if (syscheck.realtime->dirtb == NULL) {
        OSListNode *node_it;

        merror(MEM_ERROR, errno, strerror(errno));

        w_rwlock_wrlock(&syscheck.directories_lock);
        OSList_foreach(node_it, syscheck.directories) {
            directory_t *dir_it = (directory_t *)node_it->data;
            if (dir_it->options & REALTIME_ACTIVE) {
                dir_it->options &= ~ REALTIME_ACTIVE;
                dir_it->options |= SCHEDULED_ACTIVE;
            }
        }
        w_rwlock_unlock(&syscheck.directories_lock);
        return(-1);
    }
    OSHash_SetFreeDataPointer(syscheck.realtime->dirtb, (void (*)(void *))free_win32rtfim_data);

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

    return rc;
}

int realtime_adddir(const char *dir, directory_t *configuration) {
    char wdchar[260 + 1];
    win32rtfim *rtlocald;

    assert(configuration != NULL);

    if (FIM_MODE(configuration->options) == FIM_WHODATA) {
#ifdef WIN_WHODATA

        int type;

        if (!syscheck.wdata.fd && whodata_audit_start()) {
            merror_exit(FIM_CRITICAL_DATA_CREATE, "whodata file descriptors");
        }

        // This parameter is used to indicate if the file is going to be monitored in Whodata mode,
        // regardless of it was checked in the initial configuration (WHODATA_ACTIVE in opts)
        configuration->dirs_status.status |= WD_CHECK_WHODATA;
        configuration->dirs_status.status &= ~WD_CHECK_REALTIME;

        // Check if the file or directory exists
        if (type = check_path_type(dir), type == 2) {
            configuration->dirs_status.object_type = WD_STATUS_DIR_TYPE;
            configuration->dirs_status.status |= WD_STATUS_EXISTS;
        } else if (type == 1) {
            configuration->dirs_status.object_type = WD_STATUS_FILE_TYPE;
            configuration->dirs_status.status |= WD_STATUS_EXISTS;
        } else {
            mdebug2(FIM_WARN_REALTIME_OPENFAIL, dir);

            configuration->dirs_status.object_type = WD_STATUS_UNK_TYPE;
            configuration->dirs_status.status &= ~WD_STATUS_EXISTS;
            return 0;
        }

        GetSystemTime(&configuration->dirs_status.last_check);
        if (set_winsacl(dir, configuration)) {
            merror(FIM_ERROR_WHODATA_ADD_DIRECTORY, dir);
            return -2;
        }

        return 1;
#endif
    }
    w_mutex_lock(&syscheck.fim_realtime_mutex);

    /* Set key for hash */
    wdchar[260] = '\0';
    snprintf(wdchar, 260, "%s", dir);

    rtlocald = OSHash_Get_ex(syscheck.realtime->dirtb, wdchar);
    if(rtlocald != NULL) {
        if (!w_directory_exists(rtlocald->dir)) {
            if (rtlocald->watch_status == FIM_RT_HANDLE_CLOSED) {
                mdebug2(FIM_REALTIME_CALLBACK, rtlocald->dir);
                rtlocald = OSHash_Delete_ex(syscheck.realtime->dirtb, rtlocald->dir);
                free_win32rtfim_data(rtlocald);
            } else if (rtlocald->h != NULL && rtlocald->h != INVALID_HANDLE_VALUE) {
                CloseHandle(rtlocald->h);
                rtlocald->watch_status = FIM_RT_HANDLE_CLOSED;
            }
        }

        w_mutex_unlock(&syscheck.fim_realtime_mutex);
        return 1;
    }

    /* Maximum limit for realtime on Windows */
    if (_get_realtime_watches() >= syscheck.max_fd_win_rt) {
        mdebug1(FIM_REALTIME_MAXNUM_WATCHES, dir);
        w_mutex_unlock(&syscheck.fim_realtime_mutex);
        return 0;
    }

    os_calloc(1, sizeof(win32rtfim), rtlocald);

    rtlocald->h = CreateFile(dir, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                             OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);

    if (rtlocald->h == INVALID_HANDLE_VALUE || rtlocald->h == NULL) {
        os_free(rtlocald);
        mdebug2(FIM_REALTIME_ADD, dir);

        w_mutex_unlock(&syscheck.fim_realtime_mutex);
        return 0;
    }

    /* Add final elements to the hash */
    os_strdup(dir, rtlocald->dir);
    os_strdup(dir, rtlocald->overlap.hEvent);
    rtlocald->watch_status = FIM_RT_HANDLE_OPEN;

    /* Add directory to be monitored */
    if(realtime_win32read(rtlocald) == 0) {
        DWORD last_error = GetLastError();
        mdebug1(FIM_REALTIME_DIRECTORYCHANGES, rtlocald->dir, last_error, win_strerror(last_error));
        CloseHandle(rtlocald->h);
        rtlocald->watch_status = FIM_RT_HANDLE_CLOSED;
        if (!w_directory_exists(rtlocald->dir)) {
            mwarn(FIM_REALTIME_FILE_NOT_SUPPORTED, rtlocald->dir);
            configuration->options &= ~REALTIME_ACTIVE;
            configuration->options |= SCHEDULED_ACTIVE;
        }
        free_win32rtfim_data(rtlocald);

        w_mutex_unlock(&syscheck.fim_realtime_mutex);
        return 0;
    }

    if (!OSHash_Add_ex(syscheck.realtime->dirtb, wdchar, rtlocald)) {
        merror_exit(FIM_CRITICAL_ERROR_OUT_MEM);
    }

    mdebug2(FIM_REALTIME_NEWDIRECTORY, dir);

    w_mutex_unlock(&syscheck.fim_realtime_mutex);
    return 1;
}

void fim_realtime_delete_watches(__attribute__((unused)) const directory_t *configuration) {
    return;
}

// LCOV_EXCL_START
void realtime_sanitize_watch_map() {
    return;
}
// LCOV_EXCL_STOP

#else /* !WIN32 */

int realtime_start() {
    merror(FIM_ERROR_REALTIME_INITIALIZE);

    return (0);
}

int realtime_adddir(__attribute__((unused)) const char *dir,
                    __attribute__((unused)) directory_t *configuration) {
    return (0);
}

void fim_realtime_delete_watches(__attribute__((unused)) const directory_t *configuration) {
    return;
}

void realtime_process()
{
    return;
}

void realtime_sanitize_watch_map() {
    return;
}

#endif /* WIN32 */

int fim_realtime_get_queue_overflow() {
    int retval;

    w_mutex_lock(&syscheck.fim_realtime_mutex);
    if (syscheck.realtime != NULL) {
        retval = syscheck.realtime->queue_overflow;
    } else {
        retval = 0;
    }
    w_mutex_unlock(&syscheck.fim_realtime_mutex);

    return retval;
}

void fim_realtime_set_queue_overflow(int value) {
    w_mutex_lock(&syscheck.fim_realtime_mutex);
    if (syscheck.realtime != NULL) {
        syscheck.realtime->queue_overflow = value;
    }
    w_mutex_unlock(&syscheck.fim_realtime_mutex);
}

void fim_realtime_print_watches() {
    w_mutex_lock(&syscheck.fim_realtime_mutex);
    if (syscheck.realtime != NULL) {
        mdebug2(FIM_NUM_WATCHES, OSHash_Get_Elem_ex(syscheck.realtime->dirtb));
    }
    w_mutex_unlock(&syscheck.fim_realtime_mutex);
}
