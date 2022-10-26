/*
 * Wazuh Module for file downloads
 * Copyright (C) 2015, Wazuh Inc.
 * April 25, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include <os_net/os_net.h>

#ifndef WIN32

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_DOWNLOAD_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_DOWNLOAD_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_DOWNLOAD_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_DOWNLOAD_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_DOWNLOAD_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

static void * wm_download_main(wm_download_t * data);   // Module main function. It won't return
static void wm_download_destroy(wm_download_t * data);  // Destroy data
cJSON *wm_download_dump();     // Read config

// Dispatch request. Write the output into the same input buffer.
static void wm_download_dispatch(char * buffer);

const wm_context WM_DOWNLOAD_CONTEXT = {
    .name = "download",
    .start = (wm_routine)wm_download_main,
    .destroy = (void (*)(void *))wm_download_destroy,
    .dump = (cJSON * (*)(const void *))wm_download_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

// Module main function. It won't return

void * wm_download_main(wm_download_t * data) {
    int sock;
    int peer;
    ssize_t length;
    char buffer[OS_MAXSTR + 1];

    // If module is disabled, exit

    if (data->enabled) {
        minfo("Module started.");
    } else {
        minfo("Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    // Create local socket

    do {
        static unsigned int seconds = 60;

        if (sock = OS_BindUnixDomainWithPerms(WM_DOWNLOAD_SOCK, SOCK_STREAM, OS_MAXSTR, getuid(), wm_getGroupID(), 0660), sock < 0) {
            mwarn("Unable to bind to socket '%s', retrying in %u secs.", WM_DOWNLOAD_SOCK, seconds);
            sleep(seconds);
            seconds += seconds < 600 ? 60 : 0;
        }
    } while (sock < 0);

    // Main loop: wait and dispatch clients

    while (1) {

        // Wait and accept a new connection

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno == EINTR) {
                minfo("accept(): %s", strerror(errno));
            } else {
                merror("accept(): %s", strerror(errno));
            }

            continue;
        }

        // Receive request, process it and send answer

        switch (length = recv(peer, buffer, OS_MAXSTR, 0), length) {
        case -1:
            merror("recv(): %s (%d)", strerror(errno), errno);
            break;

        case 0:
            mdebug1("Client disconnected. This may be a healthcheck.");
            break;

        default:
            buffer[length] = '\0';
            wm_download_dispatch(buffer);
            if( send(peer, buffer, strlen(buffer), 0) < 0) {
                merror("send(): %s (%d)",strerror(errno), errno);
            }
        }

        close(peer);
    }
    return NULL;
}

// Dispatch request. Write the output into the same input buffer.

void wm_download_dispatch(char * buffer) {
    char * command;
    char * url;
    char * fpath;
    char * unsc_fpath = NULL;
    char * header;
    char * unsc_header = NULL;
    char * data = NULL;
    char * unsc_data = NULL;
    char jpath[PATH_MAX];
    char * next;
    char * buffer_cpy;
    char * timeout_ptr = NULL;
    long timeout = 0;

    // Copy the command buffer for error messages

    os_strdup(buffer, buffer_cpy);

    // Get command

    if (next = strchr(buffer, ' '), !(next && *next)) {
        mdebug1("Empty request command: '%s'", buffer_cpy);
        snprintf(buffer, OS_MAXSTR, "err empty command");
        goto end;
    }
    *(next++) = '\0';
    command = buffer;

    // Nowadays we only support the "download" command

    if (strcmp(command, "download")) {
        mdebug1("Invalid request command: '%s'", buffer_cpy);
        snprintf(buffer, OS_MAXSTR, "err invalid command");
        goto end;
    }

    // Get URL

    url = next;
    if (next = wstr_chr(next, '|'), !(next && *next)) {
        mdebug1("Empty request URL: '%s'", buffer_cpy);
        snprintf(buffer, OS_MAXSTR, "err empty url");
        goto end;
    }
    *(next++) = '\0';

    // Get file path

    fpath = next;
    if (next = wstr_chr(next, '|'), !(next && *next)) {
        mdebug1("Empty request file: '%s'", buffer_cpy);
        snprintf(buffer, OS_MAXSTR, "err empty file name");
        goto end;
    }
    *(next++) = '\0';

    // Get request header (optional)

    header = next;
    if (next = wstr_chr(next, '|'), !(next && *next)) {
        header = NULL;
        mdebug2("Empty request header: '%s'", buffer_cpy);
        goto unsc;
    }
    *(next++) = '\0';

    // Get request data (optional)

    data = next;
    if (next = wstr_chr(next, '|'), !(next && *next)) {
        data = NULL;
        mdebug2("Empty request data: '%s'", buffer_cpy);
        goto unsc;
    }
    *(next++) = '\0';

    // Get request timeout (optional)

    timeout_ptr = next;
    if (next = wstr_chr(next, '|'), !(next && *next)) {
        timeout = 0;
        mdebug2("Empty request timeout: '%s'", buffer_cpy);
        goto unsc;
    }
    *(next++) = '\0';
    timeout = atol(timeout_ptr);

unsc:
    // Unescape

    unsc_fpath = wstr_replace(fpath, "\\|", "|");
    if (header && *header) {
        unsc_header = wstr_replace(header, "\\|", "|");
    }
    if (data && *data) {
        unsc_data = wstr_replace(data, "\\|", "|");
    }

    // Jail path

    if (snprintf(jpath, sizeof(jpath), "%s", unsc_fpath) >= (int)sizeof(jpath)) {
        mdebug1("Path too long: '%s'", buffer_cpy);
        snprintf(buffer, OS_MAXSTR, "err path too long");
        goto end;
    }

    if (w_ref_parent_folder(jpath)) {
        mdebug1("Path references parent folder: '%s'", buffer_cpy);
        snprintf(buffer, OS_MAXSTR, "err parent folder reference");
        goto end;
    }

    // Run download
    mdebug1("Downloading '%s' to '%s'", url, jpath);

    switch (wurl_get(url, jpath, unsc_header, unsc_data, timeout)) {
    case OS_CONNERR:
        mdebug1(WURL_DOWNLOAD_FILE_ERROR, jpath, url);
        snprintf(buffer, OS_MAXSTR, "err connecting to url");
        break;

    case OS_FILERR:
        mdebug1(WURL_WRITE_FILE_ERROR, unsc_fpath);
        snprintf(buffer, OS_MAXSTR, "err writing file");
        break;

    case OS_TIMEOUT:
        mdebug1(WURL_TIMEOUT_ERROR, jpath, url);
        snprintf(buffer, OS_MAXSTR, "err timeout");
        break;

    default:
        snprintf(buffer, OS_MAXSTR, "ok");
        mdebug2("Download of '%s' finished.", url);
    }

end:
    os_free(unsc_fpath);
    os_free(unsc_header);
    os_free(unsc_data);
    os_free(buffer_cpy);
}

// Destroy data

void wm_download_destroy(wm_download_t * data) {
    free(data);
}

// Read configuration and return a module (if enabled) or NULL (if disabled)

wmodule * wm_download_read() {
#ifdef CLIENT
    // This module won't be available on agents
    return NULL;
#else
    wm_download_t * data;
    wmodule * module;

    os_calloc(1, sizeof(wmodule), module);
    os_malloc(sizeof(wm_download_t), data);
    data->enabled = getDefine_Int("wazuh_download", "enabled", 0, 1);
    module->context = &WM_DOWNLOAD_CONTEXT;
    module->data = data;
    module->tag = strdup(module->context->name);

    return module;
#endif
}

cJSON *wm_download_dump() {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();
    cJSON_AddStringToObject(wm_wd,"enabled","yes");
    cJSON_AddItemToObject(root,"wazuh_download",wm_wd);
    return root;
}
#endif
