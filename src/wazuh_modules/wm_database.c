/*
 * Wazuh Module for SQLite database syncing
 * Copyright (C) 2016 Wazuh Inc.
 * November 29, 2016
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include "sec.h"
#include "wazuh_db/wdb.h"

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>
#include <limits.h>
#define IN_BUFFER_SIZE sizeof(struct inotify_event) + NAME_MAX + 1
#endif

static void* wm_database_main(wm_database *data);       // Module main function. It won't return
static void* wm_database_destroy(wm_database *data);    // Destroy data
static void wm_sync_agents();                           // Synchronize agents

// Database module context definition

const wm_context WM_DATABASE_CONTEXT = {
    "database",
    (wm_routine)wm_database_main,
    (wm_routine)wm_database_destroy
};

// Module main function. It won't return
void* wm_database_main(__attribute__((unused)) wm_database *data) {
    char *uname;

    /* Update manager information */

    {
        char hostname[1024];

        if (gethostname(hostname, 1024) == 0)
            wdb_update_agent_name(0, hostname);
        else
            merror("%s: ERROR: Couldn't get manager's hostname: %s.", WM_DATABASE_LOGTAG, strerror(errno));
    }

    if ((uname = getuname())) {
        char *ptr;

        if ((ptr = strstr(uname, " - ")))
            *ptr = '\0';

        wdb_update_agent_version(0, uname, __ossec_name " " __version);
        free(uname);
    }

#ifdef INOTIFY_ENABLED
    char buffer[IN_BUFFER_SIZE];
    struct inotify_event *event = (struct inotify_event *)buffer;
    int fd = inotify_init();
    int wd = -1;
    ssize_t count;
    ssize_t i;
    int sync = 1;

    /* Start inotify */

    if (fd < 0) {
        merror("%s: ERROR: Couldn't init inotify: %s.", WM_DATABASE_LOGTAG, strerror(errno));
        return NULL;
    }

    /* Loop */

    while (1) {
        while (wd < 0) {
            if ((wd = inotify_add_watch(fd, KEYSFILE_PATH, IN_CLOSE_WRITE | IN_DELETE_SELF)) < 0) {
                merror("%s: ERROR: Couldn't watch client.keys file: %s.", WM_DATABASE_LOGTAG, strerror(errno));

                if (errno == ENOENT)
                    sleep(120);
                else
                    return NULL;
            }
        }

        /* Synchronize */

        if (sync) {
            debug1("%s: DEBUG: Synchronizing agents.", WM_DATABASE_LOGTAG);
            wm_sync_agents();
            debug1("%s: DEBUG: Agent sync completed.", WM_DATABASE_LOGTAG);
        }

        /* Wait for changes */

        if ((count = read(fd, buffer, IN_BUFFER_SIZE)) < 0) {
            merror("%s: ERROR: read(): %s.", WM_DATABASE_LOGTAG, strerror(errno));
            continue;
        }

        for (i = 0; i < count; i += sizeof(struct inotify_event) + event->len) {
            event = (struct inotify_event*)&buffer[i];

            switch (event->mask) {
            case IN_CLOSE_WRITE:
                sync = 1;
                break;
            case IN_DELETE_SELF:
                sync = 0;
                break;
            case IN_IGNORED:
                inotify_rm_watch(fd, wd);
                wd = -1;
                sync = 1;
                break;
            default:
                merror("%s: WARN: Unknown inotify mask: 0x%x.", WM_DATABASE_LOGTAG, event->mask);
            }
        }
    }

#else

    struct stat buffer;
    time_t timestamp = 0;

    while (1) {
        if (stat(KEYSFILE_PATH, &buffer) < 0) {
            merror("%s: ERROR: Couldn't get client.keys stat: %s.", WM_DATABASE_LOGTAG, strerror(errno));
            sleep(120);
        } else {
            if (buffer.st_mtime != timestamp) {
                /* Synchronize */
                debug1("%s: DEBUG: Synchronizing agents.", WM_DATABASE_LOGTAG);
                wm_sync_agents();
                debug1("%s: DEBUG: Agent sync completed.", WM_DATABASE_LOGTAG);
                timestamp = buffer.st_mtime;
            }

            sleep(1);
        }
    }

#endif
    return NULL;
}

void wm_sync_agents() {
    unsigned int i;
    keystore keys;
    keyentry *entry;
    int *agents;

    OS_ReadKeys(&keys, 0);

    /* Insert new entries */

    for (i = 0; i < keys.keysize; i++) {
        entry = keys.keyentries[i];
        int id;

        if (!(id = atoi(entry->id))) {
            merror("%s: ERROR: at wm_sync_agents(): invalid ID number.", WM_DATABASE_LOGTAG);
            continue;
        }

        wdb_insert_agent(id, entry->name, entry->ip->ip, entry->key);
    }

    /* Delete old keys */

    if ((agents = wdb_get_all_agents())) {
        char id[9];

        for (i = 0; agents[i] != -1; i++) {
            snprintf(id, 9, "%03d", agents[i]);

            if (OS_IsAllowedID(&keys, id) == -1)
                wdb_remove_agent(agents[i]);
            }

        free(agents);
    }
}

// Destroy data
void* wm_database_destroy(wm_database *data) {
    free(data);
    return NULL;
}

// Read configuration and return a module (if enabled) or NULL (if disabled)
wmodule* wm_database_read() {
    wm_database data;
    wmodule *module = NULL;

    data.sync_agents = getDefine_Int("wazuh_database", "sync_agents", 0, 1);

    if (data.sync_agents) {
        module = calloc(1, sizeof(wmodule));
        module->context = &WM_DATABASE_CONTEXT;
        module->data = calloc(1, sizeof(wm_database));
        memcpy(module->data, &data, sizeof(wm_database));
    }

    return module;
}
