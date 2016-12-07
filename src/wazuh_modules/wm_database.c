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
#include "addagent/manage_agents.h" // FILE_SIZE

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>
#define IN_BUFFER_SIZE sizeof(struct inotify_event) + NAME_MAX + 1
#endif

wm_database *module;

// Module main function. It won't return
static void* wm_database_main(wm_database *data);
// Destroy data
static void* wm_database_destroy(wm_database *data);
// Update manager information
static void wm_sync_manager();
static void wm_check_agents();
// Synchronize agents
static void wm_sync_agents();
static void wm_scan_directory(const char *dirname);
static int wm_sync_file(const char *dirname, const char *fname);
static long wm_fill_syscheck(sqlite3 *db, const char *path, long offset, int is_registry);
static long wm_fill_rootcheck(sqlite3 *db, const char *path, long offset);
// Extract agent name, IP and whether it's a Windows registry database from the file name
static int wm_extract_agent(const char *fname, char *name, char *ip, int *registry);

// Database module context definition
const wm_context WM_DATABASE_CONTEXT = {
    "database",
    (wm_routine)wm_database_main,
    (wm_routine)wm_database_destroy
};

// Module main function. It won't return
void* wm_database_main(wm_database *data) {
    module = data;

    // Manager name synchronization

    if (data->sync_agents)
        wm_sync_manager();

#ifdef INOTIFY_ENABLED
    char buffer[IN_BUFFER_SIZE];
    struct inotify_event *event = (struct inotify_event *)buffer;
    struct timeval timeout = { 0, 0 };
    int fd;
    int wd_agents = -1;
    int wd_syscheck;
    int wd_rootcheck;
    fd_set fdset;
    ssize_t count;
    ssize_t i;

    // Start inotify

    if ((fd = inotify_init()) < 0) {
        merror("%s: ERROR: Couldn't init inotify: %s.", WM_DATABASE_LOGTAG, strerror(errno));
        return NULL;
    }

    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

    // First synchronization and add watch for Syscheck and Rootcheck directories

    if (data->sync_agents)
        wm_sync_agents();

    if (data->sync_syscheck) {
        wm_scan_directory(DEFAULTDIR SYSCHECK_DIR);

        if ((wd_syscheck = inotify_add_watch(fd, DEFAULTDIR SYSCHECK_DIR, IN_CLOSE_WRITE)) < 0)
            merror("%s: ERROR: Couldn't watch Syscheck directory: %s.", WM_DATABASE_LOGTAG, strerror(errno));
    }

    if (data->sync_rootcheck) {
        wm_scan_directory(DEFAULTDIR ROOTCHECK_DIR);

        if ((wd_rootcheck = inotify_add_watch(fd, DEFAULTDIR ROOTCHECK_DIR, IN_CLOSE_WRITE)) < 0)
            merror("%s: ERROR: Couldn't watch Syscheck directory: %s.", WM_DATABASE_LOGTAG, strerror(errno));
    }

    // Loop

    while (1) {
        while (data->sync_agents && wd_agents < 0) {
            if ((wd_agents = inotify_add_watch(fd, KEYSFILE_PATH, IN_CLOSE_WRITE | IN_DELETE_SELF)) < 0) {
                merror("%s: ERROR: Couldn't watch client.keys file: %s.", WM_DATABASE_LOGTAG, strerror(errno));
                continue;
            }
        }

        // Wait for changes

        debug1("%s: DEBUG: Waiting for event notification...", WM_DATABASE_LOGTAG);

        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);
        timeout.tv_sec = data->sleep;

        switch (select(fd + 1, &fdset, NULL, NULL, &timeout)) {
        case -1:
            merror("%s: ERROR: select() : %s", WM_DATABASE_LOGTAG, strerror(errno));
            break;

        case 0:
            if (data->sync_agents)
                wm_check_agents();

            if (data->sync_syscheck)
                wm_scan_directory(DEFAULTDIR SYSCHECK_DIR);

            if (data->sync_rootcheck)
                wm_scan_directory(DEFAULTDIR ROOTCHECK_DIR);

            break;

        default:
            do {
                if ((count = read(fd, buffer, IN_BUFFER_SIZE)) < 0 && errno != EAGAIN) {
                    merror("%s: ERROR: read(): %s.", WM_DATABASE_LOGTAG, strerror(errno));
                    break;
                }

                for (i = 0; i < count; i += sizeof(struct inotify_event) + event->len) {
                    event = (struct inotify_event*)&buffer[i];

                    if (event->wd == wd_agents) {
                        switch (event->mask) {
                        case IN_CLOSE_WRITE:
                            wm_sync_agents();
                            break;

                        case IN_DELETE_SELF:
                            inotify_rm_watch(fd, wd_agents);
                            merror("%s: WARN: File 'client.keys' was deleted.", WM_DATABASE_LOGTAG);
                            wd_agents = -1;
                            break;

                        case IN_IGNORED:
                            break;

                        default:
                            merror("%s: WARN: Unknown inotify mask: 0x%x.", WM_DATABASE_LOGTAG, event->mask);
                        }
                    } else if (event->wd == wd_syscheck)
                        wm_sync_file(DEFAULTDIR SYSCHECK_DIR, event->name);
                    else if (event->wd == wd_rootcheck)
                        wm_sync_file(DEFAULTDIR ROOTCHECK_DIR, event->name);
                    else
                        merror("%s: ERROR: Unknown watch descriptor.", WM_DATABASE_LOGTAG);
                }
            } while (count > 0);
        }
    }

#else

    // Systems that don't support inotify

    while (1) {
        if (data->sync_agents)
            wm_check_agents();

        if (data->sync_syscheck)
            wm_scan_directory(DEFAULTDIR SYSCHECK_DIR);

        if (data->sync_rootcheck)
            wm_scan_directory(DEFAULTDIR ROOTCHECK_DIR);

        sleep(data->sleep);
    }

#endif
    return NULL;
}

// Update manager information
void wm_sync_manager() {
    char hostname[1024];
    char *uname;

    if (gethostname(hostname, 1024) == 0)
        wdb_update_agent_name(0, hostname);
    else
        merror("%s: ERROR: Couldn't get manager's hostname: %s.", WM_DATABASE_LOGTAG, strerror(errno));

    if ((uname = getuname())) {
        char *ptr;

        if ((ptr = strstr(uname, " - ")))
            *ptr = '\0';

        wdb_update_agent_version(0, uname, __ossec_name " " __version);
        free(uname);
    }
}

void wm_check_agents() {
    static time_t timestamp = 0;
    static ino_t inode = 0;
    struct stat buffer;

    if (stat(KEYSFILE_PATH, &buffer) < 0) {
        merror("%s: ERROR: Couldn't get client.keys stat: %s.", WM_DATABASE_LOGTAG, strerror(errno));
    } else {
        if (buffer.st_mtime != timestamp || buffer.st_ino != inode) {
            /* Synchronize */
            wm_sync_agents();
            timestamp = buffer.st_mtime;
            inode = buffer.st_ino;
        }
    }
}

// Synchronize agents
void wm_sync_agents() {
    unsigned int i;
    keystore keys;
    keyentry *entry;
    int *agents;

    debug1("%s: DEBUG: Synchronizing agents.", WM_DATABASE_LOGTAG);
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

    debug1("%s: DEBUG: Agent sync completed.", WM_DATABASE_LOGTAG);
}

void wm_scan_directory(const char *dirname) {
    char path[PATH_MAX + 1];
    struct dirent *dirent;
    DIR *dir;

    debug1("%s: DEBUG: Scanning directory '%s'.", WM_DATABASE_LOGTAG, dirname);
    snprintf(path, PATH_MAX, "%s", dirname);

    if (!(dir = opendir(path))) {
        merror("%s: ERROR: Couldn't open directory '%s': %s.", WM_DATABASE_LOGTAG, path, strerror(errno));
        return;
    }

    while ((dirent = readdir(dir)))
        if (dirent->d_name[0] != '.')
            wm_sync_file(dirname, dirent->d_name);

    closedir(dir);
}

int wm_sync_file(const char *dirname, const char *fname) {
    char name[FILE_SIZE];
    char addr[FILE_SIZE];
    char path[PATH_MAX + 1];
    struct stat buffer;
    long offset;
    long result = 0;
    int id_agent = -1;
    int is_registry;
    int type;
    sqlite3 *db;

    debug1("%s: DEBUG: Synchronizing file '%s/%s'", WM_DATABASE_LOGTAG, dirname, fname);
    snprintf(path, PATH_MAX, "%s/%s", dirname, fname);
    path[PATH_MAX] = '\0';

    if (!strcmp(dirname, DEFAULTDIR SYSCHECK_DIR)) {
        type = WDB_SYSCHECK;

        if (!strcmp(fname, "syscheck")) {
            id_agent = 0;
            strcpy(name, "localhost");
        }
    } else if (!strcmp(dirname, DEFAULTDIR ROOTCHECK_DIR)) {
        type = WDB_ROOTCHECK;

        if (!strcmp(fname, "rootcheck")) {
            id_agent = 0;
            strcpy(name, "localhost");
        }
    } else {
        merror("%s: ERROR: Directory name '%s' not recognized.", WM_DATABASE_LOGTAG, dirname);
        return -1;
    }

    // If id_agent != 0, then the file corresponds to an agent

    if (id_agent) {
        if (wm_extract_agent(fname, name, addr, &is_registry) < 0 || (id_agent = wdb_find_agent(name, addr)) < 0) {
            merror("%s: WARN: No such agent at database for file %s/%s", WM_DATABASE_LOGTAG, dirname, fname);
            return -1;
        } else if (is_registry)
            type = WDB_SYSCHECK_REGISTRY;
    }

    if (stat(path, &buffer) < 0) {
        debug1(FSTAT_ERROR, WM_DATABASE_LOGTAG, path, errno, strerror(errno));
        return -1;
    }

    switch (wdb_get_agent_status(id_agent)) {
    case WDB_AGENT_EMPTY:
        offset = module->full_sync ? 0 : buffer.st_size;
        break;
    case WDB_AGENT_PENDING:
        merror("%s: WARN: Agent '%d' database status was 'pending'. Data could be lost.", WM_DATABASE_LOGTAG, id_agent);
        wdb_set_agent_status(id_agent, WDB_AGENT_UPDATED);
        // Continue, don't break
    case WDB_AGENT_UPDATED:
        if ((offset = wdb_get_agent_offset(id_agent, type)) < 0)
            offset = module->full_sync ? 0 : buffer.st_size;
        break;
    default:
        merror("%s: ERROR: Couldn't get database status for agent '%d'.", WM_DATABASE_LOGTAG, id_agent);
        return -1;
    }

    if (buffer.st_size < offset) {
        merror("%s: WARN: File '%s' was rotated.", WM_DATABASE_LOGTAG, path);
        offset = 0;
    }

    if (buffer.st_size > offset) {
        if (!(db = wdb_open_agent(id_agent, name))) {
            merror("%s: ERROR: Couldn't open database for file '%s/%s'.", WM_DATABASE_LOGTAG, dirname, fname);
            return -1;
        }

        if (wdb_set_agent_status(id_agent, WDB_AGENT_PENDING) < 1) {
            merror("%s: ERROR: Couldn't write agent status on database for agent %d (%s).", WM_DATABASE_LOGTAG, id_agent, name);
            sqlite3_close_v2(db);
            return -1;
        }

        if (wdb_set_agent_offset(id_agent, type, buffer.st_size) < 1) {
            merror("%s: ERROR: Couldn't write offset data on database for agent %d (%s).", WM_DATABASE_LOGTAG, id_agent, name);
            sqlite3_close_v2(db);
            return -1;
        }

        result = type == WDB_ROOTCHECK ? wm_fill_rootcheck(db, path, offset) : wm_fill_syscheck(db, path, offset, is_registry);
        sqlite3_close_v2(db);

        if (wdb_set_agent_status(id_agent, WDB_AGENT_UPDATED) < 1) {
            merror("%s: ERROR: Couldn't write agent status on database for agent %d (%s).", WM_DATABASE_LOGTAG, id_agent, name);
            return -1;
        }

        if (result < 0) {
            merror("%s: ERROR: Couldn't fill database for file '%s/%s'.", WM_DATABASE_LOGTAG, dirname, fname);
            return -1;
        } else if (result != buffer.st_size && wdb_set_agent_offset(id_agent, type, result) < 1) {
            merror("%s: ERROR: Couldn't write offset data on database for agent %d (%s) (post-fill).", WM_DATABASE_LOGTAG, id_agent, name);
            return -1;
        }
    } else
        debug1("%s: DEBUG: Skipping file '%s/%s'", WM_DATABASE_LOGTAG, dirname, fname);

    return 0;
}

long wm_fill_syscheck(sqlite3 *db, const char *path, long offset, int is_registry) {
    char buffer[OS_MAXSTR];
    char *end;
    char *event;
    char *c_sum;
    char *f_name;
    int count;
    long last_offset = offset;
    clock_t clock_ini;
    int type = is_registry ? WDB_FILE_TYPE_REGISTRY : WDB_FILE_TYPE_FILE;
    FILE *fp = fopen(path, "r");

    sk_sum_t sum;

    if (!fp) {
        merror(FOPEN_ERROR, WM_DATABASE_LOGTAG, path, errno, strerror(errno));
        return -1;
    }

    if (fseek(fp, offset, SEEK_SET) < 0) {
        merror(FSEEK_ERROR, WM_DATABASE_LOGTAG, path, errno, strerror(errno));
        fclose(fp);
        return -1;
    }

    clock_ini = clock();
    wdb_begin(db);

    for (count = 0; fgets(buffer, OS_MAXSTR, fp); last_offset = ftell(fp)) {
        end = strchr(buffer, '\n');

        if (!end) {
            merror("%s: WARN: Corrupt line found parsing '%s' (incomplete). Breaking.", WM_DATABASE_LOGTAG, path);
            break;
        } else if (end == buffer)
            continue;

        *end = '\0';
        c_sum = buffer + 3;

        if (!(f_name = strchr(c_sum, ' '))) {
            merror("%s: WARN: Corrupt line found parsing '%s'.", WM_DATABASE_LOGTAG, path);
            continue;
        }

        *(f_name++) = '\0';

        switch (sk_decode_sum(&sum, c_sum)) {
        case 0:
            switch (wdb_get_last_fim(db, f_name, type)) {
            case WDB_FIM_NOT_FOUND:
                event = buffer[0] == '+' || (buffer[0] == '#' && buffer[1] == '+') ? "added" : "modified";
                break;
            case WDB_FIM_ADDED:
            case WDB_FIM_MODIFIED:
            case WDB_FIM_READDED:
                event = "modified";
                break;
            case WDB_FIM_DELETED:
                event = "readded";
                break;
            default:
                merror("%s: ERROR: Couldn't extract FIM data from database.", WM_DATABASE_LOGTAG);
                continue;
            }

            break;
        case 1:
            event = "deleted";
            break;
        default:
            merror("%s: WARN: Corrupt line found parsing '%s'.", WM_DATABASE_LOGTAG, path);
            continue;
        }

        if (wdb_insert_fim(db, type, f_name, event, &sum) < 0)
            merror("%s: ERROR: Couldn't insert FIM event into database from file '%s'.", WM_DATABASE_LOGTAG, path);

        count++;
    }

    wdb_commit(db);
    debug2("%s: DEBUG: Syscheck file sync finished. Count: %d. Time: %.3lf ms.", WM_DATABASE_LOGTAG, count, (double)(clock() - clock_ini) / CLOCKS_PER_SEC * 1000);

    fclose(fp);
    return last_offset;
}

long wm_fill_rootcheck(sqlite3 *db, const char *path, long offset) {
    char buffer[OS_MAXSTR];
    char *end;
    int count = 0;
    long last_offset = offset;
    rk_event_t event;
    clock_t clock_ini;
    FILE *fp = fopen(path, "r");

    if (!fp) {
        merror(FOPEN_ERROR, WM_DATABASE_LOGTAG, path, errno, strerror(errno));
        return -1;
    }

    if (fseek(fp, offset, SEEK_SET) < 0) {
        merror(FSEEK_ERROR, WM_DATABASE_LOGTAG, path, errno, strerror(errno));
        fclose(fp);
        return -1;
    }

    clock_ini = clock();
    wdb_begin(db);

    for (count = 0; fgets(buffer, OS_MAXSTR, fp); last_offset = ftell(fp)) {
        end = strchr(buffer, '\n');

        if (!end) {
            merror("%s: WARN: Corrupt line found parsing '%s' (incomplete). Breaking.", WM_DATABASE_LOGTAG, path);
            break;
        } else if (end == buffer)
            continue;

        *end = '\0';

        if (rk_decode_event(buffer, &event) < 0) {
            merror("%s: WARN: Corrupt line found parsing '%s'.", WM_DATABASE_LOGTAG, path);
            continue;
        }

        switch (wdb_update_pm(db, &event)) {
            case -1:
                merror("%s: ERROR: Updating PM tuple on SQLite database for file '%s'.", WM_DATABASE_LOGTAG, path);
                continue;
            case 0:
                if (wdb_insert_pm(db, &event) < 0) {
                    merror("%s: ERROR: Inserting PM tuple on SQLite database for file '%s'.", WM_DATABASE_LOGTAG, path);
                    continue;
                }

                // Don't break

            default:
                count++;
        }
    }

    wdb_commit(db);
    debug2("%s: DEBUG: Syscheck file sync finished. Count: %d. Time: %.3lf ms.", WM_DATABASE_LOGTAG, count, (double)(clock() - clock_ini) / CLOCKS_PER_SEC * 1000);

    fclose(fp);
    return last_offset;
}

// Extract agent name, IP and whether it's a Windows registry database from the file name
int wm_extract_agent(const char *fname, char *name, char *ip, int *registry) {
    const char *c;
    size_t z;

    if (fname[0] != '(')
        return -1;

    fname++;

    if (!(c = strchr(fname, ')')))
        return -1;

    z = c - fname;
    memcpy(name, fname, z);
    name[z] = '\0';
    fname = c + 2;

    if (!(c = strstr(fname, "->")))
        return -1;

    z = c - fname;
    memcpy(ip, fname, z);
    ip[z] = '\0';
    fname = c + 2;

    if (!(strcmp(fname, "syscheck") && strcmp(fname, "rootcheck"))) {
        *registry = 0;
        return 0;
    } else if (!strcmp(fname, "syscheck-registry")) {
        *registry = 1;
        return 0;
    } else
        return -1;
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
    data.sync_syscheck = getDefine_Int("wazuh_database", "sync_syscheck", 0, 1);
    data.sync_rootcheck = getDefine_Int("wazuh_database", "sync_rootcheck", 0, 1);
    data.full_sync = getDefine_Int("wazuh_database", "full_sync", 0, 1);
    data.sleep = getDefine_Int("wazuh_database", "sleep", 0, 86400);

    if (data.sync_agents || data.sync_syscheck || data.sync_rootcheck) {
        module = calloc(1, sizeof(wmodule));
        module->context = &WM_DATABASE_CONTEXT;
        module->data = calloc(1, sizeof(wm_database));
        memcpy(module->data, &data, sizeof(wm_database));
    }

    return module;
}
