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
#else
static void wm_check_agents();
#endif

wm_database *module;

// Module main function. It won't return
static void* wm_database_main(wm_database *data);
// Destroy data
static void* wm_database_destroy(wm_database *data);
// Update manager information
static void wm_sync_manager();
// Synchronize agents
static void wm_sync_agents();
static int wm_sync_agentinfo(int id_agent, const char *path);
static void wm_scan_directory(const char *dirname);
static int wm_sync_file(const char *dirname, const char *path);
// Fill syscheck database from an offset. Returns offset at last successful read event, or -1 on error.
static long wm_fill_syscheck(sqlite3 *db, const char *path, long offset, int is_registry);
// Fill complete rootcheck database.
static int wm_fill_rootcheck(sqlite3 *db, const char *path);
/*
 * Extract agent name, IP and whether it's a Windows registry database from the file name.
 * Returns 0 on success, 1 to ignore and -1 on error.
 */
static int wm_extract_agent(const char *fname, char *name, char *addr, int *registry);

// Database module context definition
const wm_context WM_DATABASE_CONTEXT = {
    "database",
    (wm_routine)wm_database_main,
    (wm_routine)wm_database_destroy
};

// Module main function. It won't return
void* wm_database_main(wm_database *data) {
    module = data;

    verbose("%s: INFO: Module started.", WM_DATABASE_LOGTAG);

    // Manager name synchronization

    if (data->sync_agents)
        wm_sync_manager();

#ifdef INOTIFY_ENABLED
    char buffer[IN_BUFFER_SIZE];
    char keysfile_dir[] = KEYSFILE_PATH;
    char *keysfile;
    struct inotify_event *event = (struct inotify_event *)buffer;
    int fd;
    int wd_agents = -1;
    int wd_agentinfo = -1;
    int wd_syscheck = -1;
    int wd_rootcheck = -1;
    ssize_t count;
    ssize_t i;

    // Start inotify

    if ((fd = inotify_init()) < 0) {
        merror("%s: ERROR: Couldn't init inotify: %s.", WM_DATABASE_LOGTAG, strerror(errno));
        return NULL;
    }

    if (!(keysfile = strrchr(keysfile_dir, '/'))) {
        merror("%s: CRITICAL: Couldn't decode keys file path '%s'.", WM_DATABASE_LOGTAG, keysfile_dir);
        return NULL;
    }

    *(keysfile++) = '\0';

    // First synchronization and add watch for client.keys, Agent info, Syscheck and Rootcheck directories

    if (data->sync_agents) {
        if ((wd_agents = inotify_add_watch(fd, keysfile_dir, IN_CLOSE_WRITE | IN_MOVED_TO)) < 0)
            merror("%s: ERROR: Couldn't watch client.keys file: %s.", WM_DATABASE_LOGTAG, strerror(errno));

        if ((wd_agentinfo = inotify_add_watch(fd, DEFAULTDIR AGENTINFO_DIR, IN_CLOSE_WRITE)) < 0)
            merror("%s: ERROR: Couldn't watch the agent info directory: %s.", WM_DATABASE_LOGTAG, strerror(errno));

        wm_sync_agents();
        wm_scan_directory(DEFAULTDIR AGENTINFO_DIR);
    }

    if (data->sync_syscheck) {
        if ((wd_syscheck = inotify_add_watch(fd, DEFAULTDIR SYSCHECK_DIR, IN_MODIFY)) < 0)
            merror("%s: ERROR: Couldn't watch Syscheck directory: %s.", WM_DATABASE_LOGTAG, strerror(errno));

        wm_scan_directory(DEFAULTDIR SYSCHECK_DIR);
    }

    if (data->sync_rootcheck) {
        if ((wd_rootcheck = inotify_add_watch(fd, DEFAULTDIR ROOTCHECK_DIR, IN_MODIFY)) < 0)
            merror("%s: ERROR: Couldn't watch Rootcheck directory: %s.", WM_DATABASE_LOGTAG, strerror(errno));

        wm_scan_directory(DEFAULTDIR ROOTCHECK_DIR);
    }

    // Loop

    while (1) {

        // Wait for changes

        debug1("%s: DEBUG: Waiting for event notification...", WM_DATABASE_LOGTAG);

        do {
            if ((count = read(fd, buffer, IN_BUFFER_SIZE)) < 0 && errno != EAGAIN) {
                merror("%s: ERROR: read(): %s.", WM_DATABASE_LOGTAG, strerror(errno));
                break;
            }

            for (i = 0; i < count; i += (ssize_t)(sizeof(struct inotify_event) + event->len)) {
                event = (struct inotify_event*)&buffer[i];

                if (event->wd == wd_agents) {
                    if (!strcmp(event->name, keysfile))
                        wm_sync_agents();
                }
                else if (event->wd == wd_agentinfo)
                    wm_sync_file(DEFAULTDIR AGENTINFO_DIR, event->name);
                else if (event->wd == wd_syscheck)
                    wm_sync_file(DEFAULTDIR SYSCHECK_DIR, event->name);
                else if (event->wd == wd_rootcheck)
                    wm_sync_file(DEFAULTDIR ROOTCHECK_DIR, event->name);
                else
                    merror("%s: ERROR: Unknown watch descriptor.", WM_DATABASE_LOGTAG);
            }
        } while (count > 0);
    }

#else

    // Systems that don't support inotify

    while (1) {
        if (data->sync_agents) {
            wm_check_agents();
            wm_scan_directory(DEFAULTDIR AGENTINFO_DIR);
        }

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

        wdb_update_agent_version(0, uname, __ossec_name " " __version, NULL);
        free(uname);
    }
}

#ifndef INOTIFY_ENABLED
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
#endif

// Synchronize agents
void wm_sync_agents() {
    unsigned int i;
    char path[PATH_MAX] = "";
    keystore keys;
    keyentry *entry;
    int *agents;
    struct stat buffer;

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

        if (!(wdb_insert_agent(id, entry->name, entry->ip->ip, entry->key) || module->full_sync)) {
            // Find files

            snprintf(path, PATH_MAX, "%s/(%s) %s->syscheck", DEFAULTDIR SYSCHECK_DIR, entry->name, entry->ip->ip);

            if (stat(path, &buffer) < 0) {
                if (errno != ENOENT)
                    merror(FSTAT_ERROR, WM_DATABASE_LOGTAG, path, errno, strerror(errno));
            } else if (wdb_set_agent_offset(id, WDB_SYSCHECK, buffer.st_size) < 1)
                merror("%s: ERROR: Couldn't write offset data on database for agent %d (%s).", WM_DATABASE_LOGTAG, id, entry->name);

            snprintf(path, PATH_MAX, "%s/(%s) %s->syscheck-registry", DEFAULTDIR SYSCHECK_DIR, entry->name, entry->ip->ip);

            if (stat(path, &buffer) < 0) {
                if (errno != ENOENT)
                    merror(FSTAT_ERROR, WM_DATABASE_LOGTAG, path, errno, strerror(errno));
            } else if (wdb_set_agent_offset(id, WDB_SYSCHECK_REGISTRY, buffer.st_size) < 1)
                merror("%s: ERROR: Couldn't write offset data on database for agent %d (%s).", WM_DATABASE_LOGTAG, id, entry->name);
        }
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

    OS_FreeKeys(&keys);
    debug1("%s: DEBUG: Agent sync completed.", WM_DATABASE_LOGTAG);
}

int wm_sync_agentinfo(int id_agent, const char *path) {
    char buffer[OS_MAXSTR];
    char *os;
    char *version;
    char *shared_sum;
    char *end;
    FILE *fp;

    if (!(fp = fopen(path, "r"))) {
        merror(FOPEN_ERROR, WM_DATABASE_LOGTAG, path, errno, strerror(errno));
        return -1;
    }

    os = fgets(buffer, OS_MAXSTR, fp);
    fclose(fp);

    if (!os) {
        merror("%s: ERROR: Couldn't read file '%s'.", WM_DATABASE_LOGTAG, path);
        return -1;
    }

    if (!(version = strstr(os, " - "))) {
        merror("%s: ERROR: Corrupt file '%s'.", WM_DATABASE_LOGTAG, path);
        return -1;
    }

    *version = '\0';

    if ((shared_sum = strstr(version += 3, " / "))) {
        *shared_sum = '\0';
        shared_sum += 3;
        end = strchr(shared_sum, '\n');
    } else
        end = strchr(version, '\n');

    if (!end) {
        merror("%s: WARN: Corrupt line found parsing '%s' (incomplete). Returning.", WM_DATABASE_LOGTAG, path);
        return -1;
    }

    *end = '\0';
    return wdb_update_agent_version(id_agent, os, version, shared_sum);
}

void wm_scan_directory(const char *dirname) {
    char path[PATH_MAX];
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
    char path[PATH_MAX] = "";
    struct stat buffer;
    long offset;
    int result = 0;
    int id_agent = -1;
    int is_registry = 0;
    int type;
    sqlite3 *db;

    debug1("%s: DEBUG: Synchronizing file '%s/%s'", WM_DATABASE_LOGTAG, dirname, fname);
    snprintf(path, PATH_MAX, "%s/%s", dirname, fname);

    if (!strcmp(dirname, DEFAULTDIR AGENTINFO_DIR))
        type = WDB_AGENTINFO;
    else if (!strcmp(dirname, DEFAULTDIR SYSCHECK_DIR)) {
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
        switch (wm_extract_agent(fname, name, addr, &is_registry)) {
        case 0:
            if ((id_agent = wdb_find_agent(name, addr)) < 0) {
                merror("%s: WARN: No such agent at database for file %s/%s", WM_DATABASE_LOGTAG, dirname, fname);
                return -1;
            }

            if (is_registry)
                type = WDB_SYSCHECK_REGISTRY;

            break;

        case 1:
            debug1("%s: DEBUG: Ignoring file '%s/%s'", WM_DATABASE_LOGTAG, dirname, fname);
            return 0;

        default:
            merror("%s: WARN: Couldn't extract agent name and address from file %s/%s", WM_DATABASE_LOGTAG, dirname, fname);
            return -1;
        }
    }

    if (stat(path, &buffer) < 0) {
        merror(FSTAT_ERROR, WM_DATABASE_LOGTAG, path, errno, strerror(errno));
        return -1;
    }

    switch (wdb_get_agent_status(id_agent)) {
    case -1:
        merror("%s: ERROR: Couldn't get database status for agent '%d'.", WM_DATABASE_LOGTAG, id_agent);
        return -1;
    case WDB_AGENT_PENDING:
        merror("%s: WARN: Agent '%d' database status was 'pending'. Data could be lost.", WM_DATABASE_LOGTAG, id_agent);
        wdb_set_agent_status(id_agent, WDB_AGENT_UPDATED);
        break;
    }

    switch (type) {
    case WDB_SYSCHECK:
    case WDB_SYSCHECK_REGISTRY:
        if ((offset = wdb_get_agent_offset(id_agent, type)) < 0) {
            merror("%s: ERROR: Couldn't file offset from database for agent '%d'.", WM_DATABASE_LOGTAG, id_agent);
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

            offset = wm_fill_syscheck(db, path, offset, is_registry);
            sqlite3_close_v2(db);

            if (wdb_set_agent_status(id_agent, WDB_AGENT_UPDATED) < 1) {
                merror("%s: ERROR: Couldn't write agent status on database for agent %d (%s).", WM_DATABASE_LOGTAG, id_agent, name);
                return -1;
            }

            if (offset < 0) {
                merror("%s: ERROR: Couldn't fill syscheck database for file '%s/%s'.", WM_DATABASE_LOGTAG, dirname, fname);
                return -1;
            }

            if (offset != buffer.st_size && wdb_set_agent_offset(id_agent, type, offset) < 1) {
                merror("%s: ERROR: Couldn't write offset data on database for agent %d (%s) (post-fill).", WM_DATABASE_LOGTAG, id_agent, name);
                return -1;
            }
        } else
            debug1("%s: DEBUG: Skipping file '%s/%s'", WM_DATABASE_LOGTAG, dirname, fname);

        break;

    case WDB_ROOTCHECK:
        if (!(db = wdb_open_agent(id_agent, name))) {
            merror("%s: ERROR: Couldn't open database for file '%s/%s'.", WM_DATABASE_LOGTAG, dirname, fname);
            return -1;
        }

        if (wdb_set_agent_status(id_agent, WDB_AGENT_PENDING) < 1) {
            merror("%s: ERROR: Couldn't write agent status on database for agent %d (%s).", WM_DATABASE_LOGTAG, id_agent, name);
            sqlite3_close_v2(db);
            return -1;
        }

        result = wm_fill_rootcheck(db, path);
        sqlite3_close_v2(db);

        if (wdb_set_agent_status(id_agent, WDB_AGENT_UPDATED) < 1) {
            merror("%s: ERROR: Couldn't write agent status on database for agent %d (%s).", WM_DATABASE_LOGTAG, id_agent, name);
            return -1;
        }

        if (result < 0) {
            merror("%s: ERROR: Couldn't fill rootcheck database for file '%s/%s'.", WM_DATABASE_LOGTAG, dirname, fname);
            return -1;
        }

        break;

    case WDB_AGENTINFO:
        result = wm_sync_agentinfo(id_agent, path) < 0 || wdb_update_agent_keepalive(id_agent, buffer.st_mtime) < 0 ? -1 : 0;
    }

    return result;
}

// Fill syscheck database from an offset. Returns offset at last successful read event, or -1 on error.
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
    FILE *fp;

    sk_sum_t sum;

    if (!(fp = fopen(path, "r"))) {
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

// Fill complete rootcheck database. Returns 0 on success or -1 on error.
int wm_fill_rootcheck(sqlite3 *db, const char *path) {
    char buffer[OS_MAXSTR];
    char *end;
    int count = 0;
    rk_event_t event;
    clock_t clock_ini;
    FILE *fp;

    if (!(fp = fopen(path, "r"))) {
        merror(FOPEN_ERROR, WM_DATABASE_LOGTAG, path, errno, strerror(errno));
        return -1;
    }

    clock_ini = clock();
    wdb_begin(db);

    while (fgets(buffer, OS_MAXSTR, fp)) {
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
    debug2("%s: DEBUG: Rootcheck file sync finished. Count: %d. Time: %.3lf ms.", WM_DATABASE_LOGTAG, count, (double)(clock() - clock_ini) / CLOCKS_PER_SEC * 1000);

    fclose(fp);
    return 0;
}

/*
 * Extract agent name, IP and whether it's a Windows registry database from the file name.
 * Returns 0 on success, 1 to ignore and -1 on error.
 */
int wm_extract_agent(const char *fname, char *name, char *addr, int *registry) {
    const char *c;
    const char *_name;
    const char *_addr;
    size_t z_name;
    size_t z_addr;

    switch (fname[0]) {
    case '(':
        // Syscheck/Rootcheck
        fname++;

        if (!(c = strchr(fname, ')')))
            return -1;

        z_name = c - fname;
        _name = fname;
        fname = c + 2;

        if (!(c = strstr(fname, "->")))
            return -1;

        z_addr = c - fname;
        _addr = fname;
        fname = c + 2;

        if (!(strcmp(fname, "syscheck") && strcmp(fname, "rootcheck")))
            *registry = 0;
        else if (!strcmp(fname, "syscheck-registry"))
            *registry = 1;
        else
            return -1;

        break;

    case '.':
        // Hidden files or .cpt: ignore
        return 1;

    default:
        // agent-info files

        if (!(c = strrchr(fname, '-')))
            return -1;

        z_name = c - fname;
        _name = fname;
        _addr = c + 1;
        z_addr = strlen(_addr);
    }

    memcpy(name, _name, z_name);
    name[z_name] = '\0';
    memcpy(addr, _addr, z_addr);
    addr[z_addr] = '\0';

    return 0;
}

// Destroy data
void* wm_database_destroy(wm_database *data) {
    free(data);
    return NULL;
}

// Read configuration and return a module (if enabled) or NULL (if disabled)
wmodule* wm_database_read() {
#ifdef CLIENT
    // This module won't be available on agents
    return NULL;
#else
    wm_database data;
    wmodule *module = NULL;

    data.sync_agents = getDefine_Int("wazuh_database", "sync_agents", 0, 1);
    data.sync_syscheck = getDefine_Int("wazuh_database", "sync_syscheck", 0, 1);
    data.sync_rootcheck = getDefine_Int("wazuh_database", "sync_rootcheck", 0, 1);
    data.full_sync = getDefine_Int("wazuh_database", "full_sync", 0, 1);
    data.sleep = getDefine_Int("wazuh_database", "sleep", 0, 86400);

    if (data.sync_agents || data.sync_syscheck || data.sync_rootcheck) {
        os_calloc(1, sizeof(wmodule), module);
        os_calloc(1, sizeof(wm_database), module->data);
        module->context = &WM_DATABASE_CONTEXT;
        memcpy(module->data, &data, sizeof(wm_database));
    }

    return module;
#endif
}
