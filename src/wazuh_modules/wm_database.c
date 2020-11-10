/*
 * Wazuh Module for SQLite database syncing
 * Copyright (C) 2015-2020, Wazuh Inc.
 * November 29, 2016
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include "sec.h"
#include "remoted_op.h"
#include "wazuh_db/wdb.h"
#include "addagent/manage_agents.h" // FILE_SIZE
#include "external/cJSON/cJSON.h"

#ifndef CLIENT

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>

#define IN_BUFFER_SIZE sizeof(struct inotify_event) + NAME_MAX + 1

static volatile unsigned int queue_i;
static volatile unsigned int queue_j;
static w_queue_t * queue;                 // Queue for pending files
static OSHash * ptable;                 // Table for pending paths
static pthread_mutex_t mutex_queue = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_pending = PTHREAD_COND_INITIALIZER;

int inotify_fd;

#ifndef LOCAL
int wd_agents = -2;
int wd_groups = -2;
int wd_shared_groups = -2;
#endif // !LOCAL

/* Get current inotify queued events limit */
static int get_max_queued_events();

/* Set current inotify queued events limit */
static int set_max_queued_events(int size);

// Setup inotify reader
static void wm_inotify_setup(wm_database * data);

// Real time inotify reader thread
static void * wm_inotify_start(void * args);

// Insert request into internal structure
void wm_inotify_push(const char * dirname, const char * fname);

// Extract enqueued path from internal structure
char * wm_inotify_pop();

#endif // INOTIFY_ENABLED

wm_database *module;
int wdb_wmdb_sock = -1;

// Module main function. It won't return
static void* wm_database_main(wm_database *data);
// Destroy data
static void* wm_database_destroy(wm_database *data);
// Read config
cJSON *wm_database_dump(const wm_database *data);
// Update manager information
static void wm_sync_manager();

#ifndef LOCAL

static void wm_check_agents();

// Synchronize agents and groups
static void wm_sync_agents();

// Clean dangling database files
static void wm_clean_dangling_db();

static void wm_sync_multi_groups(const char *dirname);

#endif // LOCAL

static int wm_sync_agent_group(int id_agent, const char *fname);
static int wm_sync_shared_group(const char *fname);
static void wm_scan_directory(const char *dirname);
static int wm_sync_file(const char *dirname, const char *path);

// Database module context definition
const wm_context WM_DATABASE_CONTEXT = {
    "database",
    (wm_routine)wm_database_main,
    (wm_routine)wm_database_destroy,
    (cJSON * (*)(const void *))wm_database_dump
};

// Module main function. It won't return
void* wm_database_main(wm_database *data) {
    module = data;

    mtinfo(WM_DATABASE_LOGTAG, "Module started.");

    // Reset template. Basically, remove queue/db/.template.db
    char path_template[PATH_MAX + 1];
    snprintf(path_template, sizeof(path_template), "%s/%s/%s", DEFAULTDIR, WDB_DIR, WDB_PROF_NAME);
    unlink(path_template);
    mdebug1("Template db file removed: %s", path_template);

    // Manager name synchronization
    if (data->sync_agents) {
        wm_sync_manager();
    }

#ifndef LOCAL
    wm_clean_dangling_db();
#endif

#ifdef INOTIFY_ENABLED
    if (data->real_time) {
        char * path;
        char * file;

        wm_inotify_setup(data);

        while (1) {
            path = wm_inotify_pop();

#ifndef LOCAL
            if (!strcmp(path, KEYSFILE_PATH)) {
                wm_sync_agents();
            } else
#endif // !LOCAL
            {
                if (file = strrchr(path, '/'), file) {
                    *(file++) = '\0';
                    wm_sync_file(path, file);
                } else {
                    mterror(WM_DATABASE_LOGTAG, "Couldn't extract file name from '%s'", path);
                }
            }

            free(path);
        }
    } else {
#endif // INOTIFY_ENABLED

        // Systems that don't support inotify, or real-time disabled

        long long tsleep;
        long long tstart;
        clock_t cstart;
        struct timespec spec0;
        struct timespec spec1;

        while (1) {
            tstart = (long long) time(NULL);
            cstart = clock();
            gettime(&spec0);

#ifndef LOCAL
            if (data->sync_agents) {
                wm_check_agents();
                wm_scan_directory(DEFAULTDIR GROUPS_DIR);
                wm_sync_multi_groups(DEFAULTDIR SHAREDCFG_DIR);
            }
#endif
            gettime(&spec1);
            time_sub(&spec1, &spec0);
            mtdebug1(WM_DATABASE_LOGTAG, "Cycle completed: %.3lf ms (%.3f clock ms).", spec1.tv_sec * 1000 + spec1.tv_nsec / 1000000.0, (double)(clock() - cstart) / CLOCKS_PER_SEC * 1000);

            if (tsleep = tstart + (long long) data->interval - (long long) time(NULL), tsleep >= 0) {
                sleep(tsleep);
            } else {
                mtwarn(WM_DATABASE_LOGTAG, "Time interval exceeded by %lld seconds.", -tsleep);
            }
        }
#ifdef INOTIFY_ENABLED
    }
#endif

    return NULL;
}

// Update manager information
void wm_sync_manager() {
    agent_info_data *manager_data = NULL;
    char *os_uname = NULL;

    os_calloc(1, sizeof(agent_info_data), manager_data);
    os_calloc(1, sizeof(os_data), manager_data->osd);
    os_calloc(HOST_NAME_MAX, sizeof(char), manager_data->manager_host);

    if (gethostname(manager_data->manager_host, HOST_NAME_MAX) == 0)
        wdb_update_agent_name(0, manager_data->manager_host, &wdb_wmdb_sock);
    else
        mterror(WM_DATABASE_LOGTAG, "Couldn't get manager's hostname: %s.", strerror(errno));

    /* Get node name of the manager in cluster */
    const char *(xml_node[]) = {"ossec_config", "cluster", "node_name", NULL};

    OS_XML xml;

    if (OS_ReadXML(DEFAULTCPATH, &xml) < 0){
        merror_exit(XML_ERROR, DEFAULTCPATH, xml.err, xml.err_line);
    }

    manager_data->node_name = OS_GetOneContentforElement(&xml, xml_node);

    OS_ClearXML(&xml);

    if ((os_uname = strdup(getuname()))) {
        char *ptr;

        if ((ptr = strstr(os_uname, " - ")))
            *ptr = '\0';

        parse_uname_string(os_uname, manager_data->osd);

        manager_data->id = 0;
        os_strdup(os_uname, manager_data->osd->os_uname);
        os_strdup(__ossec_name " " __ossec_version, manager_data->version);
        os_strdup("synced", manager_data->sync_status);

        wdb_update_agent_data(manager_data, &wdb_wmdb_sock);

        os_free(os_uname);
    }

    wdb_free_agent_info_data(manager_data);
}

#ifndef LOCAL

void wm_check_agents() {
    static time_t timestamp = 0;
    static ino_t inode = 0;
    struct stat buffer;

    if (stat(KEYSFILE_PATH, &buffer) < 0) {
        mterror(WM_DATABASE_LOGTAG, "Couldn't get client.keys stat: %s.", strerror(errno));
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
    char * group;
    char cidr[20];
    keystore keys = KEYSTORE_INITIALIZER;
    keyentry *entry;
    int *agents;
    clock_t clock0 = clock();
    struct timespec spec0;
    struct timespec spec1;

    gettime(&spec0);

    mtdebug1(WM_DATABASE_LOGTAG, "Synchronizing agents.");
    OS_PassEmptyKeyfile();
    OS_ReadKeys(&keys, 0, 0);

    os_calloc(OS_SIZE_65536 + 1, sizeof(char), group);

    /* Insert new entries */

    for (i = 0; i < keys.keysize; i++) {
        entry = keys.keyentries[i];
        int id;

        mtdebug2(WM_DATABASE_LOGTAG, "Synchronizing agent %s '%s'.", entry->id, entry->name);

        if (!(id = atoi(entry->id))) {
            mterror(WM_DATABASE_LOGTAG, "At wm_sync_agents(): invalid ID number.");
            continue;
        }

        if (get_agent_group(entry->id, group, OS_SIZE_65536 + 1) < 0) {
            *group = 0;
        }

        if (wdb_insert_agent(id, entry->name, NULL, OS_CIDRtoStr(entry->ip, cidr, 20) ?
                             entry->ip->ip : cidr, entry->key, *group ? group : NULL,1, &wdb_wmdb_sock)) {
            // The agent already exists, update group only.
            wm_sync_agent_group(id, entry->id);
        }
    }

    /* Delete old keys */

    if ((agents = wdb_get_all_agents(FALSE, &wdb_wmdb_sock))) {
        char id[9];

        for (i = 0; agents[i] != -1; i++) {
            snprintf(id, 9, "%03d", agents[i]);

            if (OS_IsAllowedID(&keys, id) == -1) {
                if (wdb_remove_agent(agents[i], &wdb_wmdb_sock) < 0) {
                    mtdebug1(WM_DATABASE_LOGTAG, "Couldn't remove agent %s", id);
                }
            }
        }

        os_free(agents);
    }

    os_free(group);
    OS_FreeKeys(&keys);
    mtdebug1(WM_DATABASE_LOGTAG, "Agent sync completed.");
    gettime(&spec1);
    time_sub(&spec1, &spec0);
    mtdebug1(WM_DATABASE_LOGTAG, "wm_sync_agents(): %.3f ms (%.3f clock ms).", spec1.tv_sec * 1000 + spec1.tv_nsec / 1000000.0, (double)(clock() - clock0) / CLOCKS_PER_SEC * 1000);
}

// Clean dangling database files
void wm_clean_dangling_db() {
    char dirname[PATH_MAX + 1];
    char path[PATH_MAX + 1];
    char * end;
    char * name;
    struct dirent * dirent = NULL;
    DIR * dir;

    snprintf(dirname, sizeof(dirname), "%s%s/agents", isChroot() ? "/" : "", WDB_DIR);
    mtdebug1(WM_DATABASE_LOGTAG, "Cleaning directory '%s'.", dirname);

    if (!(dir = opendir(dirname))) {
        mterror(WM_DATABASE_LOGTAG, "Couldn't open directory '%s': %s.", dirname, strerror(errno));
        return;
    }

    while ((dirent = readdir(dir)) != NULL) {
        if (dirent->d_name[0] != '.') {
            if (end = strchr(dirent->d_name, '-'), end) {
                *end = 0;

                if (name = wdb_get_agent_name(atoi(dirent->d_name), &wdb_wmdb_sock), name) {
                    // Agent found: OK
                    free(name);
                } else {
                    *end = '-';

                    if (snprintf(path, sizeof(path), "%s/%s", dirname, dirent->d_name) < (int)sizeof(path)) {
                        mtwarn(WM_DATABASE_LOGTAG, "Removing dangling DB file: '%s'", path);
                        if (remove(path) < 0) {
                            mtdebug1(WM_DATABASE_LOGTAG, DELETE_ERROR, path, errno, strerror(errno));
                        }
                    }
                }
            } else {
                mtwarn(WM_DATABASE_LOGTAG, "Strange file found: '%s/%s'", dirname, dirent->d_name);
            }
        }
    }

    closedir(dir);
}

void wm_sync_multi_groups(const char *dirname) {

    wdb_update_groups(dirname, &wdb_wmdb_sock);
}

#endif // LOCAL

int wm_sync_agent_group(int id_agent, const char *fname) {
    int result = 0;
    char *group;
    os_calloc(OS_SIZE_65536 + 1, sizeof(char), group);
    clock_t clock0 = clock();

    get_agent_group(fname, group, OS_SIZE_65536);

    if (OS_SUCCESS != wdb_update_agent_group(id_agent, *group ? group : NULL, &wdb_wmdb_sock)) {
        mterror(WM_DATABASE_LOGTAG, "Couldn't sync agent '%s' group.", fname);
        wdb_delete_agent_belongs(id_agent, &wdb_wmdb_sock);
        result = -1;
    }

    mtdebug2(WM_DATABASE_LOGTAG, "wm_sync_agent_group(%d): %.3f ms.", id_agent, (double)(clock() - clock0) / CLOCKS_PER_SEC * 1000);

    free(group);
    return result;
}

int wm_sync_shared_group(const char *fname) {
    int result = 0;
    char path[PATH_MAX];
    DIR *dp;
    clock_t clock0 = clock();

    snprintf(path,PATH_MAX, "%s/%s",DEFAULTDIR SHAREDCFG_DIR,fname);

    dp = opendir(path);

    /* The group was deleted */
    if (!dp) {
        wdb_remove_group_db(fname, &wdb_wmdb_sock);
    }
    else {
        if(wdb_find_group(fname, &wdb_wmdb_sock) <= 0){
            wdb_insert_group(fname, &wdb_wmdb_sock);
        }
        closedir(dp);
    }
    mtdebug2(WM_DATABASE_LOGTAG, "wm_sync_shared_group(): %.3f ms.", (double)(clock() - clock0) / CLOCKS_PER_SEC * 1000);
    return result;
}

void wm_scan_directory(const char *dirname) {
    char path[PATH_MAX];
    struct dirent *dirent = NULL;
    DIR *dir;

    mtdebug1(WM_DATABASE_LOGTAG, "Scanning directory '%s'.", dirname);
    snprintf(path, PATH_MAX, "%s", dirname);

    if (!(dir = opendir(path))) {
        mterror(WM_DATABASE_LOGTAG, "Couldn't open directory '%s': %s.", path, strerror(errno));
        return;
    }

    while ((dirent = readdir(dir)) != NULL)
        if (dirent->d_name[0] != '.')
            wm_sync_file(dirname, dirent->d_name);

    closedir(dir);
}

int wm_sync_file(const char *dirname, const char *fname) {
    char path[PATH_MAX] = "";
    char del_path[PATH_MAX] = "";
    int result = 0;
    int id_agent = -1;
    int type;

    mtdebug2(WM_DATABASE_LOGTAG, "Synchronizing file '%s/%s'", dirname, fname);

    if (snprintf(path, PATH_MAX, "%s/%s", dirname, fname) >= PATH_MAX) {
        mterror(WM_DATABASE_LOGTAG, "At wm_sync_file(): Path '%s/%s' exceeded length limit.", dirname, fname);
        return -1;
    }

    if (!strcmp(dirname, DEFAULTDIR GROUPS_DIR)) {
        type = WDB_GROUPS;
    } else if (!strcmp(dirname, DEFAULTDIR SHAREDCFG_DIR)) {
        type = WDB_SHARED_GROUPS;
    } else {
        mterror(WM_DATABASE_LOGTAG, "Directory name '%s' not recognized.", dirname);
        return -1;
    }

    switch (type) {

    case WDB_GROUPS:
        id_agent = atoi(fname);

        if (!id_agent) {
            mterror(WM_DATABASE_LOGTAG, "Couldn't extract agent ID from file %s/%s", dirname, fname);
            return -1;
        }

        if (wdb_get_agent_status(id_agent, &wdb_wmdb_sock) < 0) {
            snprintf(del_path, PATH_MAX - 1, DEFAULTDIR GROUPS_DIR "/%03d", id_agent);
            unlink(del_path);
            wdb_delete_agent_belongs(id_agent, &wdb_wmdb_sock);
            return -1;
        }

        break;

    case WDB_SHARED_GROUPS:
        id_agent = 0;
        break;
    }

    switch (wdb_get_agent_status(id_agent, &wdb_wmdb_sock)) {
    case -1:
        mterror(WM_DATABASE_LOGTAG, "Couldn't get database status for agent '%d'.", id_agent);
        return -1;
    case WDB_AGENT_PENDING:
        mtwarn(WM_DATABASE_LOGTAG, "Agent '%d' database status was 'pending'. Data could be lost.", id_agent);
        wdb_set_agent_status(id_agent, WDB_AGENT_UPDATED, &wdb_wmdb_sock);
        break;
    }

    switch (type) {
    case WDB_GROUPS:
        result = wm_sync_agent_group(id_agent, fname);
        break;

    case WDB_SHARED_GROUPS:
        result = wm_sync_shared_group(fname);
        break;
    }

    return result;
}


// Get read data

cJSON *wm_database_dump(const wm_database *data) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_db = cJSON_CreateObject();

    if (data->sync_agents) cJSON_AddStringToObject(wm_db,"sync_agents","yes"); else cJSON_AddStringToObject(wm_db,"sync_agents","no");
    if (data->real_time) cJSON_AddStringToObject(wm_db,"real_time","yes"); else cJSON_AddStringToObject(wm_db,"real_time","no");
    cJSON_AddNumberToObject(wm_db,"interval",data->interval);
    cJSON_AddNumberToObject(wm_db,"max_queued_events",data->max_queued_events);

    cJSON_AddItemToObject(root,"database",wm_db);

    return root;
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
    data.real_time = getDefine_Int("wazuh_database", "real_time", 0, 1);
    data.interval = getDefine_Int("wazuh_database", "interval", 0, 86400);
    data.max_queued_events = getDefine_Int("wazuh_database", "max_queued_events", 0, INT_MAX);

    if (data.sync_agents) {
        os_calloc(1, sizeof(wmodule), module);
        os_calloc(1, sizeof(wm_database), module->data);
        module->context = &WM_DATABASE_CONTEXT;
        memcpy(module->data, &data, sizeof(wm_database));
        module->tag = strdup(module->context->name);
    }

    return module;
#endif
}

#ifdef INOTIFY_ENABLED

/* Get current inotify queued events limit */
int get_max_queued_events() {
    int size;
    int n;
    FILE *fp;

    if (!(fp = fopen(MAX_QUEUED_EVENTS_PATH, "r"))) {
        mterror(WM_DATABASE_LOGTAG, FOPEN_ERROR, MAX_QUEUED_EVENTS_PATH, errno, strerror(errno));
        return -1;
    }

    n = fscanf(fp, "%d", &size);
    fclose(fp);

    if (n == 1) {
        return size;
    } else {
        return -1;
    }
}

/* Set current inotify queued events limit */
int set_max_queued_events(int size) {
    FILE *fp;

    if (!(fp = fopen(MAX_QUEUED_EVENTS_PATH, "w"))) {
        mterror(WM_DATABASE_LOGTAG, FOPEN_ERROR, MAX_QUEUED_EVENTS_PATH, errno, strerror(errno));
        return -1;
    }

    fprintf(fp, "%d\n", size);
    fclose(fp);
    return 0;
}

// Setup inotify reader
void wm_inotify_setup(wm_database * data) {
    int old_max_queued_events = -1;

    // Create hash table

    if (ptable = OSHash_Create(), !ptable) {
        merror_exit("At wm_inotify_setup(): OSHash_Create()");
    }

    // Create queue
    if (queue = queue_init(data->max_queued_events > 0 ? data->max_queued_events : 16384), !queue) {
        merror_exit("At wm_inotify_setup(): queue_init()");
    }

    // Set inotify queued events limit

    if (data->max_queued_events) {
        old_max_queued_events = get_max_queued_events();

        if (old_max_queued_events >= 0 && old_max_queued_events != data->max_queued_events) {
            mtdebug1(WM_DATABASE_LOGTAG, "Setting inotify queued events limit to '%d'", data->max_queued_events);

            if (set_max_queued_events(data->max_queued_events) < 0) {
                // Error: do not reset then
                old_max_queued_events = -1;
            }
        }
    }

    // Start inotify

    if (inotify_fd = inotify_init1(IN_CLOEXEC), inotify_fd < 0) {
        mterror_exit(WM_DATABASE_LOGTAG, "Couldn't init inotify: %s.", strerror(errno));
    }

    // Reset inotify queued events limit

    if (old_max_queued_events >= 0 && old_max_queued_events != data->max_queued_events) {
        mtdebug2(WM_DATABASE_LOGTAG, "Restoring inotify queued events limit to '%d'", old_max_queued_events);
        set_max_queued_events(old_max_queued_events);
    }

    // Run thread
    w_create_thread(wm_inotify_start, NULL);

    // First synchronization and add watch for client.keys, Syscheck and Rootcheck directories

#ifndef LOCAL

    char keysfile_path[] = KEYSFILE_PATH;
    char * keysfile_dir = dirname(keysfile_path);

    if (data->sync_agents) {
        if ((wd_agents = inotify_add_watch(inotify_fd, keysfile_dir, IN_CLOSE_WRITE | IN_MOVED_TO)) < 0)
            mterror(WM_DATABASE_LOGTAG, "Couldn't watch client.keys file: %s.", strerror(errno));

        mtdebug2(WM_DATABASE_LOGTAG, "wd_agents='%d'", wd_agents);

        if ((wd_groups = inotify_add_watch(inotify_fd, DEFAULTDIR GROUPS_DIR, IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE)) < 0)
            mterror(WM_DATABASE_LOGTAG, "Couldn't watch the agent groups directory: %s.", strerror(errno));

        mtdebug2(WM_DATABASE_LOGTAG, "wd_groups='%d'", wd_groups);

        if ((wd_shared_groups = inotify_add_watch(inotify_fd, DEFAULTDIR SHAREDCFG_DIR, IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_CREATE | IN_DELETE)) < 0)
            mterror(WM_DATABASE_LOGTAG, "Couldn't watch the shared groups directory: %s.", strerror(errno));

        mtdebug2(WM_DATABASE_LOGTAG, "wd_shared_groups='%d'", wd_shared_groups);

        wm_sync_agents();
        wm_sync_multi_groups(DEFAULTDIR SHAREDCFG_DIR);
        wdb_agent_belongs_first_time(&wdb_wmdb_sock);
    }

#endif
}

// Real time inotify reader thread
static void * wm_inotify_start(__attribute__((unused)) void * args) {
    char buffer[IN_BUFFER_SIZE];
    char keysfile_dir[] = KEYSFILE_PATH;
    char * keysfile;
    struct inotify_event *event;
    char * dirname = NULL;
    ssize_t count;
    size_t i;

    if (!(keysfile = strrchr(keysfile_dir, '/'))) {
        mterror_exit(WM_DATABASE_LOGTAG, "Couldn't decode keys file path '%s'.", keysfile_dir);
    }

    *(keysfile++) = '\0';

    while (1) {
        // Wait for changes

        mtdebug1(WM_DATABASE_LOGTAG, "Waiting for event notification...");

        do {
            if (count = read(inotify_fd, buffer, IN_BUFFER_SIZE), count < 0) {
                if (errno != EAGAIN)
                    mterror(WM_DATABASE_LOGTAG, "read(): %s.", strerror(errno));

                break;
            }

            buffer[count - 1] = '\0';

            for (i = 0; i < (size_t)count; i += (ssize_t)(sizeof(struct inotify_event) + event->len)) {
                event = (struct inotify_event*)&buffer[i];
                mtdebug2(WM_DATABASE_LOGTAG, "inotify: i='%zu', name='%s', mask='%u', wd='%d'", i, event->name, event->mask, event->wd);

                if (event->len > IN_BUFFER_SIZE) {
                    mterror(WM_DATABASE_LOGTAG, "Inotify event too large (%u)", event->len);
                    break;
                }

                if (event->name[0] == '.') {
                    mtdebug2(WM_DATABASE_LOGTAG, "Discarding hidden file.");
                    continue;
                }
#ifndef LOCAL
                if (event->wd == wd_agents) {
                    if (!strcmp(event->name, keysfile)) {
                        dirname = keysfile_dir;
                    } else {
                        continue;
                    }
                } else if (event->wd == wd_groups) {
                    dirname = DEFAULTDIR GROUPS_DIR;
                } else if (event->wd == wd_shared_groups) {
                    dirname = DEFAULTDIR SHAREDCFG_DIR;
                } else
#endif
                if (event->wd == -1 && event->mask == IN_Q_OVERFLOW) {
                    mterror(WM_DATABASE_LOGTAG, "Inotify event queue overflowed.");
                    continue;
                } else {
                    mterror(WM_DATABASE_LOGTAG, "Unknown watch descriptor '%d', mask='%u'.", event->wd, event->mask);
                    continue;
                }

                wm_inotify_push(dirname, event->name);
            }
        } while (count > 0);
    }

    return NULL;
}

// Insert request into internal structure
void wm_inotify_push(const char * dirname, const char * fname) {
    char path[PATH_MAX + 1];
    char * dup;

    if (snprintf(path, sizeof(path), "%s/%s", dirname, fname) >= (int)sizeof(path)) {
        mterror(WM_DATABASE_LOGTAG, "At wm_inotify_push(): Path too long: '%s'/'%s'", dirname, fname);
        return;
    }

    w_mutex_lock(&mutex_queue);

    if (queue_full(queue)) {
        mterror(WM_DATABASE_LOGTAG, "Internal queue is full (%zu).", queue->size);
        goto end;
    }

    switch (OSHash_Add(ptable, path, (void *)1)) {
    case 0:
        mterror(WM_DATABASE_LOGTAG, "Couldn't insert key into table.");
        break;

    case 1:
        mtdebug2(WM_DATABASE_LOGTAG, "Adding '%s': file already exists at path table.", path);
        break;

    case 2:
        os_strdup(path, dup);
        mtdebug2(WM_DATABASE_LOGTAG, "Adding '%s' to path table.", path);

        if (queue_push(queue, dup) < 0) {
            mterror(WM_DATABASE_LOGTAG, "Couldn't insert key into queue.");
            free(dup);
        }

        w_cond_signal(&cond_pending);
    }

end:
    w_mutex_unlock(&mutex_queue);
}

// Extract enqueued path from internal structure
char * wm_inotify_pop() {
    char * path;

    w_mutex_lock(&mutex_queue);

    while (queue_empty(queue)) {
        w_cond_wait(&cond_pending, &mutex_queue);
    }

    path = queue_pop(queue);

    if (!OSHash_Delete(ptable, path)) {
        mterror(WM_DATABASE_LOGTAG, "Couldn't delete key '%s' from path table.", path);
    }

    w_mutex_unlock(&mutex_queue);
    mtdebug2(WM_DATABASE_LOGTAG, "Taking '%s' from path table.", path);
    return path;
}

#endif // INOTIFY_ENABLED

#endif // !WIN32
