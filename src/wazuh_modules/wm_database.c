/*
 * Wazuh Module for SQLite database syncing
 * Copyright (C) 2015, Wazuh Inc.
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
#include "wazuh_db/helpers/wdb_global_helpers.h"
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
int is_worker;
int wdb_wmdb_sock = -1;

// Module main function. It won't return
static void* wm_database_main(wm_database *data);
// Destroy data
static void wm_database_destroy(wm_database *data);
// Read config
cJSON *wm_database_dump(const wm_database *data);
// Run a query
static size_t wm_database_query(wm_database *data, char *query, char **output);
// Update manager information
static void wm_sync_manager();

#ifndef LOCAL

static void wm_check_agents();

/**
 * @brief Method to synchronize 'client.keys' and 'global.db'. All new agents found
 *        in 'client.keys will be added to the DB and any agent in the DB that doesn't
 *        have a key will be removed.
 *        This method will also create and remove the agents artifacts according to
 *        the action taken in the database with the agent.
 */
static void wm_sync_agents();

// Clean dangling database files
static void wm_clean_dangling_wdb_dbs();

#endif // LOCAL

static int wm_sync_shared_group(const char *fname);
static int wm_sync_file(const char *dirname, const char *path);

// Database module context definition
const wm_context WM_DATABASE_CONTEXT = {
    .name = "database",
    .start = (wm_routine)wm_database_main,
    .destroy = (void(*)(void *))wm_database_destroy,
    .dump = (cJSON * (*)(const void *))wm_database_dump,
    .sync = NULL,
    .stop = NULL,
    .query = (size_t (*)(void *, char *, char **))wm_database_query,
};

// Module main function. It won't return
void* wm_database_main(wm_database *data) {
    module = data;

    mtinfo(WM_DATABASE_LOGTAG, "Module started.");

    // Check if it is a worker node
    is_worker = w_is_worker();

    // Manager name synchronization
    wm_sync_manager();

    // During the startup, both workers and master nodes should perform the
    // agents synchronization with the database using the keys. In advance,
    // the agent addition and removal from the database will be held by authd
    // in the master.
#ifndef LOCAL
    wm_sync_agents();
#endif

    // Groups synchronization with the database
    wdb_update_groups(SHAREDCFG_DIR, &wdb_wmdb_sock);

    // Legacy agent-group files need to be synchronized with the database
    // and then removed in case an upgrade has just been performed.
#ifndef LOCAL
    wm_sync_legacy_groups_files();

    // Remove dangling agent databases
    wm_clean_dangling_wdb_dbs();
#endif

#ifdef INOTIFY_ENABLED
    if (data->real_time) {
        char * path;
        char * file;

        wm_inotify_setup(data);

        while (1) {
            path = wm_inotify_pop();

#ifndef LOCAL
            if (!strcmp(path, KEYS_FILE)) {
                // The syncronization with client.keys only happens in worker nodes
                if (is_worker) {
                    wm_sync_agents();
                }
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

        // Initial wait
        sleep(data->interval);

        while (1) {
            tstart = (long long) time(NULL);
            cstart = clock();
            gettime(&spec0);

#ifndef LOCAL
            if (data->sync_agents) {
                wm_check_agents();
                wdb_update_groups(SHAREDCFG_DIR, &wdb_wmdb_sock);
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
    manager_data->node_name = get_node_name();

    if ((os_uname = strdup(getuname()))) {
        char *ptr;

        if ((ptr = strstr(os_uname, " - ")))
            *ptr = '\0';

        parse_uname_string(os_uname, manager_data->osd);

        manager_data->id = 0;
        os_strdup(os_uname, manager_data->osd->os_uname);
        os_strdup(__ossec_name " " __ossec_version, manager_data->version);
        os_strdup(AGENT_CS_ACTIVE, manager_data->connection_status);
        os_strdup("synced", manager_data->sync_status);
        os_strdup("synced", manager_data->group_config_status);

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

    if (stat(KEYS_FILE, &buffer) < 0) {
        mterror(WM_DATABASE_LOGTAG, "Couldn't get client.keys stat: %s.", strerror(errno));
    } else {
        if (buffer.st_mtime != timestamp || buffer.st_ino != inode) {
            /* Synchronize */
            if (is_worker) {
                wm_sync_agents();
            }
            timestamp = buffer.st_mtime;
            inode = buffer.st_ino;
        }
    }
}

// Synchronize agents
void wm_sync_agents() {
    static pthread_mutex_t mutex_sync = PTHREAD_MUTEX_INITIALIZER;
    keystore keys = KEYSTORE_INITIALIZER;
    clock_t clock0 = clock();
    struct timespec spec0;
    struct timespec spec1;

    w_mutex_lock(&mutex_sync);
    gettime(&spec0);

    mtdebug1(WM_DATABASE_LOGTAG, "Synchronizing agents.");
    OS_PassEmptyKeyfile();
    OS_ReadKeys(&keys, W_RAW_KEY, 0);

    sync_keys_with_wdb(&keys);

    OS_FreeKeys(&keys);
    mtdebug1(WM_DATABASE_LOGTAG, "Agents synchronization completed.");
    gettime(&spec1);
    time_sub(&spec1, &spec0);
    w_mutex_unlock(&mutex_sync);
    mtdebug1(WM_DATABASE_LOGTAG, "wm_sync_agents(): %.3f ms (%.3f clock ms).", spec1.tv_sec * 1000 + spec1.tv_nsec / 1000000.0, (double)(clock() - clock0) / CLOCKS_PER_SEC * 1000);
}

/**
 * @brief Synchronizes a keystore with the agent table of global.db. It will insert
 *        the agents that are in the keystore and are not in global.db.
 *        In addition it will remove from global.db in wazuh-db all the agents that
 *        are not in the keystore. Also it will remove all the artifacts for those
 *        agents.
 *
 * @param keys The keystore structure to be synchronized
 */
void sync_keys_with_wdb(keystore *keys) {
    rb_tree *agents = NULL;
    char **ids = NULL;
    unsigned int i;

    agents = wdb_get_all_agents_rbtree(FALSE, &wdb_wmdb_sock);

    if (agents == NULL) {
        mterror(WM_DATABASE_LOGTAG, "Couldn't synchronize the keystore with the DB.");
        return;
    }

    // Add new agents to the database
    for (i = 0; i < keys->keysize; i++) {
        keyentry *entry = keys->keyentries[i];
        int agent_id = atoi(entry->id);

        if (agent_id && (rbtree_get(agents, entry->id) == NULL)) {
            char agent_cidr[IPSIZE + 1];

            mtdebug2(WM_DATABASE_LOGTAG, "Synchronizing agent %s '%s'.", entry->id, entry->name);

            if (wdb_insert_agent(agent_id, entry->name, NULL, OS_CIDRtoStr(entry->ip, agent_cidr, IPSIZE) ?
                                entry->ip->ip : agent_cidr, entry->raw_key, NULL, 1, &wdb_wmdb_sock)) {
                mtdebug1(WM_DATABASE_LOGTAG, "Couldn't insert agent '%s' in the database.", entry->id);
            }
        }
    }

    ids = rbtree_keys(agents);

    // Delete from the database all the agents without a key and all its artifacts
    for (i = 0; ids[i] != NULL; i++) {
        int agent_id = atoi(ids[i]);

        if (agent_id && (OS_IsAllowedID(keys, ids[i]) == -1)) {
            char *agent_name = wdb_get_agent_name(agent_id, &wdb_wmdb_sock);

            if (wdb_remove_agent(agent_id, &wdb_wmdb_sock) < 0) {
                mtdebug1(WM_DATABASE_LOGTAG, "Couldn't remove agent '%s' from the database.", ids[i]);
                os_free(agent_name);
                continue;
            }

            // Agent not found. Removing agent artifacts
            wm_clean_agent_artifacts(agent_id, agent_name);

            // Remove agent-related files
            OS_RemoveCounter(ids[i]);
            OS_RemoveAgentTimestamp(ids[i]);

            os_free(agent_name);
        }
    }

    free_strarray(ids);
    rbtree_destroy(agents);
}

/**
 * @brief This function removes the wazuh-db agent DB and the diff folder of an agent.
 *
 * @param agent_id The ID of the agent.
 * @param agent_name The name of the agent.
 */
void wm_clean_agent_artifacts(int agent_id, const char* agent_name) {
    int result = OS_INVALID;

    // Removing wazuh-db database
    char wdbquery[OS_SIZE_128 + 1];
    char wdboutput[OS_SIZE_1024];
    snprintf(wdbquery, OS_SIZE_128, "wazuhdb remove %d", agent_id);
    if (result = wdbc_query_ex(&wdb_wmdb_sock, wdbquery, wdboutput, sizeof(wdboutput)), result) {
        mtdebug1(WM_DATABASE_LOGTAG, "Could not remove the wazuh-db DB of the agent %d.", agent_id);
    }

    delete_diff(agent_name);
}

// Clean dangling database files
void wm_clean_dangling_wdb_dbs() {
    char path[PATH_MAX];
    char * end = NULL;
    char * name = NULL;
    struct dirent * dirent = NULL;
    DIR * dir;

    if (!(dir = opendir(WDB2_DIR))) {
        mterror(WM_DATABASE_LOGTAG, "Couldn't open directory '%s': %s.", WDB2_DIR, strerror(errno));
        return;
    }

    while ((dirent = readdir(dir)) != NULL) {
        // Taking only databases with numbers as a first character in the names to
        // exclude global.db, global.db-journal, wdb socket, and current directory.
        if (dirent->d_name[0] >= '0' && dirent->d_name[0] <= '9') {
            if (end = strchr(dirent->d_name, '.'), end) {
                int id = (int)strtol(dirent->d_name, &end, 10);

                if (id > 0 && strncmp(end, ".db", 3) == 0 && (name = wdb_get_agent_name(id, &wdb_wmdb_sock)) != NULL) {
                    if (*name == '\0') {
                        // Agent not found.

                        if (snprintf(path, sizeof(path), "%s/%s", WDB2_DIR, dirent->d_name) < (int)sizeof(path)) {
                            mtwarn(WM_DATABASE_LOGTAG, "Removing dangling WDB DB file: '%s'", path);
                            if (remove(path) < 0) {
                                mtdebug1(WM_DATABASE_LOGTAG, DELETE_ERROR, path, errno, strerror(errno));
                            }
                        }
                    }

                    free(name);
                }
            } else {
                mtwarn(WM_DATABASE_LOGTAG, "Strange file found: '%s/%s'", WDB2_DIR, dirent->d_name);
            }
        }
    }

    closedir(dir);
}

void wm_sync_legacy_groups_files() {
    DIR *dir = opendir(GROUPS_DIR);

    if (!dir) {
        mtdebug1(WM_DATABASE_LOGTAG, "Couldn't open directory '%s': %s.", GROUPS_DIR, strerror(errno));
        return;
    }

    mtdebug1(WM_DATABASE_LOGTAG, "Scanning directory '%s'.", GROUPS_DIR);

    struct dirent *dir_entry = NULL;
    int sync_result = OS_INVALID;
    char group_file_path[OS_SIZE_512] = {0};
    bool is_dir_empty = true;

    while ((dir_entry = readdir(dir)) != NULL) {
        if (dir_entry->d_name[0] != '.') {
            snprintf(group_file_path, OS_SIZE_512, "%s/%s", GROUPS_DIR, dir_entry->d_name);

            if (is_worker) {
                mtdebug1(WM_DATABASE_LOGTAG, "Group file '%s' won't be synced in a worker node, removing.", group_file_path);
                unlink(group_file_path);
            } else {
                sync_result = wm_sync_group_file(dir_entry->d_name, group_file_path);

                if (OS_SUCCESS == sync_result) {
                    mtdebug1(WM_DATABASE_LOGTAG, "Group file '%s' successfully synced, removing.", group_file_path);
                    unlink(group_file_path);
                } else {
                    merror("Failed during the groups file '%s' syncronization.", group_file_path);
                    is_dir_empty = false;
                }
            }
        }
    }
    closedir(dir);

    if (is_dir_empty) {
        if (rmdir_ex(GROUPS_DIR)) {
            mtdebug1(WM_DATABASE_LOGTAG, "Unable to remove directory '%s': '%s' (%d)", GROUPS_DIR, strerror(errno), errno);
        }
    }
}

int wm_sync_group_file(const char* group_file, const char* group_file_path) {
    int id_agent = atoi(group_file);

    if (id_agent <= 0) {
        mtdebug1(WM_DATABASE_LOGTAG, "Couldn't extract agent ID from file '%s'.", group_file_path);
        return OS_INVALID;
    }

    FILE *fp = wfopen(group_file_path, "r");

    if (!fp) {
        mtdebug1(WM_DATABASE_LOGTAG, "Groups file '%s' could not be opened for syncronization.", group_file_path);
        return OS_INVALID;
    }

    char *groups_csv = NULL;
    os_calloc(OS_SIZE_65536 + 1, sizeof(char), groups_csv);
    int result = OS_INVALID;

    if (fgets(groups_csv, OS_SIZE_65536, fp)) {
        char *endl = strchr(groups_csv, '\n');
        if (endl) {
            *endl = '\0';
        }

        char** groups_array = w_string_split(groups_csv, ",", 0);
        size_t groups_array_size = strarray_size(groups_array);
        char** truncated_groups_array = NULL;
        if (groups_array_size > MAX_GROUPS_PER_MULTIGROUP) {
            truncated_groups_array = groups_array + (groups_array_size - MAX_GROUPS_PER_MULTIGROUP);
        }
        else {
            truncated_groups_array = groups_array;
        }
        result = wdb_set_agent_groups(id_agent,
                                      truncated_groups_array,
                                      "override",
                                      w_is_single_node(NULL) ? "synced" : "syncreq",
                                      &wdb_wmdb_sock);

        free_strarray(groups_array);
    } else {
        mtdebug1(WM_DATABASE_LOGTAG, "Empty group file '%s'.", group_file_path);
        result = OS_SUCCESS;
    }

    fclose(fp);
    os_free(groups_csv);

    return result;
}

#endif // LOCAL

int wm_sync_shared_group(const char *fname) {
    char path[PATH_MAX];
    DIR *dp = NULL;
    clock_t clock0 = clock();

    snprintf(path, PATH_MAX, "%s/%s", SHAREDCFG_DIR, fname);

    dp = opendir(path);
    if (!dp) {
        /* The group was deleted */
        wdb_remove_group_db(fname, &wdb_wmdb_sock);
    }
    else {
        if(wdb_find_group(fname, &wdb_wmdb_sock) <= 0) {
            wdb_insert_group(fname, &wdb_wmdb_sock);
        }
        closedir(dp);
    }

    mtdebug2(WM_DATABASE_LOGTAG, "wm_sync_shared_group(): %.3f ms.", (double)(clock() - clock0) / CLOCKS_PER_SEC * 1000);

    return OS_SUCCESS;
}

int wm_sync_file(const char *dirname, const char *fname) {
    char path[PATH_MAX] = "";
    int result = OS_INVALID;

    mtdebug2(WM_DATABASE_LOGTAG, "Synchronizing file '%s/%s'", dirname, fname);

    if (snprintf(path, PATH_MAX, "%s/%s", dirname, fname) >= PATH_MAX) {
        mterror(WM_DATABASE_LOGTAG, "At wm_sync_file(): Path '%s/%s' exceeded length limit.", dirname, fname);
        return result;
    }

    if (!strcmp(dirname, SHAREDCFG_DIR)) {
        result = wm_sync_shared_group(fname);
    } else {
        mterror(WM_DATABASE_LOGTAG, "Directory name '%s' not recognized.", dirname);
        return result;
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
void wm_database_destroy(wm_database *data) {
    free(data);
}

/**
 * @brief This function is used to run a query on the database module.
 *
 * @param data The database module data.
 * @param query The query to be executed.
 * @param output The output of the query.
 * @return The size of the output.
 */
static size_t wm_database_query(__attribute__((unused)) wm_database *data, char *query, char **output) {
    if (strcmp(query, "sync_agents") == 0) {
        if (is_worker) {
            wm_sync_agents();
            os_strdup("ok", *output);
        } else {
            os_strdup("err {\"error\":11,\"message\":\"Node is not a worker\"}", *output);
        }
    } else {
        os_strdup("err {\"error\":12,\"message\":\"Query not supported\"}", *output);
    }

    return strlen(*output);
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

    if (!(fp = wfopen(MAX_QUEUED_EVENTS_PATH, "r"))) {
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

    if (!(fp = wfopen(MAX_QUEUED_EVENTS_PATH, "w"))) {
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

    if (ptable = OSHash_Create(), !ptable) {
        merror_exit("At wm_inotify_setup(): OSHash_Create()");
    }

    if (queue = queue_init(data->max_queued_events > 0 ? data->max_queued_events : 16384), !queue) {
        merror_exit("At wm_inotify_setup(): queue_init()");
    }

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

    char keysfile_path[PATH_MAX] = KEYS_FILE;
    char * keysfile_dir = dirname(keysfile_path);

    if (data->sync_agents) {
        if ((wd_agents = inotify_add_watch(inotify_fd, keysfile_dir, IN_CLOSE_WRITE | IN_MOVED_TO)) < 0) {
            mterror(WM_DATABASE_LOGTAG, "Couldn't watch client.keys file: %s.", strerror(errno));
        }

        mtdebug2(WM_DATABASE_LOGTAG, "wd_agents='%d'", wd_agents);

        if ((wd_shared_groups = inotify_add_watch(inotify_fd, SHAREDCFG_DIR, IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_CREATE | IN_DELETE)) < 0) {
            mterror(WM_DATABASE_LOGTAG, "Couldn't watch the shared groups directory: %s.", strerror(errno));
        }

        mtdebug2(WM_DATABASE_LOGTAG, "wd_shared_groups='%d'", wd_shared_groups);
    }

#endif
}

// Real time inotify reader thread
static void * wm_inotify_start(__attribute__((unused)) void * args) {
    char buffer[IN_BUFFER_SIZE];
    char keysfile_dir[PATH_MAX] = KEYS_FILE;
    char * keysfile;
    struct inotify_event *event;
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
                char * dirname = NULL;
                char path[PATH_MAX + 1] = {0};
                event = (struct inotify_event*)&buffer[i];
                mtdebug2(WM_DATABASE_LOGTAG, "inotify: i='%zu', name='%s', mask='%u', wd='%d'", i, event->name, event->mask, event->wd);

                if (event->len > IN_BUFFER_SIZE) {
                    mterror(WM_DATABASE_LOGTAG, "Inotify event too large (%u)", event->len);
                    break;
                }
#ifndef LOCAL
                if (event->wd == wd_agents) {
                    if (!strcmp(event->name, keysfile)) {
                        dirname = keysfile_dir;
                    } else {
                        continue;
                    }
                } else if (event->wd == wd_shared_groups) {
                    dirname = SHAREDCFG_DIR;
                } else
#endif
                if (event->wd == -1 && event->mask == IN_Q_OVERFLOW) {
                    mterror(WM_DATABASE_LOGTAG, "Inotify event queue overflowed.");
                    continue;
                } else {
                    mterror(WM_DATABASE_LOGTAG, "Unknown watch descriptor '%d', mask='%u'.", event->wd, event->mask);
                    continue;
                }

                snprintf(path, PATH_MAX, "%s/%s", dirname, event->name);

                if (event->name[0] == '.' && IsDir(path)) {
                    mtdebug2(WM_DATABASE_LOGTAG, "Discarding hidden file.");
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
