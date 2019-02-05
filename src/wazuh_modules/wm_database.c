/*
 * Wazuh Module for SQLite database syncing
 * Copyright (C) 2015-2019, Wazuh Inc.
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
#include "external/cJSON/cJSON.h"

#ifndef WIN32

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
int wd_agentinfo = -2;
int wd_groups = -2;
int wd_shared_groups = -2;
#endif // !LOCAL
int wd_syscheck = -2;
int wd_rootcheck = -2;

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

// Module main function. It won't return
static void* wm_database_main(wm_database *data);
// Destroy data
static void* wm_database_destroy(wm_database *data);
// Read config
cJSON *wm_database_dump(const wm_database *data);
// Update manager information
static void wm_sync_manager();
// Get agent's architecture
static char * wm_get_os_arch(char * os_header);

#ifndef LOCAL

static void wm_check_agents();

// Synchronize agents and groups
static void wm_sync_agents();

// Clean dangling database files
static void wm_clean_dangling_db();

static void wm_sync_multi_groups(const char *dirname);

#endif // LOCAL

static int wm_sync_agentinfo(int id_agent, const char *path);
static int wm_sync_agent_group(int id_agent, const char *fname);
static int wm_sync_shared_group(const char *fname);
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
                wm_scan_directory(DEFAULTDIR AGENTINFO_DIR);
                wm_scan_directory(DEFAULTDIR GROUPS_DIR);
                wm_sync_multi_groups(DEFAULTDIR SHAREDCFG_DIR);
            }
#endif
            if (data->sync_syscheck) {
                wm_scan_directory(DEFAULTDIR SYSCHECK_DIR);
            }

            if (data->sync_rootcheck) {
                wm_scan_directory(DEFAULTDIR ROOTCHECK_DIR);
            }

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
    char hostname[1024];
    char *os_uname;
    const char *path;
    char *os_name = NULL;
    char *os_major = NULL;
    char *os_minor = NULL;
    char *os_build = NULL;
    char *os_version = NULL;
    char *os_codename = NULL;
    char *os_platform = NULL;
    char *os_arch = NULL;
    struct stat buffer;
    regmatch_t match[2];
    int match_size;

    if (gethostname(hostname, 1024) == 0)
        wdb_update_agent_name(0, hostname);
    else
        mterror(WM_DATABASE_LOGTAG, "Couldn't get manager's hostname: %s.", strerror(errno));

    /* Get node name of the manager in cluster */
    char* node_name;

    const char *(xml_node[]) = {"ossec_config", "cluster", "node_name", NULL};

    OS_XML xml;

    if (OS_ReadXML(DEFAULTCPATH, &xml) < 0){
        merror_exit(XML_ERROR, DEFAULTCPATH, xml.err, xml.err_line);
    }

    node_name = OS_GetOneContentforElement(&xml, xml_node);

    OS_ClearXML(&xml);

    if ((os_uname = strdup(getuname()))) {
        os_arch = wm_get_os_arch(os_uname);
        char *ptr;

        if ((ptr = strstr(os_uname, " - ")))
            *ptr = '\0';

        if (os_name = strstr(os_uname, " ["), os_name){
            *os_name = '\0';
            os_name += 2;
            if (os_version = strstr(os_name, ": "), os_version){
                *os_version = '\0';
                os_version += 2;
                *(os_version + strlen(os_version) - 1) = '\0';

                // os_major.os_minor (os_codename)
                if (os_codename = strstr(os_version, " ("), os_codename){
                    *os_codename = '\0';
                    os_codename += 2;
                    *(os_codename + strlen(os_codename) - 1) = '\0';
                }

                // Get os_major
                if (w_regexec("^([0-9]+)\\.*", os_version, 2, match)) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_major = malloc(match_size +1);
                    snprintf (os_major, match_size +1, "%.*s", match_size, os_version + match[1].rm_so);
                }

                // Get os_minor
                if (w_regexec("^[0-9]+\\.([0-9]+)\\.*", os_version, 2, match)) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_minor = malloc(match_size +1);
                    snprintf (os_minor, match_size +1, "%.*s", match_size, os_version + match[1].rm_so);
                }

            } else
                *(os_name + strlen(os_name) - 1) = '\0';

            // os_name|os_platform
            if (os_platform = strstr(os_name, "|"), os_platform){
                *os_platform = '\0';
                os_platform ++;
            }
        }

        wdb_update_agent_version(0, os_name, os_version, os_major, os_minor, os_codename, os_platform, os_build, os_uname, os_arch, __ossec_name " " __ossec_version, NULL, NULL, hostname, node_name);

        free(node_name);
        free(os_major);
        free(os_minor);
        free(os_uname);
        free(os_arch);
    }

    // Set starting offset if full_sync disabled

    if (!module->full_sync) {
        path = DEFAULTDIR SYSCHECK_DIR "/syscheck";

        // Don't print error if stat fails because syscheck and rootcheck must not exist

        if (!stat(path, &buffer) && buffer.st_size > 0) {
            switch (wdb_get_agent_status(0)) {
            case -1:
                mterror(WM_DATABASE_LOGTAG, "Couldn't get database status for manager.");
                break;
            case WDB_AGENT_EMPTY:
                if (wdb_set_agent_offset(0, WDB_SYSCHECK, buffer.st_size) < 1)
                    mterror(WM_DATABASE_LOGTAG, "Couldn't write offset data on database for manager.");
            }
        }

        if (wdb_set_agent_status(0, WDB_AGENT_UPDATED) < 1) {
            mterror(WM_DATABASE_LOGTAG, "Couldn't write agent status on database for manager.");
        }
    }
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
    char path[PATH_MAX] = "";
    char * group;
    char cidr[20];
    keystore keys = KEYSTORE_INITIALIZER;
    keyentry *entry;
    int *agents;
    clock_t clock0 = clock();
    struct timespec spec0;
    struct timespec spec1;
    struct stat buffer;

    gettime(&spec0);

    mtdebug1(WM_DATABASE_LOGTAG, "Synchronizing agents.");
    OS_PassEmptyKeyfile();
    OS_ReadKeys(&keys, 0, 0, 0);

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

        if (!(wdb_insert_agent(id, entry->name, OS_CIDRtoStr(entry->ip, cidr, 20) ? entry->ip->ip : cidr, entry->key, *group ? group : NULL,1) || module->full_sync)) {

            // Find files

            snprintf(path, PATH_MAX, "%s/(%s) %s->syscheck", DEFAULTDIR SYSCHECK_DIR, entry->name, entry->ip->ip);

            if (stat(path, &buffer) < 0) {
                if (errno != ENOENT)
                    mterror(WM_DATABASE_LOGTAG, FSTAT_ERROR, path, errno, strerror(errno));
            } else if (wdb_set_agent_offset(id, WDB_SYSCHECK, buffer.st_size) < 1)
                mterror(WM_DATABASE_LOGTAG, "Couldn't write offset data on database for agent %d (%s).", id, entry->name);

            snprintf(path, PATH_MAX, "%s/(%s) %s->syscheck-registry", DEFAULTDIR SYSCHECK_DIR, entry->name, entry->ip->ip);

            if (stat(path, &buffer) < 0) {
                if (errno != ENOENT)
                    mterror(WM_DATABASE_LOGTAG, FSTAT_ERROR, path, errno, strerror(errno));
            } else if (wdb_set_agent_offset(id, WDB_SYSCHECK_REGISTRY, buffer.st_size) < 1)
                mterror(WM_DATABASE_LOGTAG, "Couldn't write offset data on database for agent %d (%s).", id, entry->name);
        } else {
            // The agent already exists, update group only.
            wm_sync_agent_group(id, entry->id);
        }
    }

    /* Delete old keys */

    if ((agents = wdb_get_all_agents())) {
        char id[9];

        for (i = 0; agents[i] != -1; i++) {
            snprintf(id, 9, "%03d", agents[i]);

            if (OS_IsAllowedID(&keys, id) == -1)
                if (wdb_remove_agent(agents[i]) < 0) {
                    mtdebug1(WM_DATABASE_LOGTAG, "Couldn't remove agent %s", id);
                }
            }

        free(agents);
    }

    free(group);
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
    struct dirent * dirent;
    DIR * dir;

    snprintf(dirname, sizeof(dirname), "%s%s/agents", isChroot() ? "/" : "", WDB_DIR);
    mtdebug1(WM_DATABASE_LOGTAG, "Cleaning directory '%s'.", dirname);

    if (!(dir = opendir(dirname))) {
        mterror(WM_DATABASE_LOGTAG, "Couldn't open directory '%s': %s.", dirname, strerror(errno));
        return;
    }

    while ((dirent = readdir(dir))) {
        if (dirent->d_name[0] != '.') {
            if (end = strchr(dirent->d_name, '-'), end) {
                *end = 0;

                if (name = wdb_agent_name(atoi(dirent->d_name)), name) {
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

    wdb_update_groups(dirname);
}

#endif // LOCAL

char * wm_get_os_arch(char * os_header) {
    const char * ARCHS[] = { "x86_64", "i386", "i686", "sparc", "amd64", "ia64", "AIX", "armv6", "armv7", NULL };
    char * os_arch = NULL;
    int i;

    for (i = 0; ARCHS[i]; i++) {
        if (strstr(os_header, ARCHS[i])) {
            os_strdup(ARCHS[i], os_arch);
            break;
        }
    }

    if (!ARCHS[i]) {
        os_strdup("", os_arch);
    }

    mtdebug2(WM_DATABASE_LOGTAG, "Detected architecture from %s: %s", os_header, os_arch);
    return os_arch;
}


int wm_sync_agentinfo(int id_agent, const char *path) {
    char header[OS_MAXSTR];
    char files[OS_MAXSTR];
    char file[OS_MAXSTR];
    char *os = NULL;
    char *version = NULL;
    char *os_name = NULL;
    char *os_major = NULL;
    char *os_minor = NULL;
    char *os_build = NULL;
    char *os_version = NULL;
    char *os_codename = NULL;
    char *os_platform = NULL;
    char *os_arch = NULL;
    char *config_sum = NULL;
    char *merged_sum = NULL;
    char manager_host[512] = "";
    char node_name[512] = "";
    char *end;
    char *end_manager;
    char *end_node;
    char *end_line;
    FILE *fp;
    int result;
    clock_t clock0 = clock();
    regmatch_t match[2];
    int match_size;

    strncpy(node_name, "unknown", sizeof(node_name) - 1);

    if (!(fp = fopen(path, "r"))) {
        mterror(WM_DATABASE_LOGTAG, FOPEN_ERROR, path, errno, strerror(errno));
        return -1;
    }

    if (os = fgets(header, OS_MAXSTR, fp), !os) {
        mtdebug1(WM_DATABASE_LOGTAG, "Empty file '%s'. Agent is pending.", path);


    } else {

        if (end_line = strstr(os, "\n"), end_line){
            *end_line = '\0';
        } else {
            mtwarn(WM_DATABASE_LOGTAG, "Corrupt line found parsing '%s' (incomplete). Returning.", path);
            fclose(fp);
            return -1;
        }

        if (config_sum = strstr(os, " / "), config_sum){
            *config_sum = '\0';
            config_sum += 3;
        }

        if (version = strstr(os, " - "), version){
            *version = '\0';
            version += 3;
        } else {
            mterror(WM_DATABASE_LOGTAG, "Corrupt file '%s'.", path);
            fclose(fp);
            return -1;
        }

        // [Ver: os_major.os_minor.os_build]
        if (os_version = strstr(os, " [Ver: "), os_version){
            *os_version = '\0';
            os_version += 7;
            os_name = os;
            *(os_version + strlen(os_version) - 1) = '\0';

            // Get os_major

            if (w_regexec("^([0-9]+)\\.*", os_version, 2, match)) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_major = malloc(match_size +1 );
                snprintf (os_major, match_size + 1, "%.*s", match_size, os_version + match[1].rm_so);
            }

            // Get os_minor

            if (w_regexec("^[0-9]+\\.([0-9]+)\\.*", os_version, 2, match)) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_minor = malloc(match_size +1);
                snprintf(os_minor, match_size + 1, "%.*s", match_size, os_version + match[1].rm_so);
            }

            // Get os_build

            if (w_regexec("^[0-9]+\\.[0-9]+\\.([0-9]+)\\.*", os_version, 2, match)) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_build = malloc(match_size +1);
                snprintf(os_build, match_size + 1, "%.*s", match_size, os_version + match[1].rm_so);
            }

            os_platform = "windows";
        }
        else {
            if (os_name = strstr(os, " ["), os_name){
                *os_name = '\0';
                os_name += 2;
                if (os_version = strstr(os_name, ": "), os_version){
                    *os_version = '\0';
                    os_version += 2;
                    *(os_version + strlen(os_version) - 1) = '\0';

                    // os_major.os_minor (os_codename)
                    if (os_codename = strstr(os_version, " ("), os_codename){
                        *os_codename = '\0';
                        os_codename += 2;
                        *(os_codename + strlen(os_codename) - 1) = '\0';
                    }

                    // Get os_major
                    if (w_regexec("^([0-9]+)\\.*", os_version, 2, match)) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        os_major = malloc(match_size +1);
                        snprintf(os_major, match_size + 1, "%.*s", match_size, os_version + match[1].rm_so);
                    }

                    // Get os_minor
                    if (w_regexec("^[0-9]+\\.([0-9]+)\\.*", os_version, 2, match)) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        os_minor = malloc(match_size +1);
                        snprintf(os_minor, match_size + 1, "%.*s", match_size, os_version + match[1].rm_so);
                    }

                } else
                    *(os_name + strlen(os_name) - 1) = '\0';

                // os_name|os_platform
                if (os_platform = strstr(os_name, "|"), os_platform){
                    *os_platform = '\0';
                    os_platform ++;
                }
            }
            os_arch = wm_get_os_arch(os);
        }

        // Search for merged.mg sum

        while (end = NULL, merged_sum = fgets(files, OS_MAXSTR, fp), merged_sum) {
            if (*merged_sum != '\"' && *merged_sum != '!' && (end = strchr(merged_sum, ' '), end)) {
                *end = '\0';

                if (strcmp(end + 1, SHAREDCFG_FILENAME "\n") == 0) {
                    break;
                }
            }

            merged_sum = NULL;
        }

        // Search for manager hostname connected to the agent and the node name of the cluster

        const char * MANAGER_HOST = "#\"manager_hostname\":";
        const char * NODE_NAME = "#\"node_name\":";

        while (fgets(file, OS_MAXSTR, fp)) {
            if (!strncmp(file, MANAGER_HOST, strlen(MANAGER_HOST))) {
                strncpy(manager_host, file + strlen(MANAGER_HOST), sizeof(manager_host) - 1);
                manager_host[sizeof(manager_host) - 1] = '\0';

                if (end_manager = strchr(manager_host, '\n'), end_manager){
                    *end_manager = '\0';
                }
            }
            if (!strncmp(file, NODE_NAME, strlen(NODE_NAME))) {
                strncpy(node_name, file + strlen(NODE_NAME), sizeof(node_name) - 1);
                node_name[sizeof(node_name) - 1] = '\0';

                if (end_node = strchr(node_name, '\n'), end_node){
                    *end_node = '\0';
                }
            }
        }
    }


    result = wdb_update_agent_version(id_agent, os_name, os_version, os_major, os_minor, os_codename, os_platform, os_build, os, os_arch, version, config_sum, merged_sum, manager_host, node_name);
    mtdebug2(WM_DATABASE_LOGTAG, "wm_sync_agentinfo(%d): %.3f ms.", id_agent, (double)(clock() - clock0) / CLOCKS_PER_SEC * 1000);

    free(os_major);
    free(os_arch);
    free(os_minor);
    free(os_build);
    fclose(fp);
    return result;
}

int wm_sync_agent_group(int id_agent, const char *fname) {
    int result = 0;
    char *group;
    os_calloc(OS_SIZE_65536 + 1, sizeof(char), group);
    clock_t clock0 = clock();

    get_agent_group(fname, group, OS_SIZE_65536);

    switch (wdb_update_agent_group(id_agent, *group ? group : NULL)) {
    case -1:
        mterror(WM_DATABASE_LOGTAG, "Couldn't sync agent '%s' group.", fname);
        wdb_delete_agent_belongs(id_agent);
        result = -1;
        break;
    case 0:
        mtdebug1(WM_DATABASE_LOGTAG, "No such agent '%s' on DB when updating group.", fname);
        break;
    default:
        break;
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
        wdb_remove_group_db(fname);
    }
    else {
        if( wdb_find_group(fname) <= 0){
            wdb_insert_group(fname);
        }
    }
    closedir(dp);
    mtdebug2(WM_DATABASE_LOGTAG, "wm_sync_shared_group(): %.3f ms.", (double)(clock() - clock0) / CLOCKS_PER_SEC * 1000);
    return result;
}

void wm_scan_directory(const char *dirname) {
    char path[PATH_MAX];
    struct dirent *dirent;
    DIR *dir;

    mtdebug1(WM_DATABASE_LOGTAG, "Scanning directory '%s'.", dirname);
    snprintf(path, PATH_MAX, "%s", dirname);

    if (!(dir = opendir(path))) {
        mterror(WM_DATABASE_LOGTAG, "Couldn't open directory '%s': %s.", path, strerror(errno));
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
    char del_path[PATH_MAX] = "";
    struct stat buffer;
    long offset;
    int result = 0;
    int id_agent = -1;
    int is_registry = 0;
    int type;
    sqlite3 *db;

    mtdebug2(WM_DATABASE_LOGTAG, "Synchronizing file '%s/%s'", dirname, fname);

    if (snprintf(path, PATH_MAX, "%s/%s", dirname, fname) >= PATH_MAX) {
        mterror(WM_DATABASE_LOGTAG, "At wm_sync_file(): Path '%s/%s' exceeded length limit.", dirname, fname);
        return -1;
    }

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
    } else if (!strcmp(dirname, DEFAULTDIR GROUPS_DIR)) {
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

        if (wdb_get_agent_status(id_agent) < 0) {
            snprintf(del_path, PATH_MAX - 1, DEFAULTDIR GROUPS_DIR "/%03d", id_agent);
            unlink(del_path);
            wdb_delete_agent_belongs(id_agent);
            return -1;
        }

        break;

    case WDB_SHARED_GROUPS:
        id_agent = 0;
        break;

    default:
        // If id_agent != 0, then the file corresponds to an agent

        if (id_agent) {
            switch (wm_extract_agent(fname, name, addr, &is_registry)) {
            case 0:
                if ((id_agent = wdb_find_agent(name, addr)) < 0) {
                    mtdebug1(WM_DATABASE_LOGTAG, "No such agent at database for file %s/%s", dirname, fname);
                    snprintf(del_path, PATH_MAX, "%s/%s", dirname, fname);
                    unlink(del_path);
                    return -1;
                }

                if (is_registry)
                    type = WDB_SYSCHECK_REGISTRY;

                break;

            case 1:
                mtdebug1(WM_DATABASE_LOGTAG, "Ignoring file '%s/%s'", dirname, fname);
                return 0;

            default:
                mterror(WM_DATABASE_LOGTAG, "Couldn't extract agent name and address from file %s/%s", dirname, fname);
                return -1;
            }
        }

        if (stat(path, &buffer) < 0) {
            mterror(WM_DATABASE_LOGTAG, FSTAT_ERROR, path, errno, strerror(errno));
            return -1;
        }
    }

    switch (wdb_get_agent_status(id_agent)) {
    case -1:
        mterror(WM_DATABASE_LOGTAG, "Couldn't get database status for agent '%d'.", id_agent);
        return -1;
    case WDB_AGENT_PENDING:
        mtwarn(WM_DATABASE_LOGTAG, "Agent '%d' database status was 'pending'. Data could be lost.", id_agent);
        wdb_set_agent_status(id_agent, WDB_AGENT_UPDATED);
        break;
    }

    switch (type) {
    case WDB_SYSCHECK:
    case WDB_SYSCHECK_REGISTRY:
        if ((offset = wdb_get_agent_offset(id_agent, type)) < 0) {
            mterror(WM_DATABASE_LOGTAG, "Couldn't file offset from database for agent '%d'.", id_agent);
            return -1;
        }

        if (buffer.st_size < offset) {
            mtwarn(WM_DATABASE_LOGTAG, "File '%s' was truncated.", path);
            offset = 0;
        }

        if (buffer.st_size > offset) {
            if (!(db = wdb_open_agent(id_agent, name))) {
                mterror(WM_DATABASE_LOGTAG, "Couldn't open database for file '%s/%s'.", dirname, fname);
                return -1;
            }

            if (wdb_set_agent_status(id_agent, WDB_AGENT_PENDING) < 1) {
                mterror(WM_DATABASE_LOGTAG, "Couldn't write agent status on database for agent %d (%s).", id_agent, name);
                sqlite3_close_v2(db);
                return -1;
            }

            if (wdb_set_agent_offset(id_agent, type, buffer.st_size) < 1) {
                mterror(WM_DATABASE_LOGTAG, "Couldn't write offset data on database for agent %d (%s).", id_agent, name);
                sqlite3_close_v2(db);
                return -1;
            }

            offset = wm_fill_syscheck(db, path, offset, is_registry);
            sqlite3_close_v2(db);

            if (wdb_set_agent_status(id_agent, WDB_AGENT_UPDATED) < 1) {
                mterror(WM_DATABASE_LOGTAG, "Couldn't write agent status on database for agent %d (%s).", id_agent, name);
                return -1;
            }

            if (offset < 0) {
                mterror(WM_DATABASE_LOGTAG, "Couldn't fill syscheck database for file '%s/%s'.", dirname, fname);
                return -1;
            }

            if (offset != buffer.st_size && wdb_set_agent_offset(id_agent, type, offset) < 1) {
                mterror(WM_DATABASE_LOGTAG, "Couldn't write offset data on database for agent %d (%s) (post-fill).", id_agent, name);
                return -1;
            }
        } else
            mtdebug1(WM_DATABASE_LOGTAG, "Skipping file '%s/%s' (no new data).", dirname, fname);

        break;

    case WDB_ROOTCHECK:
        if (!(db = wdb_open_agent(id_agent, name))) {
            mterror(WM_DATABASE_LOGTAG, "Couldn't open database for file '%s/%s'.", dirname, fname);
            return -1;
        }

        if (wdb_set_agent_status(id_agent, WDB_AGENT_PENDING) < 1) {
            mterror(WM_DATABASE_LOGTAG, "Couldn't write agent status on database for agent %d (%s).", id_agent, name);
            sqlite3_close_v2(db);
            return -1;
        }

        result = wm_fill_rootcheck(db, path);
        sqlite3_close_v2(db);

        if (wdb_set_agent_status(id_agent, WDB_AGENT_UPDATED) < 1) {
            mterror(WM_DATABASE_LOGTAG, "Couldn't write agent status on database for agent %d (%s).", id_agent, name);
            return -1;
        }

        if (result < 0) {
            mterror(WM_DATABASE_LOGTAG, "Couldn't fill rootcheck database for file '%s/%s'.", dirname, fname);
            return -1;
        }

        break;

    case WDB_AGENTINFO:
        result = wm_sync_agentinfo(id_agent, path) < 0 || wdb_update_agent_keepalive(id_agent, buffer.st_mtime) < 0 ? -1 : 0;
        break;

    case WDB_GROUPS:
        result = wm_sync_agent_group(id_agent, fname);
        break;

    case WDB_SHARED_GROUPS:
        result = wm_sync_shared_group(fname);
        break;
    }

    return result;
}

// Fill syscheck database from an offset. Returns offset at last successful read event, or -1 on error.
long wm_fill_syscheck(sqlite3 *db, const char *path, long offset, int is_registry) {
    char buffer[OS_MAXSTR];
    char *end;
    char *event;
    char *c_sum;
    char *timestamp;
    char *f_name;
    int count;
    long last_offset = offset;
    clock_t clock_ini;
    int type = is_registry ? WDB_FILE_TYPE_REGISTRY : WDB_FILE_TYPE_FILE;
    FILE *fp;

    sk_sum_t sum;
    memset(&sum, 0, sizeof(sk_sum_t));

    if (!(fp = fopen(path, "r"))) {
        mterror(WM_DATABASE_LOGTAG, FOPEN_ERROR, path, errno, strerror(errno));
        return -1;
    }

    if (fseek(fp, offset, SEEK_SET) < 0) {
        mterror(WM_DATABASE_LOGTAG, FSEEK_ERROR, path, errno, strerror(errno));
        fclose(fp);
        return -1;
    }

    clock_ini = clock();
    wdb_begin(db);

    for (count = 0; fgets(buffer, OS_MAXSTR, fp); last_offset = ftell(fp)) {
        end = strchr(buffer, '\n');

        if (!end) {
            mtwarn(WM_DATABASE_LOGTAG, "Corrupt line found parsing '%s' (incomplete). Breaking.", path);
            break;
        } else if (end == buffer)
            continue;

        *end = '\0';
        c_sum = buffer + 3;

        if (!(timestamp = strstr(c_sum, " !"))) {
            mtwarn(WM_DATABASE_LOGTAG, "Corrupt line found parsing '%s' (no timestamp found).", path);
            continue;
        }

        *timestamp = '\0';
        timestamp += 2;

        if (!(f_name = strchr(timestamp, ' '))) {
            mtwarn(WM_DATABASE_LOGTAG, "Corrupt line found parsing '%s'.", path);
            continue;
        }

        *(f_name++) = '\0';

        switch (sk_decode_sum(&sum, c_sum, NULL)) {
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
                mterror(WM_DATABASE_LOGTAG, "Couldn't extract FIM data from database.");
                continue;
            }

            break;
        case 1:
            event = "deleted";
            break;
        default:
            mtwarn(WM_DATABASE_LOGTAG, "Corrupt line found parsing '%s'.", path);
            continue;
        }

        if (wdb_insert_fim(db, type, atol(timestamp), f_name, event, &sum) < 0)
            mterror(WM_DATABASE_LOGTAG, "Couldn't insert FIM event into database from file '%s'.", path);

        count++;
    }

    wdb_commit(db);
    mtdebug2(WM_DATABASE_LOGTAG, "Syscheck file sync finished. Count: %d. Time: %.3lf ms.", count, (double)(clock() - clock_ini) / CLOCKS_PER_SEC * 1000);

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
        mterror(WM_DATABASE_LOGTAG, FOPEN_ERROR, path, errno, strerror(errno));
        return -1;
    }

    clock_ini = clock();
    wdb_begin(db);

    while (fgets(buffer, OS_MAXSTR, fp)) {
        end = strchr(buffer, '\n');

        if (!end) {
            mtwarn(WM_DATABASE_LOGTAG, "Corrupt line found parsing '%s' (incomplete). Breaking.", path);
            break;
        } else if (end == buffer)
            continue;

        *end = '\0';

        if (rk_decode_event(buffer, &event) < 0) {
            mtwarn(WM_DATABASE_LOGTAG, "Corrupt line found parsing '%s'.", path);
            continue;
        }

        switch (wdb_update_pm(db, &event)) {
            case -1:
                mterror(WM_DATABASE_LOGTAG, "Updating PM tuple on SQLite database for file '%s'.", path);
                continue;
            case 0:
                if (wdb_insert_pm(db, &event) < 0) {
                    mterror(WM_DATABASE_LOGTAG, "Inserting PM tuple on SQLite database for file '%s'.", path);
                    continue;
                }

                count++;
                break;

            default:
                count++;
        }
    }

    wdb_commit(db);
    mtdebug2(WM_DATABASE_LOGTAG, "Rootcheck file sync finished. Count: %d. Time: %.3lf ms.", count, (double)(clock() - clock_ini) / CLOCKS_PER_SEC * 1000);

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


// Get readed data

cJSON *wm_database_dump(const wm_database *data) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_db = cJSON_CreateObject();

    if (data->sync_agents) cJSON_AddStringToObject(wm_db,"sync_agents","yes"); else cJSON_AddStringToObject(wm_db,"sync_agents","no");
    if (data->sync_syscheck) cJSON_AddStringToObject(wm_db,"sync_syscheck","yes"); else cJSON_AddStringToObject(wm_db,"sync_syscheck","no");
    if (data->sync_rootcheck) cJSON_AddStringToObject(wm_db,"sync_rootcheck","yes"); else cJSON_AddStringToObject(wm_db,"sync_rootcheck","no");
    if (data->full_sync) cJSON_AddStringToObject(wm_db,"full_sync","yes"); else cJSON_AddStringToObject(wm_db,"full_sync","no");
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
    data.sync_syscheck = 0; //getDefine_Int("wazuh_database", "sync_syscheck", 0, 1);
    data.sync_rootcheck = getDefine_Int("wazuh_database", "sync_rootcheck", 0, 1);
    data.full_sync = getDefine_Int("wazuh_database", "full_sync", 0, 1);
    data.real_time = getDefine_Int("wazuh_database", "real_time", 0, 1);
    data.interval = getDefine_Int("wazuh_database", "interval", 0, 86400);
    data.max_queued_events = getDefine_Int("wazuh_database", "max_queued_events", 0, INT_MAX);

    if (data.sync_agents || data.sync_syscheck || data.sync_rootcheck) {
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

    if (inotify_fd = inotify_init(), inotify_fd < 0) {
        mterror_exit(WM_DATABASE_LOGTAG, "Couldn't init inotify: %s.", strerror(errno));
    }

    // Reset inotify queued events limit

    if (old_max_queued_events >= 0 && old_max_queued_events != data->max_queued_events) {
        mtdebug2(WM_DATABASE_LOGTAG, "Restoring inotify queued events limit to '%d'", old_max_queued_events);
        set_max_queued_events(old_max_queued_events);
    }

    // Run thread
    w_create_thread(wm_inotify_start, NULL);

    // First synchronization and add watch for client.keys, Agent info, Syscheck and Rootcheck directories

#ifndef LOCAL

    char keysfile_path[] = KEYSFILE_PATH;
    char * keysfile_dir = dirname(keysfile_path);

    if (data->sync_agents) {
        if ((wd_agents = inotify_add_watch(inotify_fd, keysfile_dir, IN_CLOSE_WRITE | IN_MOVED_TO)) < 0)
            mterror(WM_DATABASE_LOGTAG, "Couldn't watch client.keys file: %s.", strerror(errno));

        mtdebug2(WM_DATABASE_LOGTAG, "wd_agents='%d'", wd_agents);

        if ((wd_agentinfo = inotify_add_watch(inotify_fd, DEFAULTDIR AGENTINFO_DIR, IN_CLOSE_WRITE | IN_ATTRIB | IN_MOVED_TO)) < 0)
            mterror(WM_DATABASE_LOGTAG, "Couldn't watch the agent info directory: %s.", strerror(errno));

        mtdebug2(WM_DATABASE_LOGTAG, "wd_agentinfo='%d'", wd_agentinfo);

        if ((wd_groups = inotify_add_watch(inotify_fd, DEFAULTDIR GROUPS_DIR, IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE)) < 0)
            mterror(WM_DATABASE_LOGTAG, "Couldn't watch the agent groups directory: %s.", strerror(errno));

        mtdebug2(WM_DATABASE_LOGTAG, "wd_groups='%d'", wd_groups);

        if ((wd_shared_groups = inotify_add_watch(inotify_fd, DEFAULTDIR SHAREDCFG_DIR, IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_CREATE | IN_DELETE)) < 0)
            mterror(WM_DATABASE_LOGTAG, "Couldn't watch the shared groups directory: %s.", strerror(errno));

        mtdebug2(WM_DATABASE_LOGTAG, "wd_shared_groups='%d'", wd_shared_groups);

        wm_sync_agents();
        wm_sync_multi_groups(DEFAULTDIR SHAREDCFG_DIR);
        wdb_agent_belongs_first_time();
        wm_scan_directory(DEFAULTDIR AGENTINFO_DIR);
    }

#endif

    if (data->sync_syscheck) {
        if ((wd_syscheck = inotify_add_watch(inotify_fd, DEFAULTDIR SYSCHECK_DIR, IN_MODIFY)) < 0)
            mterror(WM_DATABASE_LOGTAG, "Couldn't watch Syscheck directory: %s.", strerror(errno));

        mtdebug2(WM_DATABASE_LOGTAG, "wd_syscheck='%d'", wd_syscheck);
        wm_scan_directory(DEFAULTDIR SYSCHECK_DIR);
    }

    if (data->sync_rootcheck) {
        if ((wd_rootcheck = inotify_add_watch(inotify_fd, DEFAULTDIR ROOTCHECK_DIR, IN_MODIFY)) < 0)
            mterror(WM_DATABASE_LOGTAG, "Couldn't watch Rootcheck directory: %s.", strerror(errno));

        mtdebug2(WM_DATABASE_LOGTAG, "wd_rootcheck='%d'", wd_rootcheck);
        wm_scan_directory(DEFAULTDIR ROOTCHECK_DIR);
    }
}

// Real time inotify reader thread
static void * wm_inotify_start(__attribute__((unused)) void * args) {
    char buffer[IN_BUFFER_SIZE];
    char keysfile_dir[] = KEYSFILE_PATH;
    char * keysfile = keysfile_dir;
    struct inotify_event *event = (struct inotify_event *)buffer;
    char * dirname = NULL;
    ssize_t count;
    size_t i;

        if (!(keysfile = strrchr(keysfile_dir, '/'))) {
            mterror_exit(WM_DATABASE_LOGTAG, "Couldn't decode keys file path '%s'.", keysfile_dir);
        }

        *(keysfile++) = '\0';

    // Loop

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
                    } else if (event->wd == wd_agentinfo) {
                        dirname = DEFAULTDIR AGENTINFO_DIR;
                    } else if (event->wd == wd_groups) {
                        dirname = DEFAULTDIR GROUPS_DIR;
                    } else if (event->wd == wd_shared_groups) {
                        dirname = DEFAULTDIR SHAREDCFG_DIR;
                    } else
#endif
                    if (event->wd == wd_syscheck) {
                        dirname = DEFAULTDIR SYSCHECK_DIR;
                    } else if (event->wd == wd_rootcheck) {
                        dirname = DEFAULTDIR ROOTCHECK_DIR;
                    } else if (event->wd == -1 && event->mask == IN_Q_OVERFLOW) {
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
