/*
 * Wazuh Database Daemon
 * Copyright (C) 2015-2019, Wazuh Inc.
 * January 03, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"
#include <os_net/os_net.h>

static void wdb_help() __attribute__ ((noreturn));
static void handler(int signum);
static void cleanup();
static void * run_dealer(void * args);
static void * run_worker(void * args);
static void * run_gc(void * args);
static void * run_up(void * args);

//int wazuhdb_fdsock;
wnotify_t * notify_queue;
//static w_queue_t * sock_queue;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
//static pthread_cond_t sock_cond = PTHREAD_COND_INITIALIZER;
static volatile int running = 1;
rlim_t nofile;

int main(int argc, char ** argv) {
    int test_config = 0;
    int run_foreground = 0;
    int i;
    int status;

    pthread_t thread_dealer;
    pthread_t * worker_pool;
    pthread_t thread_gc;
    pthread_t thread_up;

    OS_SetName(ARGV0);

    // Get options

    {
        int c;

        while (c = getopt(argc, argv, "Vdhtf"), c != -1) {
            switch (c) {
            case 'V':
                print_version();
                break;

            case 'h':
                wdb_help();
                break;

            case 'd':
                nowDebug();
                break;

            case 't':
                test_config = 1;
                break;

            case 'f':
                run_foreground = 1;
                break;

            default:
                wdb_help();
            }
        }
    }

    // Read internal options

    config.sock_queue_size = getDefine_Int("wazuh_db", "sock_queue_size", 1, 1024);
    config.worker_pool_size = getDefine_Int("wazuh_db", "worker_pool_size", 1, 32);
    config.commit_time = getDefine_Int("wazuh_db", "commit_time", 1, 3600);
    config.open_db_limit = getDefine_Int("wazuh_db", "open_db_limit", 1, 4096);
    nofile = getDefine_Int("wazuh_db", "rlimit_nofile", 1024, 1048576);

    if (!isDebug()) {
        int debug_level;

        for (debug_level = getDefine_Int("wazuh_db", "debug", 0, 2); debug_level; debug_level--) {
            nowDebug();
        }
    }

    if (test_config) {
        exit(0);
    }

    // Initialize variables

    //sock_queue = queue_init(config.sock_queue_size);
    open_dbs = OSHash_Create();
    if (!open_dbs) merror_exit("wazuh_db: OSHash_Create() failed");

    mdebug1(STARTED_MSG);

    if (!run_foreground) {
        goDaemon();
        nowDaemon();
    }

    // Reset template. Basically, remove queue/db/.template.db
    // The prefix is needed here, because we are not yet chrooted
    char path_template[OS_FLSIZE + 1];
    snprintf(path_template, sizeof(path_template), "%s/%s/%s", DEFAULTDIR, WDB2_DIR, WDB_PROF_NAME);
    unlink(path_template);
    mdebug1("Template file removed: %s", path_template);

    // Set max open files limit
    struct rlimit rlimit = { nofile, nofile };

    if (setrlimit(RLIMIT_NOFILE, &rlimit) < 0) {
        merror("Could not set resource limit for file descriptors to %d: %s (%d)", (int)nofile, strerror(errno), errno);
    }

    // Set user and group

    {
        uid_t uid = Privsep_GetUser(USER);
        gid_t gid = Privsep_GetGroup(GROUPGLOBAL);

        if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
            merror_exit(USER_ERROR, USER, GROUPGLOBAL);
        }

        if (Privsep_SetGroup(gid) < 0) {
            merror_exit(SETGID_ERROR, GROUPGLOBAL, errno, strerror(errno));
        }

        // Change root

        if (Privsep_Chroot(DEFAULTDIR) < 0) {
            merror_exit(CHROOT_ERROR, DEFAULTDIR, errno, strerror(errno));
        }

        if (Privsep_SetUser(uid) < 0) {
            merror_exit(SETUID_ERROR, USER, errno, strerror(errno));
        }
    }

    // Signal manipulation

    {
        struct sigaction action = { .sa_handler = handler, .sa_flags = SA_RESTART };
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGINT, &action, NULL);

        action.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &action, NULL);
    }

    atexit(cleanup);

    // Create PID file

    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    minfo(STARTUP_MSG, (int)getpid());

    if (notify_queue = wnotify_init(1), !notify_queue) {
        merror_exit("at run_dealer(): wnotify_init(): %s (%d)",
                strerror(errno), errno);
    }

    // Start threads

    if (status = pthread_create(&thread_dealer, NULL, run_dealer, NULL), status != 0) {
        merror("Couldn't create thread: %s", strerror(status));
        return EXIT_FAILURE;
    }

    os_malloc(sizeof(pthread_t) * config.worker_pool_size, worker_pool);

    for (i = 0; i < config.worker_pool_size; i++) {
        if (status = pthread_create(worker_pool + i, NULL, run_worker, NULL), status != 0) {
            merror("Couldn't create thread: %s", strerror(status));
            return EXIT_FAILURE;
        }
    }

    if (status = pthread_create(&thread_gc, NULL, run_gc, NULL), status != 0) {
        merror("Couldn't create thread: %s", strerror(status));
        return EXIT_FAILURE;
    }

    if (status = pthread_create(&thread_up, NULL, run_up, NULL), status != 0) {
        merror("Couldn't create thread: %s", strerror(status));
        return EXIT_FAILURE;
    }

    // Join threads

    pthread_join(thread_dealer, NULL);

    for (i = 0; i < config.worker_pool_size; i++) {
        pthread_join(worker_pool[i], NULL);
    }

    wnotify_close(notify_queue);
    free(worker_pool);
    pthread_join(thread_gc, NULL);
    wdb_close_all();

    // Reset template here too, remove queue/db/.template.db again
    // Without the prefix, because chrooted at that point
    snprintf(path_template, sizeof(path_template), "%s/%s", WDB2_DIR, WDB_PROF_NAME);
    unlink(path_template);
    mdebug1("Template file removed again: %s", path_template);

    return EXIT_SUCCESS;
}

void * run_dealer(__attribute__((unused)) void * args) {
    int sock;
    int peer;
    fd_set fdset;
    struct timeval timeout;

    if (sock = OS_BindUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror_exit("Unable to bind to socket '%s': '%s'. Closing local server.",
                WDB_LOCAL_SOCK, strerror(errno));
    }

    while (running) {
        // Wait for socket

        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        switch (select(sock + 1, &fdset, NULL, NULL, &timeout)) {
        case -1:
            if (errno == EINTR) {
                minfo("at run_dealer(): select(): %s", strerror(EINTR));
            } else {
                merror_exit("at run_dealer(): select(): %s", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        // Accept new peer

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno == EINTR) {
                minfo("at run_dealer(): accept(): %s", strerror(errno));
            } else {
                merror("at run_dealer(): accept(): %s", strerror(errno));
            }

            continue;
        }
        if (wnotify_add(notify_queue, peer) < 0) {
            merror("at run_dealer(): wnotify_add(%d): %s (%d)",
                    peer, strerror(errno), errno);
            goto error;
        }

        mdebug1("New client connected (%d).", peer);
    }

error:
    close(sock);
    unlink(WDB_LOCAL_SOCK);
    return NULL;
}

void * run_worker(__attribute__((unused)) void * args) {
    char buffer[OS_MAXSTR + 1];
    char response[OS_MAXSTR + 1];
    ssize_t length;
    int terminal;
    int peer;

    while (running) {
        // Dequeue peer
        w_mutex_lock(&queue_mutex);

        switch (wnotify_wait(notify_queue, 100)) {
        case -1:
            if (errno == EINTR) {
                mdebug1("at run_worker(): wnotify_wait(): %s", strerror(EINTR));
            } else {
                merror("at run_worker(): wnotify_wait(): %s", strerror(errno));
            }

            w_mutex_unlock(&queue_mutex);
            continue;

        case 0:
            w_mutex_unlock(&queue_mutex);
            continue;
        }

        peer = wnotify_get(notify_queue, 0);
        if (wnotify_delete(notify_queue, peer) < 0) {
            merror("at run_worker(): wnotify_delete(%d): %s (%d)",
                    peer, strerror(errno), errno);
        }

        w_mutex_unlock(&queue_mutex);

        ssize_t count;
        length = 0;
        count = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR);

        if(count == OS_SOCKTERR){
            mwarn("at run_worker(): received string size is bigger than %d bytes",
                    OS_MAXSTR);
            break;
        }
        length+=count;

        switch (length) {
        case -1:
            merror("at run_worker(): at recv(): %s (%d)", strerror(errno), errno);
            close(peer);
            continue;

        case 0:
            mdebug1("Client %d disconnected.", peer);
            close(peer);
            continue;

        default:
            if (length > 0 && buffer[length - 1] == '\n') {
                buffer[length - 1] = '\0';
                terminal = 1;
            } else {
                buffer[length] = '\0';
                terminal = 0;
            }

            *response = '\0';
            wdb_parse(buffer, response);
            if (length = strlen(response), length > 0) {
                if (terminal && length < OS_MAXSTR - 1) {
                    response[length++] = '\n';
                }
                if (OS_SendSecureTCP(peer,length,response) < 0) {
                    merror("at run_worker(): OS_SendSecureTCP(%d): %s (%d)",
                            peer, strerror(errno), errno);
                }
            }
            break;
        }

        if (wnotify_add(notify_queue, peer) < 0) {
            merror("at run_worker(): wnotify_add(%d): %s (%d)",
                    peer, strerror(errno), errno);
        }
    }

    return NULL;
}

void * run_gc(__attribute__((unused)) void * args) {
    while (running) {
        wdb_commit_old();
        wdb_close_old();
        sleep(1);
    }

    return NULL;
}

void * run_up(__attribute__((unused)) void * args) {
    DIR *fd;
    struct dirent *db;
    wdb_t * wdb;
    char * db_folder;
    char * name;
    char * entry;

    os_calloc(PATH_MAX + 1, sizeof(char), db_folder);
    snprintf(db_folder, PATH_MAX, "%s", WDB2_DIR);

    fd = opendir(db_folder);

    if (!fd) {
        mdebug1("Opening directory: '%s': %s", db_folder, strerror(errno));
        os_free(db_folder);
        return NULL;
    }

    while ((db = readdir(fd)) != NULL) {
        if ((strcmp(db->d_name, ".") == 0) ||
            (strcmp(db->d_name, "..") == 0) ||
            (strcmp(db->d_name, ".template.db") == 0) ||
            (strcmp(db->d_name, "000.db") == 0)) {
            continue;
        }

        os_strdup(db->d_name, entry);

        if (name = strchr(entry, '-'), name) {
            free(entry);
            continue;
        }

        if (name = strchr(entry, '.'), !name) {
            free(entry);
            continue;
        }

        *(name++) = '\0';
        wdb = wdb_open_agent2(atoi(entry));
        mdebug2("Upgraded DB for agent '%s' in run_up", wdb->agent_id);
        wdb_leave(wdb);
        free(entry);
    }

    os_free(db_folder);
    closedir(fd);
    return NULL;
}

void wdb_help() {
    print_header();

    print_out("  %s: -[Vhdtf]", ARGV0);
    print_out("    -V          Version and license message.");
    print_out("    -h          This help message.");
    print_out("    -d          Debug mode. Use this parameter multiple times to increase the debug level.");
    print_out("    -t          Test configuration.");
    print_out("    -f          Run in foreground.");

    exit(EXIT_SUCCESS);
}

void handler(int signum) {
    switch (signum) {
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
        minfo(SIGNAL_RECV, signum, strsignal(signum));
        running = 0;
        break;
    default:
        merror("unknown signal (%d)", signum);
    }
}

void cleanup() {
    DeletePID(ARGV0);
}
