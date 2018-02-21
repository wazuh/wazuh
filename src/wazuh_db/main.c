/*
 * Wazuh Database Daemon
 * Copyright (C) 2018 Wazuh Inc.
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

static w_queue_t * sock_queue;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sock_cond = PTHREAD_COND_INITIALIZER;
static volatile int running = 1;

int main(int argc, char ** argv) {
    int test_config = 0;
    int run_foreground = 0;
    int i;
    int status;

    pthread_t thread_dealer;
    pthread_t * worker_pool;
    pthread_t thread_gc;

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

    sock_queue = queue_init(config.sock_queue_size);
    open_dbs = OSHash_Create();

    mdebug1(STARTED_MSG);

    if (!run_foreground) {
        goDaemon();
        nowDaemon();
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

    // Join threads

    pthread_join(thread_dealer, NULL);

    for (i = 0; i < config.worker_pool_size; i++) {
        pthread_join(worker_pool[i], NULL);
    }

    free(worker_pool);
    pthread_join(thread_gc, NULL);
    wdb_close_all();

    return EXIT_SUCCESS;
}

void * run_dealer(__attribute__((unused)) void * args) {
    int sock;
    int peer;
    fd_set fdset;
    struct timeval timeout;

    if (sock = OS_BindUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror_exit("Unable to bind to socket '%s': '%s'. Closing local server.", WDB_LOCAL_SOCK, strerror(errno));
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

        // Enqueue peer

        w_mutex_lock(&queue_mutex);

        if (queue_full(sock_queue)) {
            static const char * MESSAGE = "err Queue is full";

            w_mutex_unlock(&queue_mutex);
            merror("Couldn't accept new connection: sock queue is full.");
            send(peer, MESSAGE, strlen(MESSAGE), 0);
            close(peer);
        } else {
            int * peer_copy;

            os_malloc(sizeof(int), peer_copy);
            *peer_copy = peer;
            queue_push(sock_queue, peer_copy);
            w_cond_signal(&sock_cond);
            w_mutex_unlock(&queue_mutex);
            mdebug2("New client enqueued.");
        }
    }

    close(sock);
    unlink(WDB_LOCAL_SOCK);
    return NULL;
}

void * run_worker(__attribute__((unused)) void * args) {
    struct timeval now;
    char buffer[OS_MAXSTR + 1];
    char response[OS_MAXSTR + 1];
    ssize_t length;
    int * peer;
    int status;
    int terminal;
    wnotify_t * notify;

    if (notify = wnotify_init(1), !notify) {
        merror_exit("at run_worker(): wnotify_init(): %s (%d)", strerror(errno), errno);
    }

    while (running) {
        // Dequeue peer
        w_mutex_lock(&queue_mutex);

        if (queue_empty(sock_queue)) {
            gettimeofday(&now, NULL);
            struct timespec timeout = { now.tv_sec + 1, now.tv_usec * 1000 };

            switch (status = pthread_cond_timedwait(&sock_cond, &queue_mutex, &timeout), status) {
            case 0:
            case ETIMEDOUT:
                w_mutex_unlock(&queue_mutex);
                continue;
            default:
                merror_exit("at run_worker(): at pthread_cond_timedwait(): %s (%d)", strerror(status), status);
            }
        }

        peer = queue_pop(sock_queue);
        w_mutex_unlock(&queue_mutex);

        mdebug1("Dispatching new client (%d)", *peer);

        if (wnotify_add(notify, *peer) < 0) {
            merror("at run_worker(): wnotify_add(%d): %s (%d)", *peer, strerror(errno), errno);
            goto error;
        }

        status = 0;

        while (running && !status) {

            // Wait for socket

            switch (wnotify_wait(notify, 1000)) {
            case -1:
                if (errno == EINTR) {
                    mdebug1("at run_worker(): wnotify_wait(): %s", strerror(EINTR));
                } else {
                    merror("at run_worker(): wnotify_wait(%d): %s", *peer, strerror(errno));
                    status = 1;
                }

                continue;

            case 0:
                continue;
            }

            char buffer2[OS_MAXSTR + 1] = {0};
            ssize_t count;
            length = 0;

            memset(buffer,0,OS_MAXSTR+1);

            while((count = recv(*peer, buffer, OS_MAXSTR, 0))>0)
            {
             	length += count;
                strcat(buffer2,buffer);
            }

            switch (length) {
            case -1:
                merror("at run_worker(): at recv(): %s (%d)", strerror(errno), errno);
                status = 1;
                break;

            case 0:
                mdebug1("Client %d disconnected.", *peer);
                status = 1;
                break;

            default:

                if (length > 0 && buffer[length - 1] == '\n') {
                    buffer2[length - 1] = '\0';
                    terminal = 1;
                } else {
                    buffer2[length] = '\0';
                    terminal = 0;
                }

                *response = '\0';
                wdb_parse(buffer2, response);
                if (length = strlen(response), length > 0) {
                    if (terminal && length < OS_MAXSTR - 1) {
                        response[length++] = '\n';
                    }
                    if (send(*peer, response, length, 0) < 0) {
                        merror("at run_worker(): send(%d): %s (%d)", *peer, strerror(errno), errno);
                    }
                }
            }
        }

        if (wnotify_delete(notify, *peer) < 0) {
            merror("at run_worker(): wnotify_delete(%d): %s (%d)", *peer, strerror(errno), errno);
        }

error:
        close(*peer);
        free(peer);
    }

    wnotify_close(notify);
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
