/*
 * Wazuh Cluster Daemon
 * Copyright (C) 2017 Wazuh Inc.
 * October 05, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sqlite3.h>
#include <string.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/inotify.h>
#include <debug_op.h>
#include <defs.h>
#include <help.h>
#include <file_op.h>
#include <error_messages.h>

#define DB_PATH "/var/db/cluster_db"
#define SOCKET_PATH "/queue/ossec/cluster_db"
#define IN_BUFFER_SIZE sizeof(struct inotify_event) + 256
#define AGENT_INFO_PATH "/queue/agent-info/"
#define CLIENT_KEYS_PATH "/etc/client.keys"
#define AGENT_GROUPS_PATH "/queue/agent-groups/"
#define LOG_FILE "/logs/cluster_debug_socket.log"
#define LOG_FILE_I "/logs/cluster_debug_inotify.log"

#define MAIN_TAG "wazuh-clusterd-internal"
#define INOTIFY_TAG "cluster_inotify"
#define DB_TAG "cluster_db_socket"

/* Print help statement */
static void help_cluster_daemon(char * name)
{
    print_header();
    print_out("  %s: -[Vhdf]", name);
    print_out("    -V          Version and license message.");
    print_out("    -h          This help message.");
    print_out("    -d          Debug mode. Use this parameter multiple times to increase the debug level.");
    print_out("    -f          Run in foreground.");
    print_out(" ");
    exit(1);
}

int prepare_db(sqlite3 *db, sqlite3_stmt **res, char *sql) {
    int rc = sqlite3_prepare_v2(db, sql, -1, *(&res), 0);
    if (rc != SQLITE_OK) {
        char *create = "CREATE TABLE IF NOT EXISTS manager_file_status (" \
                       "id_manager TEXT," \
                        "id_file   TEXT," \
                        "status    TEXT NOT NULL CHECK (status IN ('synchronized', 'pending', 'failed', 'invalid')),"\
                        "PRIMARY KEY (id_manager, id_file))";
        rc = sqlite3_exec(db, create, NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            sqlite3_close(db);
            mterror_exit(DB_TAG, "Failed to fetch data: %s", sqlite3_errmsg(db));
        }
        int rc = sqlite3_prepare_v2(db, sql, -1, *(&res), 0);
        if (rc != SQLITE_OK) {
            sqlite3_close(db);
            mterror_exit(DB_TAG, "Failed to fetch data: %s", sqlite3_errmsg(db));
        }
    } 
    return 0;
}

void* daemon_socket() {
    mtdebug1(DB_TAG,"Preparing server socket");
    /* Prepare socket */
    struct sockaddr_un addr;
    char buf[1000000];
    char response[10000];
    int fd,cl,rc;

    char socket_path[80];
    strcpy(socket_path, DEFAULTDIR);
    strcat(socket_path, SOCKET_PATH);

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        mterror_exit(DB_TAG, "Error initializing server socket: %s", strerror(errno));
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
    unlink(socket_path);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        mterror_exit(DB_TAG, "Error binding socket: %s", strerror(errno));
    }

    /* Change permissions */
    if (chmod(socket_path, 0660) < 0) {
        close(fd);
        mterror_exit(DB_TAG, "Error changing socket permissions: %s", strerror(errno));
    }

    /* Prepare database */
    char db_path[80];
    strcpy(db_path, DEFAULTDIR);
    strcat(db_path, DB_PATH);

    mtdebug1(DB_TAG, "Opening database %s", db_path);

    sqlite3 *db;
    sqlite3_stmt *res;
    int sqlite_rc = sqlite3_open(db_path, &db);
    if (sqlite_rc != SQLITE_OK) {
        mterror_exit(DB_TAG, "Error opening database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    // sql sentences to update file status
    char *sql_upd2 = "UPDATE manager_file_status SET status = ? WHERE id_manager = ? AND id_file = ?";
    char *sql_upd1 = "UPDATE manager_file_status SET status = 'pending' WHERE id_file = ?";
    // sql sentence to insert new row
    char *sql_ins = "INSERT INTO manager_file_status VALUES (?,?,'pending')";
    // sql sentence to perform a select query
    char *sql_sel = "SELECT * FROM manager_file_status WHERE id_manager = ? LIMIT ? OFFSET ?";
    char *sql_count = "SELECT Count(*) FROM manager_file_status WHERE id_manager = ?";

    char *sql;
    bool has2, has3, select, count;

    if (listen(fd, 5) == -1) {
        mterror_exit(DB_TAG, "Error listening in socket: %s", strerror(errno));
    }

    char *cmd;
    while (1) {
        if ( (cl = accept(fd, NULL, NULL)) == -1) {
            mterror(DB_TAG, "Error accepting connection: %s", strerror(errno));
            continue;
        }

        mtdebug2(DB_TAG,"Accepted connection from %d", cl);

        memset(buf, 0, sizeof(buf));
        memset(response, 0, sizeof(response));
        // strcpy(response, " ");
        while ( (rc=recv(cl,buf,sizeof(buf),0)) > 0) {

            cmd = strtok(buf, " ");
            mtdebug2(DB_TAG,"Received %s command", cmd);
            if (cmd != NULL && strcmp(cmd, "update1") == 0) {
                sql = sql_upd1;
                count = false;
                has2 = false;
                has3 = false;
                select = false;
            } else if (cmd != NULL && strcmp(cmd, "update2") == 0) {
                sql = sql_upd2;
                count = false;
                has2 = true;
                has3 = true;
                select = false;
            } else if (cmd != NULL && strcmp(cmd, "insert") == 0) {
                sql = sql_ins;
                count = false;
                has2 = true;
                has3 = false;
                select = false;
            } else if (cmd != NULL && strcmp(cmd, "select") == 0) {
                sql = sql_sel;
                select = true;
                count = false;
                has2 = true;
                has3 = true;
                strcpy(response, " ");
            } else if (cmd != NULL && strcmp(cmd, "count") == 0) {
                sql = sql_count;
                select = false;
                count = true;
                has2 = false;
                has3 = false;
            } else {
                mtdebug1(DB_TAG,"Nothing to do");
                goto transaction_done;
            }
            
            int step;
            prepare_db(db, &res, sql);
            sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
            while (cmd != NULL) {
                cmd = strtok(NULL, " ");
                if (cmd == NULL) break;
                sqlite3_bind_text(res,1,cmd,-1,0);
                if (has2) {
                    cmd = strtok(NULL, " ");
                    sqlite3_bind_text(res,2,cmd,-1,0);
                } 
                if (has3) {
                    cmd = strtok(NULL, " ");
                    sqlite3_bind_text(res,3,cmd,-1,0);
                }
                
                do {
                    step = sqlite3_step(res);
                    if (step != SQLITE_ROW) break;
                    if (select) {
                        strcat(response, (char *)sqlite3_column_text(res, 1));
                        strcat(response, "*");
                        strcat(response, (char *)sqlite3_column_text(res, 2));
                        strcat(response, " ");
                    } else if (count) {
                        char str[10];
                        sprintf(str, "%d", sqlite3_column_int(res, 0));
                        strcpy(response, str);
                    } else 
                        strcpy(response, "Command OK");
                } while (step == SQLITE_ROW);
                sqlite3_clear_bindings(res);
                sqlite3_reset(res);

            }
            sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL);

            transaction_done:
            send(cl,response,sizeof(response),0);

            memset(buf, 0, sizeof(buf));
            memset(response, 0, sizeof(response));
        }

        if (rc == -1) {
            mterror_exit(DB_TAG, "Error reading in socket: %s", strerror(errno));
        }
        else if (rc == 0) {
            mtinfo(DB_TAG,"Closed connection from %d", cl);
            if (close(cl) < 0) {
                mterror_exit(DB_TAG, "Error closing connection from %d: %s", cl, strerror(errno));
            }
        }
    }

    sqlite3_close(db);

    return 0;
}

void* daemon_inotify() {
    mtinfo(INOTIFY_TAG,"Preparing client socket");
    /* prepare socket */
    struct sockaddr_un addr;
    int db_socket,rc;

    char socket_path[80];
    strcpy(socket_path, DEFAULTDIR);
    strcat(socket_path, SOCKET_PATH);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    mtdebug1(INOTIFY_TAG, "Preparing inotify watchers");
    /* prepare inotify */
    int fd, wd_agent_info, wd_client_keys, wd_agent_groups;
    fd = inotify_init ();

    char agent_info_path[80];
    strcpy(agent_info_path, DEFAULTDIR);
    strcat(agent_info_path, AGENT_INFO_PATH);
    wd_agent_info = inotify_add_watch (fd, agent_info_path, IN_MODIFY);
    if (wd_agent_info < 0) 
        mterror(INOTIFY_TAG, "Error setting watcher for agent info: %s", strerror(errno));

    char agent_groups_path[80];
    strcpy(agent_groups_path, DEFAULTDIR);
    strcat(agent_groups_path, AGENT_GROUPS_PATH);
    wd_agent_groups = inotify_add_watch (fd, agent_groups_path, IN_MODIFY);
    if (wd_agent_groups < 0)
        mterror(INOTIFY_TAG, "Error setting watcher for agent groups: %s", strerror(errno));

    char client_keys_path[80];
    strcpy(client_keys_path, DEFAULTDIR);
    strcat(client_keys_path, CLIENT_KEYS_PATH);
    wd_client_keys = inotify_add_watch (fd, client_keys_path, IN_MODIFY);
    if (wd_client_keys < 0) 
        mterror(INOTIFY_TAG, "Error setting watcher for client keys: %s", strerror(errno));

    char buffer[IN_BUFFER_SIZE];
    struct inotify_event *event = (struct inotify_event *)buffer;
    ssize_t count;
    unsigned int i;

    while (1) {
        if ((count = read(fd, buffer, IN_BUFFER_SIZE)) < 0) {
            if (errno != EAGAIN)
                mterror(INOTIFY_TAG, "Error reading inotify: %s", strerror(errno));

            break;
        }

        buffer[count - 1] = '\0';

        for (i = 0; i < count; i += (ssize_t)(sizeof(struct inotify_event) + event->len)) {
            char cmd[80];

            event = (struct inotify_event*)&buffer[i];
            mtdebug2(INOTIFY_TAG,"inotify: i='%d', name='%s', mask='%u', wd='%d'", i, event->name, event->mask, event->wd);
            if (event->wd == wd_agent_info) {
                if (event->mask & IN_MODIFY) {
                    strcpy(cmd, "update1 ");
                    strcat(cmd, AGENT_INFO_PATH);
                    strcat(cmd, event->name);
                } else if (event->mask & IN_IGNORED) {
                    inotify_rm_watch(fd, wd_agent_info);
                    wd_agent_info = inotify_add_watch(fd, agent_info_path , IN_MODIFY);
                } else if (event->mask & IN_Q_OVERFLOW) {
                    mtinfo(INOTIFY_TAG, "Inotify event queue overflowed");
                    continue;
                } else {
                    mtinfo(INOTIFY_TAG, "Unknown inotify event");
                    continue;
                }
            } else if (event->wd == wd_agent_groups) {
                if (event->mask & IN_MODIFY) {
                    strcpy(cmd, "update1 ");
                    strcat(cmd, AGENT_GROUPS_PATH);
                    strcat(cmd, event->name);
                } else if (event->mask & IN_IGNORED) {
                    inotify_rm_watch(fd, wd_agent_groups);
                    wd_agent_groups = inotify_add_watch(fd, agent_groups_path , IN_MODIFY);
                } else if (event->mask & IN_Q_OVERFLOW) {
                    mtinfo(INOTIFY_TAG, "Inotify event queue overflowed");
                    continue;
                } else {
                    mtinfo(INOTIFY_TAG, "Unknown inotify event");
                    continue;
                }
            } else if (event->wd == wd_client_keys) {
                if (event->mask & IN_MODIFY) {
                    strcpy(cmd, "update1 ");
                    strcat(cmd, CLIENT_KEYS_PATH);
                } else if (event->mask & IN_IGNORED) {
                    inotify_rm_watch(fd, wd_client_keys);
                    wd_client_keys = inotify_add_watch(fd, client_keys_path , IN_MODIFY);
                } else if (event->mask & IN_Q_OVERFLOW) {
                    mtinfo(INOTIFY_TAG, "Inotify event queue overflowed");
                    continue;
                } else {
                    mtinfo(INOTIFY_TAG, "Unknown inotify event");
                    continue;
                }
            } 

            if ((db_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
                mterror_exit(INOTIFY_TAG, "Error initializing client socket: %s", strerror(errno));
            }

            if (connect(db_socket, (struct sockaddr*)&addr , sizeof(addr)) < 0) {
                mterror_exit(INOTIFY_TAG, "Error connecting to socket: %s", strerror(errno));
            }

            if ((rc = write(db_socket, cmd, sizeof(cmd))) < 0) {
                mterror_exit(INOTIFY_TAG, "Error writing update in DB socket: %s", strerror(errno));
            }

            char data[10000];
            recv(db_socket, data, sizeof(data),0);
            if (shutdown(db_socket, SHUT_RDWR) < 0) {
                mterror(INOTIFY_TAG, "Error in shutdown: %s", strerror(errno));
            }
            if (close(db_socket) < 0) {
                mterror(INOTIFY_TAG, "Error closing client socket:  %s", strerror(errno));
            }
            memset(cmd,0,sizeof(cmd));
            memset(data,0,sizeof(data));
        }
    }

    mtdebug1(INOTIFY_TAG,"Removing watchers");
    /*removing the directory from the watch list.*/
    inotify_rm_watch( fd, wd_agent_info );
    inotify_rm_watch( fd, wd_agent_groups );
    inotify_rm_watch( fd, wd_client_keys );
    close(fd);

    return 0;
}

/* Signal handler */
void handler(int signum) {
    switch (signum) {
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
        mtinfo(MAIN_TAG, SIGNAL_RECV, signum, strsignal(signum));
        DeletePID(MAIN_TAG);
        break;
    default:
        mterror(MAIN_TAG, "unknown signal (%d)", signum);
    }
    exit(1);
}

int main(int argc, char * const * argv) {
    int run_foreground = 0;
    int c;
    while (c = getopt(argc, argv, "fdVh"), c != -1) {
        switch(c) {
            case 'f':
                run_foreground = 1;
                break;

            case 'd':
                nowDebug();
                break;

            case 'V':
                print_version();
                break;

            case 'h':
                help_cluster_daemon(argv[0]);
                break;
        }
    }

    if (!run_foreground) {
        if (daemon(0, 0) < 0) {
            mterror_exit(MAIN_TAG, "Error starting daemon: %s", strerror(errno));
        }
    }

    /* Create PID files */
    mtdebug2(MAIN_TAG, "Creating PID file...");
    if (CreatePID(MAIN_TAG, getpid()) < 0) {
        mterror_exit(MAIN_TAG, PID_ERROR);
    }

    /* Signal manipulation */
    {
        struct sigaction action = { .sa_handler = handler, .sa_flags = SA_RESTART };
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGINT, &action, NULL);
    }

    pthread_t socket_thread, inotify_thread;

    pthread_create(&socket_thread, NULL, daemon_socket, NULL);
    sleep(1);
    pthread_create(&inotify_thread, NULL, daemon_inotify, NULL);

    pthread_join(socket_thread, NULL);
    pthread_join(inotify_thread, NULL);

    return 0;
}
