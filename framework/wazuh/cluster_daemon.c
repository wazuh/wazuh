// gcc -pthread -Wall cluster_daemon.c -o daemon -l sqlite3
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

#define OSSEC_PATH "/var/ossec"
#define DB_PATH "/stats/cluster_db"
#define SOCKET_PATH "/queue/ossec/cluster_db"
#define IN_BUFFER_SIZE sizeof(struct inotify_event) + 256
#define AGENT_INFO_PATH "/queue/agent-info/"
#define CLIENT_KEYS_PATH "/etc/client.keys"
#define AGENT_GROUPS_PATH "/queue/agent-groups/"
#define LOG_FILE "/logs/cluster_debug_socket.log"
#define LOG_FILE_I "/logs/cluster_debug_inotify.log"

struct file_thread_param {
    FILE *f;
};

int prepare_db(sqlite3 *db, sqlite3_stmt **res, char *sql, FILE *f) {
    int rc = sqlite3_prepare_v2(db, sql, -1, *(&res), 0);
    if (rc != SQLITE_OK) {
        char *create = "CREATE TABLE IF NOT EXISTS manager_file_status (" \
                       "id_manager TEXT," \
                        "id_file   TEXT," \
                        "status    TEXT NOT NULL CHECK (status IN ('synchronized', 'pending', 'failed', 'invalid')),"\
                        "PRIMARY KEY (id_manager, id_file))";
        rc = sqlite3_exec(db, create, NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            fprintf(f, "Failed to fetch data: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            exit(-1);
        }
        int rc = sqlite3_prepare_v2(db, sql, -1, *(&res), 0);
        if (rc != SQLITE_OK) {
            fprintf(f, "Failed to fetch data: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            exit(-1);
        }
    } 
    return 0;
}

void* daemon_socket(void *arg) {
    struct file_thread_param *param = arg;
    FILE *f = param->f;
    free(param);

    fprintf(f,"Preparing server socket\n");
    /* Prepare socket */
    struct sockaddr_un addr;
    char buf[1000000];
    char response[10000];
    int fd,cl,rc;

    char socket_path[80];
    strcpy(socket_path, OSSEC_PATH);
    strcat(socket_path, SOCKET_PATH);

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        fprintf(f, "Error initializing server socket: %s\n", strerror(errno));
        exit(-1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
    unlink(socket_path);

    int oldmask = umask(0660);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        fprintf(f, "Error binding socket: %s\n", strerror(errno));
        exit(-1);
    }

    umask(oldmask);

    fprintf(f,"Opening database\n");
    /* Prepare database */
    char db_path[80];
    strcpy(db_path, OSSEC_PATH);
    strcat(db_path, DB_PATH);

    sqlite3 *db;
    sqlite3_stmt *res;
    int sqlite_rc = sqlite3_open(db_path, &db);
    if (sqlite_rc != SQLITE_OK) {
        fprintf(f, "Error opening database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(-1);
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
        fprintf(f, "Error listening in socket: %s\n", strerror(errno));
        exit(-1);
    }

    char *cmd;
    while (1) {
        if ( (cl = accept(fd, NULL, NULL)) == -1) {
            fprintf(f, "Error accepting connection: %s\n", strerror(errno));
            continue;
        }

        fprintf(f,"Accepted connection from %d\n", cl);

        memset(buf, 0, sizeof(buf));
        memset(response, 0, sizeof(response));
        // strcpy(response, " ");
        while ( (rc=recv(cl,buf,sizeof(buf),0)) > 0) {

            cmd = strtok(buf, " ");
            fprintf(f,"Received %s command\n", cmd);
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
                fprintf(f,"Nothing to do\n");
                goto transaction_done;
            }
            
            int step;
            if (prepare_db(db, &res, sql, f) < 0) exit(-1);
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
            fprintf(f, "Error reading in socket: %s\n", strerror(errno));
            exit(-1);
        }
        else if (rc == 0) {
            fprintf(f,"Closed connection from %d\n", cl);
            if (close(cl) < 0) {
                fprintf(f, "Error closing connection from %d: %s\n", cl, strerror(errno));
                exit(-1);
            }
        }
    }

    sqlite3_close(db);

    return 0;
}

void* daemon_inotify(void *arg) {
    struct file_thread_param *param = arg;
    FILE *f = param->f;
    free(param);

    fprintf(f,"Preparing client socket\n");
    /* prepare socket */
    struct sockaddr_un addr;
    int db_socket,rc;

    char socket_path[80];
    strcpy(socket_path, OSSEC_PATH);
    strcat(socket_path, SOCKET_PATH);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    fprintf(f, "Preparing inotify watchers\n");
    /* prepare inotify */
    int fd, wd_agent_info, wd_client_keys, wd_agent_groups;
    fd = inotify_init ();

    char agent_info_path[80];
    strcpy(agent_info_path, OSSEC_PATH);
    strcat(agent_info_path, AGENT_INFO_PATH);
    wd_agent_info = inotify_add_watch (fd, agent_info_path, IN_MODIFY);
    if (wd_agent_info < 0) 
        fprintf(f, "Error setting watcher for agent info: %s\n", strerror(errno));

    char agent_groups_path[80];
    strcpy(agent_groups_path, OSSEC_PATH);
    strcat(agent_groups_path, AGENT_GROUPS_PATH);
    wd_agent_groups = inotify_add_watch (fd, agent_groups_path, IN_MODIFY);
    if (wd_agent_groups < 0)
        fprintf(f, "Error setting watcher for agent groups: %s\n", strerror(errno));

    char client_keys_path[80];
    strcpy(client_keys_path, OSSEC_PATH);
    strcat(client_keys_path, CLIENT_KEYS_PATH);
    wd_client_keys = inotify_add_watch (fd, client_keys_path, IN_MODIFY);
    if (wd_client_keys < 0) 
        fprintf(f, "Error setting watcher for client keys: %s\n", strerror(errno));

    char buffer[IN_BUFFER_SIZE];
    struct inotify_event *event = (struct inotify_event *)buffer;
    ssize_t count;
    unsigned int i;

    while (1) {
        if ((count = read(fd, buffer, IN_BUFFER_SIZE)) < 0) {
            if (errno != EAGAIN)
                fprintf(f, "Error reading inotify: %s\n", strerror(errno));

            break;
        }

        buffer[count - 1] = '\0';

        for (i = 0; i < count; i += (ssize_t)(sizeof(struct inotify_event) + event->len)) {
            char cmd[80];

            event = (struct inotify_event*)&buffer[i];
            fprintf(f,"inotify: i='%d', name='%s', mask='%u', wd='%d'\n", i, event->name, event->mask, event->wd);
            if (event->wd == wd_agent_info) {
                if (event->mask & IN_MODIFY) {
                    strcpy(cmd, "update1 ");
                    strcat(cmd, AGENT_INFO_PATH);
                    strcat(cmd, event->name);
                } else if (event->mask & IN_IGNORED) {
                    inotify_rm_watch(fd, wd_agent_info);
                    wd_agent_info = inotify_add_watch(fd, agent_info_path , IN_MODIFY);
                } else if (event->mask & IN_Q_OVERFLOW) {
                    fprintf(f, "Inotify event queue overflowed");
                    continue;
                } else {
                    fprintf(f, "Unknown inotify event\n");
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
                    fprintf(f, "Inotify event queue overflowed");
                    continue;
                } else {
                    fprintf(f, "Unknown inotify event\n");
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
                    fprintf(f, "Inotify event queue overflowed");
                    continue;
                } else {
                    fprintf(f, "Unknown inotify event\n");
                    continue;
                }
            } 

            if ((db_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
                fprintf(f, "Error initializing client socket: %s\n", strerror(errno));
                exit(-1);
            }

            if (connect(db_socket, (struct sockaddr*)&addr , sizeof(addr)) < 0) {
                fprintf(f, "Error connecting to socket: %s\n", strerror(errno));
                exit(-1);
            }

            if ((rc = write(db_socket, cmd, sizeof(cmd))) < 0) {
                fprintf(f, "Error writing update in DB socket: %s\n", strerror(errno));
                exit(-1);
            }

            char data[10000];
            recv(db_socket, data, sizeof(data),0);
            if (shutdown(db_socket, SHUT_RDWR) < 0) {
                fprintf(f, "Error in shutdown: %s\n", strerror(errno));
            }
            if (close(db_socket) < 0) {
                fprintf(f, "Error closing client socket:  %s\n", strerror(errno));
            }
            memset(cmd,0,sizeof(cmd));
            memset(data,0,sizeof(data));
        }
    }

    fprintf(f,"Removing watchers\n");
    /*removing the directory from the watch list.*/
    inotify_rm_watch( fd, wd_agent_info );
    inotify_rm_watch( fd, wd_agent_groups );
    inotify_rm_watch( fd, wd_client_keys );
    close(fd);

    return 0;
}

int main(void) {
    if (daemon(0, 0) < 0) {
        fprintf(stderr, "Error starting daemon: %s\n", strerror(errno));
        exit(-1);
    }

    struct file_thread_param *arg = malloc(sizeof *arg);

    char log_path[80];
    strcpy(log_path, OSSEC_PATH);
    strcat(log_path, LOG_FILE);
    FILE *f = fopen(log_path, "w");
    arg->f = f;

    if (f == NULL) {
        fprintf(stderr, "Error opening file %s: %s\n", log_path, strerror(errno));
        exit(-1);
    }

    struct file_thread_param *arg2 = malloc(sizeof *arg2);

    char log_path2[80];
    strcpy(log_path2, OSSEC_PATH);
    strcat(log_path2, LOG_FILE_I);
    FILE *f2 = fopen(log_path2, "w");
    arg2->f = f2;

    if (f2 == NULL) {
        fprintf(stderr, "Error opening file %s: %s\n", log_path, strerror(errno));
        exit(-1);
    }

    pthread_t socket_thread, inotify_thread;

    pthread_create(&socket_thread, NULL, daemon_socket, arg);
    sleep(1);
    pthread_create(&inotify_thread, NULL, daemon_inotify, arg2);

    pthread_join(socket_thread, NULL);
    pthread_join(inotify_thread, NULL);

    return 0;
}
