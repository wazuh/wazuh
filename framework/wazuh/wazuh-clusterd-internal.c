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
#include <sys/stat.h>
#include <error_messages.h>
#include <cJSON.h>
#include <dirent.h>
#include <pwd.h>
#include <hash_op.h>
#include <queue_op.h>
#include <md5_op.h>

#define DB_PATH DEFAULTDIR "/var/db/cluster.db"
#define SOCKET_PATH DEFAULTDIR "/queue/ossec/cluster_db"
#define IN_BUFFER_SIZE sizeof(struct inotify_event) + 256

#define CLUSTER_JSON DEFAULTDIR "/framework/wazuh/cluster.json"

#define MAIN_TAG "wazuh-clusterd-internal"
#define INOTIFY_TAG MAIN_TAG ":inotify"
#define DB_TAG MAIN_TAG ":db_socket"

#define PATH_MAX 4096

static w_queue_t * queue;                 // Queue for pending files
static OSHash * ptable;                   // Table for pending paths
static pthread_mutex_t mutex_queue = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_pending = PTHREAD_COND_INITIALIZER;

/* Print help statement */
static void help_cluster_daemon(char * name)
{
    print_header();
    print_out("  %s: -[Vhdf]", name);
    print_out("    -V                   Version and license message.");
    print_out("    -h                   This help message.");
    print_out("    -d                   Debug mode. Use this parameter multiple times to increase the debug level.");
    print_out("    -f                   Run in foreground.");
    print_out("    -t<node_type>        Specify node type.");
    print_out(" ");
    exit(1);
}

/* function to get the size of a file */
off_t fsize(char *file) {
    struct stat filestat;
    if (stat(file, &filestat) == 0) {
        return filestat.st_size;
    }
    return 0;
}

/* function to get the modification date of a fize */
time_t mod_time(char *file) {
    struct stat filestat;
    if (stat(file, &filestat) == 0) {
        return filestat.st_mtime;
    }
    return 0;
}

/* Read a file and store data into a byte array
   size: length of the array
   The funcion will read (size-1) bytes and terminate the string
*/
void read_file(char * pathname, char * buffer, off_t size) {
    if (size < 0) mterror_exit(INOTIFY_TAG, "File %s is empty", pathname);
    size_t unsigned_size = (size_t)size;
    FILE * pFile;
    size_t result;

    pFile = fopen(pathname, "rb");
    if (pFile == NULL)
        mterror_exit(MAIN_TAG, "Error opening file: %s", strerror(errno));

    // copy the file into the buffer
    result = fread(buffer, sizeof(char), unsigned_size-1, pFile);
    buffer[unsigned_size - 1] = '\0';
    if (result != unsigned_size-1)
        mterror_exit(MAIN_TAG, "Error reading file: %s", strerror(errno));

    // terminte
    fclose(pFile);
}

int prepare_db(sqlite3 *db, sqlite3_stmt **res, char *sql) {
    int rc = sqlite3_prepare_v2(db, sql, -1, *(&res), 0);
    if (rc != SQLITE_OK) {
        char *create1 = "CREATE TABLE IF NOT EXISTS manager_file_status (" \
                       "id_manager TEXT," \
                        "id_file   TEXT," \
                        "status    TEXT NOT NULL CHECK (status IN ('synchronized', 'pending', 'failed', 'invalid')),"\
                        "PRIMARY KEY (id_manager, id_file))";
        rc = sqlite3_exec(db, create1, NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            sqlite3_close(db);
            mterror_exit(DB_TAG, "Failed to create db table: %s", sqlite3_errmsg(db));
        }

        char *create2 = "CREATE TABLE IF NOT EXISTS last_sync (" \
                        "date     INTEGER PRIMARY KEY," \
                        "duration REAL)";
        rc = sqlite3_exec(db, create2, NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            sqlite3_close(db);
            mterror_exit(DB_TAG, "Failed to create db table: %s", sqlite3_errmsg(db));
        }

        char *create3 = "CREATE TABLE IF NOT EXISTS file_integrity (" \
                        "filename TEXT PRIMARY KEY," \
                        "md5      TEXT," \
                        "mod_date INTEGER)";
        rc = sqlite3_exec(db, create3, NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            sqlite3_close(db);
            mterror_exit(DB_TAG, "Failed to create db table: %s", sqlite3_errmsg(db));
        }

        char *create4 = "CREATE TABLE IF NOT EXISTS node_name_ip (" \
                        "name       TEXT," \
                        "id_manager TEXT PRIMARY KEY)";
        rc = sqlite3_exec(db, create4, NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            sqlite3_close(db);
            mterror_exit(DB_TAG, "Failed to create db table: %s", sqlite3_errmsg(db));
        }

        char *create5 = "CREATE TABLE IF NOT EXISTS actual_master (" \
                        "node_name TEXT PRIMARY KEY)";
        rc = sqlite3_exec(db, create5, NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            sqlite3_close(db);
            mterror_exit(DB_TAG, "Failed to create db table: %s", sqlite3_errmsg(db));
        }

        rc = sqlite3_prepare_v2(db, sql, -1, *(&res), 0);
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

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        mterror_exit(DB_TAG, "Error initializing server socket: %s", strerror(errno));
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path)-1);
    unlink(SOCKET_PATH);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        mterror_exit(DB_TAG, "Error binding socket: %s (%s)", strerror(errno), SOCKET_PATH);
    }

    /* Change permissions */
    if (chmod(SOCKET_PATH, 0660) < 0) {
        close(fd);
        mterror_exit(DB_TAG, "Error changing socket permissions: %s", strerror(errno));
    }

    /* Change user and group to ossec */
    struct passwd *pwd;
    if ((pwd = getpwnam("ossec")) == NULL)
        mterror_exit(DB_TAG, "Could not get uid for user ossec: %s", strerror(errno));

    if (chown(SOCKET_PATH, pwd->pw_uid, pwd->pw_gid) < 0)
        mterror_exit(DB_TAG, "Could not change owner of file %s: %s", SOCKET_PATH, strerror(errno));


    mtdebug1(DB_TAG, "Opening database %s", DB_PATH);

    sqlite3 *db;
    sqlite3_stmt *res;
    int sqlite_rc = sqlite3_open(DB_PATH, &db);
    if (sqlite_rc != SQLITE_OK) {
        mterror_exit(DB_TAG, "Error opening database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    // sql sentences to update file status
    char *sql_upd2 = "UPDATE manager_file_status SET status = ? WHERE id_manager = ? AND id_file = ?";
    char *sql_upd1 = "UPDATE manager_file_status SET status = 'pending' WHERE id_file = ?";
    char *sql_clr  = "UPDATE manager_file_status SET status = 'pending'";
    // sql sentence to insert new row
    char *sql_ins = "INSERT OR REPLACE INTO manager_file_status VALUES (?,?,'pending')";
    // sql sentence to perform a select query
    char *sql_sel = "SELECT * FROM manager_file_status WHERE id_manager = ? LIMIT ? OFFSET ?";
    char *sql_count = "SELECT Count(*) FROM manager_file_status WHERE id_manager = ?";
    char *sql_del1 = "DELETE FROM manager_file_status WHERE id_file = ?";
    // sql sentences to insert a new row in the last_sync table
    char *sql_del_lastsync = "DELETE FROM last_sync";
    char *sql_last_sync = "INSERT INTO last_sync(date, duration) VALUES (?,?)";
    char *sql_sel_sync = "SELECT * FROM last_sync";
    // sql sentences to insert or update a new row in the file_integrity table
    char *sql_ins_fi = "INSERT OR REPLACE INTO file_integrity VALUES (?,?,?)";
    char *sql_sel_fi = "SELECT * FROM file_integrity LIMIT ? OFFSET ?";
    char *sql_count_fi = "SELECT Count(*) FROM file_integrity";
    char *sql_upd_fi = "UPDATE file_integrity SET md5 = ?, mod_date = ? WHERE filename = ?";
    // sql sentence to manage IP from name
    char *sql_sel_by_name = "SELECT manager_file_status.id_manager as id_manager, manager_file_status.id_file as id_file, manager_file_status.status as status FROM node_name_ip INNER JOIN manager_file_status ON manager_file_status.id_manager = node_name_ip.id_manager WHERE node_name_ip.name = ? LIMIT ? OFFSET ?";
    char *sql_sel_ip_by_name = "SELECT id_manager FROM node_name_ip WHERE name = ?";
    char *sql_sel_name_by_ip = "SELECT name FROM node_name_ip WHERE id_manager = ?";
    char *sql_upd_ip_name = "UPDATE node_name_ip SET name = ? WHERE id_manager = ?";
    char *sql_ins_ip_name = "INSERT OR REPLACE INTO node_name_ip VALUES (?,?)";
    // SQL sentence to get the actual master
    char *sql_sel_actual = "SELECT * FROM actual_master";
    char *sql_ins_actual = "INSERT OR REPLACE INTO actual_master VALUES (?)";
    char *sql_del_actual = "DELETE FROM actual_master";

    char *sql;
    bool has1, has2, has3, select, count, select_last_sync, select_files, response_str;

    if (listen(fd, 5) == -1) {
        mterror_exit(DB_TAG, "Error listening in socket: %s", strerror(errno));
    }

    char *cmd, *endptr;
    while (1) {
        if ( (cl = accept(fd, NULL, NULL)) == -1) {
            mterror(DB_TAG, "Error accepting connection: %s", strerror(errno));
            continue;
        }


        mtdebug2(DB_TAG,"Accepted connection from %d", cl);

        memset(buf, 0, sizeof(buf));
        memset(response, 0, sizeof(response));
        while ( (rc=recv(cl,buf,sizeof(buf),0)) > 0) {
            has1=false; has2=false; has3=false; select=false; count=false; select_last_sync=false; select_files=false; response_str=false;

            cmd = strtok(buf, " ");
            mtdebug2(DB_TAG,"Received %s command", cmd);
            if (cmd != NULL && strcmp(cmd, "update1") == 0) {
                sql = sql_upd1;
                has1 = true;
            }else if (cmd != NULL && strcmp(cmd, "delete1") == 0) {
                sql = sql_del1;
                has1 = true;
            } else if (cmd != NULL && strcmp(cmd, "update2") == 0) {
                sql = sql_upd2;
                has1 = true;
                has2 = true;
                has3 = true;
            } else if (cmd != NULL && strcmp(cmd, "insert") == 0) {
                sql = sql_ins;
                has1 = true;
                has2 = true;
            } else if (cmd != NULL && strcmp(cmd, "select") == 0) {
                sql = sql_sel;
                select = true;
                has1 = true;
                has2 = true;
                has3 = true;
                strcpy(response, " ");
            } else if (cmd != NULL && strcmp(cmd, "sellast") == 0) {
                sql = sql_sel_sync;
                select_last_sync = true;
                strcpy(response, " ");
            } else if (cmd != NULL && strcmp(cmd, "count") == 0) {
                sql = sql_count;
                count = true;
                has1 = true;
            } else if (cmd != NULL && strcmp(cmd, "clear") == 0) {
                sql = sql_clr;
            } else if (cmd != NULL && strcmp(cmd, "clearlast") == 0) {
                sql = sql_del_lastsync;
            } else if (cmd != NULL && strcmp(cmd, "updatelast") == 0) {
                sql = sql_last_sync;
                has1 = true;
                has2 = true;
            } else if (cmd != NULL && strcmp(cmd, "insertfile") == 0) {
                sql = sql_ins_fi;
                has1 = true;
                has2 = true;
                has3 = true;
            } else if (cmd != NULL && strcmp(cmd, "selfiles") == 0) {
                sql = sql_sel_fi;
                has1 = true;
                has2 = true;
                select_files = true;
                strcpy(response, " ");
            } else if (cmd != NULL && strcmp(cmd, "countfiles") == 0) {
                sql = sql_count_fi;
                count = true;
            } else if (cmd != NULL && strcmp(cmd, "updatefile") == 0) {
                sql = sql_upd_fi;
                has1 = true;
                has2 = true;
                has3 = true;
            } else if (cmd != NULL && strcmp(cmd, "selectbyname") == 0) {
                sql = sql_sel_by_name;
                select = true;
                has1 = true; // name
                has2 = true; // limit
                has3 = true; // offset
                strcpy(response, " ");
            } else if (cmd != NULL && strcmp(cmd, "getip") == 0) {
                sql = sql_sel_ip_by_name;
                has1 = true; // name
                response_str = true;
            } else if (cmd != NULL && strcmp(cmd, "getname") == 0) {
                sql = sql_sel_name_by_ip;
                has1 = true; // name
                response_str = true;
            } else if (cmd != NULL && strcmp(cmd, "updatename") == 0) {
                sql = sql_upd_ip_name;
                has1 = true; // name
                has2 = true; // ip
            } else if (cmd != NULL && strcmp(cmd, "insertname") == 0) {
                sql = sql_ins_ip_name;
                has1 = true; // name
                has2 = true; // ip
            } else if (cmd != NULL && strcmp(cmd, "insertactual") == 0) {
                sql = sql_ins_actual;
                has1 = true;
            } else if (cmd != NULL && strcmp(cmd, "selactual") == 0) {
                sql = sql_sel_actual;
                select = true;
                strcpy(response, " ");
            } else if (cmd != NULL && strcmp(cmd, "delactual") == 0) {
                sql = sql_del_actual;
            } else {
                mtdebug1(DB_TAG,"Nothing to do");
                goto transaction_done;
            }

            int step;
            prepare_db(db, &res, sql);
            if (has1) {
                sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
                while (cmd != NULL) {
                    cmd = strtok(NULL, " ");
                    if (cmd == NULL) break;

                    if (strcmp(sql, sql_last_sync) == 0) {
                        long int value = strtol(cmd, &endptr, 10);
                        if (endptr == cmd) mterror_exit(DB_TAG, "No integer found in database request. Found: %s", cmd);
                        rc = sqlite3_bind_int(res,1,value);
                    }
                    else rc = sqlite3_bind_text(res,1,cmd,-1,0);
                    if (rc != SQLITE_OK) mterror_exit(DB_TAG,"Could not bind 1st parameter of query: %s", sqlite3_errmsg(db));

                    if (has2) {
                        cmd = strtok(NULL, " ");
                        if (strcmp(sql, sql_last_sync) == 0) {
                            double value = strtod(cmd, &endptr);
                            if (endptr == cmd) mterror_exit(DB_TAG, "No floating number found in database request. Found: %s", cmd);
                            rc = sqlite3_bind_double(res,2,value);
                        }
                        else rc = sqlite3_bind_text(res,2,cmd,-1,0);
                        if (rc != SQLITE_OK) mterror_exit(DB_TAG,"Could not bind 2nd parameter of query: %s", sqlite3_errmsg(db));
                    }
                    if (has3) {
                        cmd = strtok(NULL, " ");
                        if (strcmp(sql, sql_ins_fi) == 0) {
                            long int value = strtol(cmd, &endptr, 10);
                            if (endptr == cmd) mterror_exit(DB_TAG, "No integer found in database request. Found: %s", cmd);
                            rc = sqlite3_bind_int(res,3,value);
                        }
                        else rc = sqlite3_bind_text(res,3,cmd,-1,0);
                        if (rc != SQLITE_OK) mterror_exit(DB_TAG,"Could not bind 3rd parameter of query: %s", sqlite3_errmsg(db));
                    }

                    do {
                        step = sqlite3_step(res);
                        if (step == SQLITE_DONE && !count && !select && !select_files && !response_str) {
                            strcpy(response, "Command OK");
                            break;
                        }
                        else if (step != SQLITE_ROW && step != SQLITE_OK) break;

                        if (select) {
                            strcat(response, (char *)sqlite3_column_text(res, 1));
                            strcat(response, "*");
                            strcat(response, (char *)sqlite3_column_text(res, 2));
                            strcat(response, " ");
                        } else if (count) {
                            char str[10];
                            sprintf(str, "%d", sqlite3_column_int(res, 0));
                            strcpy(response, str);
                        } else if (select_files) {
                            char str[100];
                            sprintf(str, "%s*%s*%d ", (char *)sqlite3_column_text(res, 0), (char *)sqlite3_column_text(res, 1), sqlite3_column_int(res, 2));
                            strcat(response, str);
                        } else if (response_str) {
                            strcpy(response, (char *)sqlite3_column_text(res,0));
                        } else
                            strcpy(response, "Command OK");
                    } while (step == SQLITE_ROW || step == SQLITE_OK);
                    sqlite3_clear_bindings(res);
                    sqlite3_reset(res);

                }
                sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL);
            } else {
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                sqlite_rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
                if (sqlite_rc != SQLITE_OK) {
                    sqlite3_close(db);
                    mterror_exit(DB_TAG, "Failed to fetch data: %s", sqlite3_errmsg(db));
                }
                if (select_last_sync || count || select) {
                    do {
                        step = sqlite3_step(res);
                        if (step != SQLITE_ROW && step != SQLITE_OK) break;
                        if (select_last_sync) sprintf(response, "%d %lf", sqlite3_column_int(res, 0), sqlite3_column_double(res, 1));
                        else if (count) sprintf(response, "%d", sqlite3_column_int(res, 0));
                        else if (select) sprintf(response, "%s", (char *)sqlite3_column_text(res, 0));
                    } while (step == SQLITE_ROW || step == SQLITE_OK);
                } else strcpy(response, "Command OK");
            }

            transaction_done:
            if (send(cl,response,sizeof(response),0) < 0)
                mterror(DB_TAG, "Error sending response: %s", strerror(errno));

            memset(buf, 0, sizeof(buf));
            memset(response, 0, sizeof(response));
        }

        if (rc == -1) {
            mterror_exit(DB_TAG, "Error reading in socket: %s", strerror(errno));
        }
        else if (rc == 0) {
            mtdebug2(DB_TAG,"Closed connection from %d", cl);
            if (close(cl) < 0) {
                mterror_exit(DB_TAG, "Error closing connection from %d: %s", cl, strerror(errno));
            }
        }
    }

    sqlite3_close(db);

    return 0;
}


/* structure to save all info required for inotify daemon */
typedef struct {
    char name[PATH_MAX];
    char path[PATH_MAX];
    uint32_t flags;
    int watcher;
    cJSON * files;
} inotify_watch_file;

/* Convert a inotify flag string to int mask */
uint32_t get_flag_mask(cJSON * flags) {
    int i;
    uint32_t mask = 0;
    for (i = 0; i < cJSON_GetArraySize(flags); i++) {
        char * flag = cJSON_GetArrayItem(flags, i)->valuestring;
        if (strcmp(flag, "IN_ACCESS") == 0) mask |= IN_ACCESS;
        else if (strcmp(flag, "IN_ATTRIB") == 0) mask |= IN_ATTRIB;
        else if (strcmp(flag, "IN_CLOSE_WRITE") == 0) mask |= IN_CLOSE_WRITE;
        else if (strcmp(flag, "IN_CLOSE_NOWRITE") == 0) mask |= IN_CLOSE_NOWRITE;
        else if (strcmp(flag, "IN_CREATE") == 0) mask |= IN_CREATE;
        else if (strcmp(flag, "IN_DELETE") == 0) mask |= IN_DELETE;
        else if (strcmp(flag, "IN_DELETE_SELF") == 0) mask |= IN_DELETE_SELF;
        else if (strcmp(flag, "IN_MODIFY") == 0) mask |= IN_MODIFY;
        else if (strcmp(flag, "IN_MOVE_SELF") == 0) mask |= IN_MOVE_SELF;
        else if (strcmp(flag, "IN_MOVED_FROM") == 0) mask |= IN_MOVED_FROM;
        else if (strcmp(flag, "IN_MOVED_TO") == 0) mask |= IN_MOVED_TO;
        else if (strcmp(flag, "IN_OPEN") == 0) mask |= IN_OPEN;
        else if (strcmp(flag, "IN_ALL_EVENTS") == 0) mask |= IN_ALL_EVENTS;
        else if (strcmp(flag, "IN_DONT_FOLLOW") == 0) mask |= IN_DONT_FOLLOW;
        else if (strcmp(flag, "IN_MASK_ADD") == 0) mask |= IN_MASK_ADD;
        else if (strcmp(flag, "IN_ONESHOT") == 0) mask |= IN_ONESHOT;
        else if (strcmp(flag, "IN_ONLYDIR") == 0) mask |= IN_ONLYDIR;
        else if (strcmp(flag, "IN_MOVE") == 0) mask |= IN_MOVE;
        else if (strcmp(flag, "IN_CLOSE") == 0) mask |= IN_CLOSE;
    }
    return mask;
}

/* Store subdirectories names in subdirs array */
unsigned int get_subdirs(char * path, char ***_subdirs, unsigned int max_files_to_watch) {
    struct dirent *direntp;
    DIR *dirp;
    unsigned int found_subdirs = 0;
    unsigned int i=0;
    char **subdirs = *_subdirs;
    char **more_subdirs;
    for (i=0; i<max_files_to_watch; i++) if (subdirs[i] == 0) break;

    if ((dirp = opendir(path)) == NULL)
        mterror_exit(INOTIFY_TAG, "Error listing subdirectories of %s: %s", path, strerror(errno));

    while ((direntp = readdir(dirp)) != NULL) {
        if (strcmp(direntp->d_name, ".") == 0 || strcmp(direntp->d_name, "..") == 0) continue;

        if (direntp->d_type == DT_DIR) {
            if (found_subdirs+i == max_files_to_watch) {
                max_files_to_watch += 30;
                more_subdirs = (char **) realloc(subdirs, max_files_to_watch * sizeof(char*));
                if (more_subdirs == NULL) {
                    free(subdirs);
                    mterror_exit(INOTIFY_TAG, "Error reallocating memory for found subdirectories");
                } else *_subdirs = subdirs = more_subdirs;
                memset(subdirs + found_subdirs + i, 0, 30 * sizeof(char *));
            }

            size_t name_size = (sizeof(path) + sizeof(direntp->d_name) + sizeof("/")  + 1) * sizeof(char);
            subdirs[found_subdirs+i] = (char *) malloc(name_size);
            if (snprintf(subdirs[found_subdirs+i], name_size, "%s%s/", path, direntp->d_name) >= (ssize_t)name_size)
                mterror(INOTIFY_TAG, "String overflow in directory name %s%s", path, direntp->d_name);

            found_subdirs += get_subdirs(subdirs[found_subdirs+i], _subdirs, max_files_to_watch) + 1;
        }
    }

    if (closedir(dirp) < 0)
        mterror(INOTIFY_TAG, "Error closing directory %s: %s", path, strerror(errno));

    return found_subdirs;
}

/* Check if event filename is on ignore list */
bool check_if_ignore(cJSON * exclude_files, char * event_filename) {
    int i;
    bool exclude = false;
    for (i = 0; i < cJSON_GetArraySize(exclude_files); i++) {
        char * filename = cJSON_GetArrayItem(exclude_files, i)->valuestring;
        if (strcmp(filename, "all") == 0) {
            exclude = true;
            break;
        }
        if (strstr(event_filename, filename) != NULL) {
            exclude = true;
            break;
        }
    }
    return exclude;
}

/* read files to watch from cluster.json file */
cJSON * read_cluster_json_file() {
    off_t size = fsize(CLUSTER_JSON)+1;
    char * cluster_json;
    cluster_json = (char *) malloc (sizeof(char) *size+1);
    read_file(CLUSTER_JSON, cluster_json, size);

    cJSON * root = cJSON_Parse(cluster_json);

    return root;
}

/* get directories and subdirectories to watch with inotify */
unsigned int get_files_to_watch(char * node_type, inotify_watch_file ** _files, cJSON * root) {
    unsigned int n_files_to_watch = 0, max_files_to_watch = 30;
    int i = 0;
    inotify_watch_file * more_files = NULL, * files = *_files;

    for (i = 0; i < cJSON_GetArraySize(root); i++) {
        cJSON *subitem = cJSON_GetArrayItem(root, i);
        if (strcmp(subitem->string, "excluded_files") == 0) continue;
        cJSON *source_item = cJSON_GetObjectItemCaseSensitive(subitem, "source");

        if (strcmp(source_item->valuestring, node_type) == 0 ||
            strcmp(source_item->valuestring, "all") == 0) {

            char aux_path[PATH_MAX];
            if (snprintf(aux_path, PATH_MAX, "%s%s", DEFAULTDIR, subitem->string) >= PATH_MAX)
                mterror(INOTIFY_TAG, "Overflow error copying %s's name in memory", subitem->string);

            uint32_t flags = get_flag_mask(cJSON_GetObjectItemCaseSensitive(subitem, "flags"));
            if (cJSON_GetObjectItemCaseSensitive(subitem, "recursive")->type == cJSON_True) {
                char ** subdirs = (char **) calloc(30, sizeof(char*));
                if (subdirs == NULL) mterror_exit(INOTIFY_TAG, "Error allocating memory for subdirectories watchers");
                unsigned int found_subdirs = get_subdirs(aux_path, &subdirs, max_files_to_watch);
                unsigned int j;
                for (j = 0; j < found_subdirs; j++) {
                    strcpy(files[n_files_to_watch].path, subdirs[j]);

                    strcpy(files[n_files_to_watch].name, strstr(subdirs[j], subitem->string));

                    files[n_files_to_watch].flags = flags;
                    n_files_to_watch++;
                    if (n_files_to_watch >= max_files_to_watch) {
                        mtdebug2(INOTIFY_TAG, "Reallocating memory for file structure");
                        max_files_to_watch += 10;
                        more_files = realloc(files, max_files_to_watch*sizeof(inotify_watch_file));

                        if (more_files != NULL) *_files = files = more_files;
                        else {
                            free(files);
                            mterror_exit(INOTIFY_TAG, "Error reallocating memory for cluster.json files struct");
                        }
                        memset(files + n_files_to_watch, 0, 10 * sizeof(char *));
                    }

                }
            }

            if (snprintf(files[n_files_to_watch].path, PATH_MAX, "%s", aux_path) >= PATH_MAX)
                mterror(INOTIFY_TAG, "String overflow in filepath %s", files[n_files_to_watch].path);

            if (snprintf(files[n_files_to_watch].name, PATH_MAX, "%s", subitem->string) >= PATH_MAX)
                mterror(INOTIFY_TAG, "String overflow in file name %s", subitem->string);

            files[n_files_to_watch].flags = flags;

            files[n_files_to_watch].files = cJSON_GetObjectItemCaseSensitive(subitem, "files");

            mtinfo(INOTIFY_TAG, "Monitoring %s", cJSON_GetObjectItemCaseSensitive(subitem, "description")->valuestring);
            n_files_to_watch++;
            if (n_files_to_watch >= max_files_to_watch) {
                mtdebug2(INOTIFY_TAG, "Reallocating memory for file structure");
                max_files_to_watch += 10;
                more_files = realloc(files, max_files_to_watch*sizeof(inotify_watch_file));

                if (more_files != NULL) *_files = files = more_files;
                else {
                    free(files);
                    mterror_exit(INOTIFY_TAG, "Error reallocating memory for cluster.json files struct");
                }
                memset(files + n_files_to_watch, 0, 10 * sizeof(char *));
            }
        }
    }

    return n_files_to_watch;
}

typedef struct {
    int fd;
    int n_files_to_watch;
    inotify_watch_file * files;
    cJSON * root;
} inotify_reader_arguments;

// Insert request into internal structure
void inotify_push_request(char * cmd) {
    char * dup;
    int error;

    error = pthread_mutex_lock(&mutex_queue);
    if (error) mterror_exit(INOTIFY_TAG, "Error locking queue at inotify_push_request: %s", strerror(errno));

    if (queue_full(queue)) {
        mterror(INOTIFY_TAG, "Internal queue is full (%zu)", queue->size);
        goto end;
    }

    switch (OSHash_Add(ptable, cmd, (void *)1)) {
    case 0:
        mterror(INOTIFY_TAG, "Could not insert key %s into table", cmd);
        break;

    case 1:
        mtdebug2(INOTIFY_TAG, "Adding %s: command already exists at path table", cmd);
        break;

    case 2:
        dup = strdup(cmd);
        mtdebug2(INOTIFY_TAG, "Adding %s to inotify command table", cmd);

        if (queue_push(queue, dup) < 0) {
            mterror(INOTIFY_TAG, "Could not insert key %s into queue", dup);
            free(dup);
        }
        error = pthread_cond_signal(&cond_pending);
        if (error) mterror_exit(INOTIFY_TAG, "Error sending cond signal at inotify_push_request: %s", strerror(errno));
    }
end:
    error = pthread_mutex_unlock(&mutex_queue);
    if (error) mterror_exit(INOTIFY_TAG, "Error unlocking queue at inotify_push_request: %s", strerror(errno));
}

// Real time inotify reader thread
void* inotify_reader(void * args) {
    inotify_reader_arguments* reader_args = (inotify_reader_arguments*) args;

    int i, fd = reader_args->fd;
    unsigned int n_files_to_watch = reader_args->n_files_to_watch;
    inotify_watch_file * files = reader_args->files;
    cJSON * root = reader_args->root;

    char buffer[IN_BUFFER_SIZE];
    struct inotify_event *event = (struct inotify_event *)buffer;
    ssize_t count;
    bool ignore = false;

    while (1) {
        if ((count = read(fd, buffer, IN_BUFFER_SIZE)) < 0) {
            if (errno != EAGAIN)
                mterror(INOTIFY_TAG, "Error reading inotify: %s", strerror(errno));

            break;
        }

        buffer[count - 1] = '\0';

        for (i = 0; i < count; i += (ssize_t)(sizeof(struct inotify_event) + event->len)) {
            char cmd[100];

            event = (struct inotify_event*)&buffer[i];
            mtdebug2(INOTIFY_TAG,"inotify: i='%d', name='%s', mask='%u', wd='%d'", i, event->name, event->mask, event->wd);
            unsigned int j;
            for (j = 0; j < n_files_to_watch; j++) {
                if (event->wd == files[j].watcher) {
                    if (check_if_ignore(cJSON_GetObjectItemCaseSensitive(root, "excluded_files"), event->name) ||
                        !check_if_ignore(files[j].files, event->name)) {
                        ignore = true;
                        continue;
                    }

                    if (event->mask & IN_DELETE) {
                        strcpy(cmd, "delete1 ");
                        strcat(cmd, files[j].name);
                        strcat(cmd, event->name);
                    }
                    else if (event->mask & files[j].flags) {
                        strcpy(cmd, "update1 ");
                        strcat(cmd, files[j].name);
                        strcat(cmd, event->name);

                        inotify_push_request(cmd);
                        memset(cmd,0,sizeof(cmd));

                        os_md5 md5_file;
                        if (OS_MD5_File(files[j].path, md5_file, OS_BINARY) < 0) {
                            mterror(INOTIFY_TAG, "Could not compute MD5 of file %s", files[j].path);
                            ignore = true;
                            continue;
                        }

                        if (sprintf(cmd, "updatefile %s %ld %s", md5_file, mod_time(files[j].path), files[j].path) >= 100) {
                            mterror(INOTIFY_TAG, "String overflow sending file updates to database in file %s", files[j].path);
                            ignore = true;
                            continue;
                        }

                    } else if (event->mask & IN_Q_OVERFLOW) {
                        mtinfo(INOTIFY_TAG, "Inotify event queue overflowed");
                        ignore = true;
                        continue;
                    } else {
                        mtinfo(INOTIFY_TAG, "Unknown inotify event");
                        ignore = true;
                        continue;
                    }
                }
            }

            if (ignore) {
                ignore = false;
                continue;
            }
            inotify_push_request(cmd);
            memset(cmd,0,sizeof(cmd));
        }
    }
    return 0;
}

char * inotify_pop() {
    char * cmd;
    int error;

    error = pthread_mutex_lock(&mutex_queue);
    if (error) mterror_exit(INOTIFY_TAG, "Error locking queue at inotify_pop: %s", strerror(errno));

    while (queue_empty(queue)) {
        error = pthread_cond_wait(&cond_pending, &mutex_queue);
        if (errno) mterror_exit(INOTIFY_TAG, "Error waiting for condition at inotify_pop: %s", strerror(errno));
    }

    cmd = queue_pop(queue);

    if (!OSHash_Delete(ptable, cmd)) mterror(INOTIFY_TAG, "Could not delete key %s from table", cmd);

    error = pthread_mutex_unlock(&mutex_queue);
    if (error) mterror_exit(INOTIFY_TAG, "Error unlocking queue at inotify_pop: %s", strerror(errno));

    mtdebug2(INOTIFY_TAG, "Taking %s from table", cmd);
    return cmd;
}

void* daemon_inotify(void * args) {
    char * node_type = args;
    mtinfo(INOTIFY_TAG,"Preparing client socket");
    /* prepare socket to send data to cluster database */
    struct sockaddr_un addr;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path)-1);

    // Create hash table
    if (ptable = OSHash_Create(), !ptable)
        mterror_exit(INOTIFY_TAG, "At daemon_inotify(): OSHash_Create()");

    // Create queue
    if (queue = queue_init(16384), !queue)
        mterror_exit(INOTIFY_TAG, "At daemon_inotify(): queue_init()");

    cJSON * root = read_cluster_json_file();

    inotify_watch_file * files;
    files = malloc(30*sizeof(inotify_watch_file));
    unsigned int i, n_files_to_watch = get_files_to_watch(node_type, &files, root);

    mtdebug1(INOTIFY_TAG, "Preparing inotify watchers");
    /* prepare inotify */
    int fd = inotify_init ();
    for (i = 0; i < n_files_to_watch; i++) {
        files[i].files = files[i].files == NULL ? cJSON_Parse("[\"all\"]") : files[i].files;
        mtdebug1(INOTIFY_TAG, "Monitoring %s files from directory %s", cJSON_Print(files[i].files), files[i].name);
        files[i].watcher = inotify_add_watch(fd, files[i].path, files[i].flags);
        if (files[i].watcher < 0)
            mterror(INOTIFY_TAG, "Error setting watcher for file %s: %s",
                files[i].path, strerror(errno));
    }

    pthread_t inotify_reader_thread;
    inotify_reader_arguments thread_args;
    thread_args.fd = fd;
    thread_args.n_files_to_watch = n_files_to_watch;
    thread_args.files = files;
    thread_args.root = root;
    pthread_create(&inotify_reader_thread, NULL, inotify_reader, &thread_args);


    int db_socket, rc;
    while(1) {
        char * cmd = inotify_pop();

        if ((db_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
            mterror_exit(INOTIFY_TAG, "Error initializing client socket: %s", strerror(errno));
        }

        if (connect(db_socket, (struct sockaddr*)&addr , sizeof(addr)) < 0) {
            mterror_exit(INOTIFY_TAG, "Error connecting to socket: %s", strerror(errno));
        }

        if ((rc = write(db_socket, cmd, strlen(cmd))) < 0) {
            mterror_exit(INOTIFY_TAG, "Error writing update in DB socket: %s", strerror(errno));
        }

        char data[10000];
        if (recv(db_socket, data, sizeof(data),0) < 0)
            mterror(INOTIFY_TAG, "Error receving data from DB socket: %s", strerror(errno));

        if (shutdown(db_socket, SHUT_RDWR) < 0) {
            mterror(INOTIFY_TAG, "Error in shutdown: %s", strerror(errno));
        }
        if (close(db_socket) < 0) {
            mterror(INOTIFY_TAG, "Error closing client socket:  %s", strerror(errno));
        }
        memset(data,0,sizeof(data));
        free(cmd);
    }

    mtdebug1(INOTIFY_TAG,"Removing watchers");
    /*removing the directory from the watch list.*/
    for (i = 0; i < n_files_to_watch; i++) inotify_rm_watch(fd, files[i].watcher);
    free(files);
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
    char * node_type = ""; // default value
    while (c = getopt(argc, argv, "fdVht:"), c != -1) {
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
            case 't':
                if (!optarg) {
                    mterror_exit(MAIN_TAG, "-t needs an argument");
                }
                node_type = optarg;
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
    pthread_create(&inotify_thread, NULL, daemon_inotify, node_type);

    pthread_join(socket_thread, NULL);
    pthread_join(inotify_thread, NULL);

    return 0;
}
