/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <math.h>
#include "shared.h"
#include "syscheck.h"
#include "syscheck_op.h"
#include "wazuh_modules/wmodules.h"
#include "dirtree_op.h"
#include "integrity_op.h"

// delete this functions
// ==================================
static void print_file_info(struct stat path_stat);
int print_hash_tables();
int generate_dirtree(OSDirTree * tree);
static int strcompare(const void *s1, const void *s2);
void print_tree(OSTreeNode * tree);
// ==================================

// Global variables
static int __base_line = 0;
pthread_mutex_t __lastcheck_mutex = PTHREAD_MUTEX_INITIALIZER;

int fim_scan() {
    OSDirTree * fim_tree;
    int position = 0;
    char * (*checksum_function)(void*) = fim_get_checksum;

    minfo(FIM_FREQUENCY_STARTED);

    //if (fim_tree = OSDirTree_Create(), !fim_tree) {
    //    merror("Can't create dir tree structure");
    //    return OS_INVALID;
    //}

    while (syscheck.dir[position] != NULL) {
        fim_directory(syscheck.dir[position], position, NULL, 0);
        position++;
    }

    __base_line = 1;
    //generate_dirtree(fim_tree);
    //print_tree(fim_tree->first_node);

    print_hash_tables();
    syscheck.integrity_data = initialize_integrity (syscheck.fim_entry->rows, checksum_function);
    generate_integrity(syscheck.fim_entry, syscheck.integrity_data);
    print_integrity(syscheck.integrity_data);
    minfo(FIM_FREQUENCY_ENDED);

    return 0;
}

int fim_scheduled_scan() {
    int position = 0;

    while (syscheck.dir[position] != NULL) {
        if ( !(syscheck.opts[position] & WHODATA_ACTIVE) &&
             !(syscheck.opts[position] & REALTIME_ACTIVE) ) {
            fim_directory(syscheck.dir[position], position, NULL, 0);
        }
        position++;
    }
    print_hash_tables();
    check_deleted_files();
    return 0;
}


int fim_directory (char * path, int dir_position, whodata_evt * w_evt, int max_depth) {
    DIR *dp;
    struct dirent *entry;
    char *f_name;
    char *s_name;
    char linked_read_file[PATH_MAX + 1] = {'\0'};
    int options;
    int position;
    int check_depth;
    int mode = 0;
    size_t path_size;
    short is_nfs;

    //minfo("~~ =====================================");
    //minfo("~~ Directory: '%s'", path);

    if (!path) {
        merror(NULL_ERROR);
        return OS_INVALID;
    }

    // If the directory have another configuration will come back
    // TODO: check different configuration with parent/siblings directories
    if (position = fim_configuration_directory(path), position != dir_position) {
        return 0;
    }
    options = syscheck.opts[dir_position];

    if (check_depth = fim_check_depth(path, dir_position), check_depth < 0) {
        minfo("Wrong parent directory of: %s", path);
        return 0;
    }

    if(max_depth >= syscheck.max_depth || max_depth >= syscheck.recursion_level[dir_position]) {
        merror(FIM_MAX_RECURSION_LEVEL, path);
        return 0;
    }

    // Open the directory given
    dp = opendir(path);

    if (!dp) {
        merror(FIM_PATH_NOT_OPEN, path, strerror(errno));
        return (-1);
    }

    // Should we check for NFS?
    if (syscheck.skip_nfs) {
        is_nfs = IsNFS(path);
        if (is_nfs != 0) {
            // Error will be -1, and 1 means skipped
            closedir(dp);
            return (is_nfs);
        }
    }

    if (options & REALTIME_ACTIVE) {
        mode = FIM_REALTIME;
    } else if (options & WHODATA_ACTIVE) {
        mode = FIM_WHODATA;
    } else {
        mode = FIM_SCHEDULED;
    }

    // Check for real time flag
    if (options & REALTIME_ACTIVE || options & WHODATA_ACTIVE) {
#if defined INOTIFY_ENABLED || defined WIN32
        realtime_adddir(path, options & WHODATA_ACTIVE);
#else
        mwarn(FIM_WARN_REALTIME_UNSUPPORTED, path);
#endif
    }

    os_calloc(PATH_MAX + 2, sizeof(char), f_name);
    while ((entry = readdir(dp)) != NULL) {
        *linked_read_file = '\0';

        // Ignore . and ..
        if ((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        strncpy(f_name, path, PATH_MAX);
        path_size = strlen(path);
        s_name = f_name + path_size;

        // Check if the file name is already null terminated
        if (*(s_name - 1) != PATH_SEP) {
            *s_name++ = PATH_SEP;
        }
        *(s_name) = '\0';
        strncpy(s_name, entry->d_name, PATH_MAX - path_size - 2);
#ifdef WIN32
        str_lowercase(f_name);
#endif
        // Process the event related to f_name
        if(fim_process_event(f_name, mode, w_evt) == -1) {
            os_free(f_name);
            closedir(dp);
            return -1;
        }
    }

    os_free(f_name);
    closedir(dp);
    return (0);
}


int fim_check_file (char * file_name, int dir_position, int mode, whodata_evt * w_evt) {
    cJSON * json_alert = NULL;
    fim_entry_data * entry_data;
    fim_entry_data * saved_data;
    struct stat file_stat;
    //char * checksum;
    char * json_formated;
    int options;
    int position;
    int check_depth;

    // If the directory is in another configuration will come back
    if (position = fim_configuration_directory(file_name), position != dir_position) {
        return 0;
    }
    options = syscheck.opts[dir_position];

    if (check_depth = fim_check_depth(file_name, dir_position), check_depth < 0) {
        merror("Wrong parent directory of: %s", file_name);
        return 0;
    }

    if (w_stat(file_name, &file_stat) < 0) {
        fim_delete (file_name, w_evt);
        return 0;
    }
    //minfo("~~ -------------------------------------");
    // minfo("~~ File(%ld) '%s' -%d-%d-", file_stat.st_size, file_name, syscheck.n_entries, syscheck.n_inodes);
    // print_file_info(file_stat, mode);

    //File attributes
    if (entry_data = fim_get_data(file_name, file_stat, mode, options), !entry_data) {
        merror("Couldn't get attributes for file: '%s'", file_name);
        return OS_INVALID;
    }

    // Form the checksum
    //checksum = fim_get_checksum (entry_data);

    //if (!checksum) {
    //    merror("File '%s' skipped", file_name);
    //    return OS_INVALID;
    //}

    if (saved_data = (fim_entry_data *) OSHash_Get_ex(syscheck.fim_entry, file_name), !saved_data) {
        // New entry. Insert into hash table
        if (fim_insert (file_name, entry_data) == -1) {
            free_entry_data(entry_data);
            os_free(entry_data);
            return OS_INVALID;
        }

        if (__base_line) {
            json_alert = fim_json_alert_add (file_name, entry_data, w_evt);
        }


    } else {
        // Checking for changes
        saved_data->scanned = 1;
        if (json_alert = fim_json_alert_changes (file_name, saved_data, entry_data, w_evt), json_alert) {
            if (fim_update (file_name, entry_data) == -1) {
                return OS_INVALID;
            }
        } else {
            free_entry_data(entry_data);
            os_free(entry_data);
        }
    }

    if (json_alert) {
        // minfo("File '%s' checksum: '%s'", file_name, checksum);
        json_formated = cJSON_PrintUnformatted(json_alert);
        minfo("JSON output:");
        minfo("%s", json_formated);
        os_free(json_formated);
        cJSON_Delete(json_alert);
    }
    return 0;
}

// Returns the position of the path into directories array
int fim_configuration_directory(char * path) {
    char *find_path;
    char *sep;
    int position = -1;
    int it;

    find_path = strdup(path);
    if (find_path[strlen(find_path) - 1] != '/') {
        wm_strcat(&find_path, "/", '\0');
    }

    while (sep = strrchr(find_path, '/'), sep) {
        *(++sep) = '\0';

        for (it = 0; syscheck.dir[it]; it++) {
            if (!strcmp(syscheck.dir[it], find_path)) {
                position = it;
                os_free(find_path);

                return position;
            }
        }
        *(--sep) = '\0';
    }

    os_free(find_path);
    return position;
}


// Evaluates the depth of the directory or file and checks if it exceeds the configured max_depth value
int fim_check_depth(char * path, int dir_position) {
    char * pos;
    int depth = 0;
    unsigned int parent_path_size;

    parent_path_size = strlen(syscheck.dir[dir_position]) - 1;   // We need to remove the last '/' for comparision

    if (parent_path_size > strlen(path)) {
        merror("Parent directory < path: %s < %s", syscheck.dir[dir_position], path);
        return -1;
    }

    pos = path + parent_path_size - 1;
    // minfo("Busco prof de %s", path);
    // minfo("Conf dir: %s", syscheck.dir[dir_position]);
    // minfo("find: %s", pos);

    while (pos) {
        // minfo("find: %s", pos);
        if (pos = strchr(pos, '/'), pos) {
            depth++;
        } else {
            break;
        }
        pos++;
    }
    // minfo("depth: %d", depth);

    return depth;
}


// Get data from file
fim_entry_data * fim_get_data (const char * file_name, struct stat file_stat, int mode, int options) {
    fim_entry_data * data = NULL;
    int size_name;
    int size_group;

    os_calloc(1, sizeof(fim_entry_data), data);

    size_name = sizeof(get_user(file_name, file_stat.st_uid, NULL)) + 1;
    size_group = sizeof(get_group(file_stat.st_gid)) + 1;
    os_calloc(size_name, sizeof(char), data->user_name);
    os_calloc(size_group, sizeof(char), data->group_name);

    *(data)->hash_md5 = '\0';
    *(data)->hash_sha1 = '\0';
    *(data)->hash_sha256 = '\0';

    data->size = file_stat.st_size;
    data->perm = file_stat.st_mode;
    data->uid = file_stat.st_uid;
    data->gid = file_stat.st_gid;
    data->mtime = file_stat.st_mtime;
    data->inode = file_stat.st_ino;

    // The file exists and we don't have to delete it from the hash tables
    data->scanned = 1;

    snprintf(data->user_name, size_name, "%s", get_user(file_name, file_stat.st_uid, NULL));
    snprintf(data->group_name, size_group, "%s", get_group(file_stat.st_gid));

    // We won't calculate hash for symbolic links, empty or large files
    if ((file_stat.st_mode & S_IFMT) == FIM_REGULAR &&
            file_stat.st_size > 0 &&
            (size_t)file_stat.st_size < syscheck.file_max_size) {
        if (OS_MD5_SHA1_SHA256_File(file_name,
                                    syscheck.prefilter_cmd,
                                    data->hash_md5,
                                    data->hash_sha1,
                                    data->hash_sha256,
                                    OS_BINARY,
                                    syscheck.file_max_size) < 0) {
            merror("Couldn't generate hashes: '%s'", file_name);
            free_entry_data(data);
            return NULL;
        }
    }

    data->mode = mode;
    data->options = options;

    return data;
}

// Returns checksum string
char * fim_get_checksum (fim_entry_data * data) {
    char *checksum = NULL;
    int size;

    os_calloc(OS_SIZE_128, sizeof(char), checksum);

    size = snprintf(checksum,
            OS_SIZE_128,
            "%d:%d:%d:%d:%s:%s:%d:%lu:%s:%s:%s",
            data->size,
            data->perm,
            data->uid,
            data->gid,
            data->user_name,
            data->group_name,
            data->mtime,
            data->inode,
            data->hash_md5,
            data->hash_sha1,
            data->hash_sha256);

    if (size < 0) {
        merror("Wrong size, can't get checksum");
        os_free(checksum);
    } else if (size - 1 >= OS_SIZE_128) {
        // Needs more space
        os_realloc(checksum, (size + 1) * sizeof(char), checksum);
        snprintf(checksum,
                size + 1,
                "%d:%d:%d:%d:%s:%s:%d:%lu:%s:%s:%s",
                data->size,
                data->perm,
                data->uid,
                data->gid,
                data->user_name,
                data->group_name,
                data->mtime,
                data->inode,
                data->hash_md5,
                data->hash_sha1,
                data->hash_sha256);
    }

    return checksum;
}


// Inserts a file in the syscheck hash table structure (inodes and paths)
int fim_insert (char * file, fim_entry_data * data) {
    char * inode_key;
    int result;

    if (result = OSHash_Add_fim(syscheck.fim_entry, file, data, 0), result == 0) {
        merror("Unable to add file to db: '%s'", file);
        return (-1);
    } else if (result == 1) {
        minfo("Duplicated path: '%s'", file);
        return (-1);
    }
    syscheck.n_entries++;


#ifndef WIN32
    fim_inode_data * inode_data;

    // Function OSHash_Add_ex doesn't alloc memory for the data of the hash table
    os_calloc(OS_SIZE_16, sizeof(char), inode_key);
    snprintf(inode_key, OS_SIZE_16, "%ld", data->inode);

    if (inode_data = OSHash_Get_ex(syscheck.fim_inode, inode_key), !inode_data) {
        os_calloc(1, sizeof(fim_inode_data), inode_data);

        inode_data->paths = os_AddStrArray(file, inode_data->paths);
        inode_data->items = 1;

        if (OSHash_Add_ex(syscheck.fim_inode, inode_key, inode_data) != 2) {
            merror("Unable to add inode to db: '%s' => '%s'", inode_key, file);
            os_free(inode_key);
            return (-1);
        }

        syscheck.n_inodes++;
    } else {
        // TODO:
        char **new_paths, **to_delete;
        struct stat inode_stat;
        int i = 0;

        if (!os_IsStrOnArray(file, inode_data->paths)) {
            inode_data->paths = os_AddStrArray(file, inode_data->paths);
            inode_data->items++;
            syscheck.n_inodes++;
        }

        os_calloc(inode_data->items, sizeof(char*), new_paths);
        os_calloc(inode_data->items, sizeof(char*), to_delete);
        for(i = 0; i < inode_data->items; i++) {
            if(stat(inode_data->paths[i], &inode_stat) < 0) {
                to_delete = os_AddStrArray(inode_data->paths[i], to_delete);
            } else {
                new_paths = os_AddStrArray(inode_data->paths[i], new_paths);
            }
        }

        i = 0;
        while(to_delete[i]) {
            fim_delete(to_delete[i++], NULL);
        }

        free_strarray(to_delete);
        free_strarray(inode_data->paths);
        inode_data->paths = new_paths;

    }
#endif

    os_free(inode_key);
    return 0;
}

// TODO: Migrate dir_position and max_depth inside the function
int fim_process_event(char * file, int mode, whodata_evt *w_evt) {
    struct stat file_stat;
    int dir_position = 0;
    int depth = 0;

    dir_position = fim_configuration_directory(file);
    depth = fim_check_depth(file, dir_position);

    if(w_stat(file, &file_stat)){
        // Not existing file
        fim_delete (file, w_evt);
        return 0;
    }
    switch(file_stat.st_mode & S_IFMT) {
        case FIM_REGULAR:
            // Regular file
            if (fim_check_file(file, dir_position, mode, w_evt) < 0) {
                merror("Skiping file: '%s'", file);
            }
            break;

        case FIM_DIRECTORY:
            // Directory path
            fim_directory(file, dir_position, w_evt, depth + 1);
            break;
#ifndef WIN32
        case FIM_LINK:
            // Symbolic links add link and follow if it is configured
            // TODO: implement symbolic links
            break;
#endif
        default:
            // Invalid filetype
            mdebug2("Invalid filetype: '%s'", file);
            return -1;
    }
    return 0;
}


// Update an entry in the syscheck hash table structure (inodes and paths)
int fim_update (char * file, fim_entry_data * data) {
    char * inode_key;

    os_calloc(OS_SIZE_16, sizeof(char), inode_key);
    snprintf(inode_key, OS_SIZE_16, "%ld", data->inode);

    if (!file || strcmp(file, "") == 0 || !inode_key || strcmp(inode_key, "") == 0) {
        merror("Can't update entry invalid file or inode");
    }

    if (OSHash_Update(syscheck.fim_entry, file, data) == 0) {
        merror("Unable to update file to db, key not found: '%s'", file);
        os_free(inode_key);
        return (-1);
    }
    os_free(inode_key);
    return 0;
}


// Deletes a path from the syscheck hash table structure and sends a deletion event
int fim_delete (char * file_name, whodata_evt * w_evt) {
    fim_entry_data * saved_data;
    char * inode;
    char * json_formated;
    char * file_to_delete;
    cJSON * json_alert = NULL;

    if (saved_data = OSHash_Get(syscheck.fim_entry, file_name), saved_data) {
#ifndef WIN32
        os_calloc(OS_SIZE_16, sizeof(char), inode);
        snprintf(inode, OS_SIZE_16, "%ld", saved_data->inode);
        os_strdup(file_name, file_to_delete);
        delete_inode_item(inode, file_to_delete);
        // TODO: Send alert to manager (send_msg())
        if(json_alert = fim_json_alert_delete(file_to_delete, saved_data, w_evt), json_alert) {
        // minfo("File '%s' checksum: '%s'", file_name, checksum);
            json_formated = cJSON_PrintUnformatted(json_alert);
            minfo("JSON output:");
            minfo("%s", json_formated);
            os_free(json_formated);
            cJSON_Delete(json_alert);
        }
#endif
        OSHash_Delete(syscheck.fim_entry, file_to_delete);
        free_entry_data(saved_data);
        os_free(saved_data);
        os_free(inode);
        os_free(file_to_delete);
    }

    return 0;
}

// Deletes a path from the syscheck hash table structure and sends a deletion event on scheduled scans
int check_deleted_files() {
    OSHashNode * hash_node;
    fim_entry_data * fim_entry_data;
    unsigned int * inode_it;
    char * key;

    os_calloc(1, sizeof(unsigned int), inode_it);

    hash_node = OSHash_Begin(syscheck.fim_entry, inode_it);
    while(hash_node) {
        fim_entry_data = hash_node->data;

        // File doesn't exist so we have to delete it from the
        // hash tables and send a deletion event.
        if(!fim_entry_data->scanned && fim_entry_data->mode == FIM_SCHEDULED) {
            minfo("~~~~ file '%s' has been deleted.", hash_node->key);
            os_strdup(hash_node->key, key);
            // We must save the next node before deteling the current one
            hash_node = OSHash_Next(syscheck.fim_entry, inode_it, hash_node);
            fim_delete(key, NULL);
            os_free(key);
            continue;
        }
        // File still exists. We only need to reset the scanned flag.
        else {
            fim_entry_data->scanned = 0;
        }

        hash_node = OSHash_Next(syscheck.fim_entry, inode_it, hash_node);
    }
    os_free(inode_it);
    return 0;
}

void delete_inode_item(char *inode_key, char *file_name) {
    fim_inode_data *inode_data;
    char **new_paths;
    int i = 0;

    if (inode_data = OSHash_Get(syscheck.fim_inode, inode_key), inode_data) {
        // If it's the last path we can delete safely the hash node
        if(inode_data->items == 1) {
            if(inode_data = OSHash_Delete(syscheck.fim_inode, inode_key), inode_data) {
                merror("~~~ deleted '%s' from hash table", inode_key);
                free_inode_data(inode_data);
                os_free(inode_data);
            }
        }
        // We must delete only file_name from paths
        else {
            os_calloc(inode_data->items-1, sizeof(char*), new_paths);
            for(i = 0; i < inode_data->items; i++) {
                if(strcmp(inode_data->paths[i], file_name)) {
                    new_paths = os_AddStrArray(inode_data->paths[i], new_paths);
                }
            }

            free_strarray(inode_data->paths);
            inode_data->paths = new_paths;
            inode_data->items--;
        }
    }
}


cJSON * fim_json_alert_add (char * file_name, fim_entry_data * data, whodata_evt * w_evt) {
    cJSON * response = NULL;
    cJSON * fim_report = NULL;
    cJSON * fim_attributes = NULL;
    cJSON * fim_audit = NULL;

    fim_report = cJSON_CreateObject();
    cJSON_AddStringToObject(fim_report, "path", file_name);
    cJSON_AddNumberToObject(fim_report, "options", data->options);
    cJSON_AddStringToObject(fim_report, "alert", TYPE_ALERT_ADDED);

    fim_attributes = cJSON_CreateObject();
    cJSON_AddNumberToObject(fim_attributes, "new_size", data->size);
    cJSON_AddNumberToObject(fim_attributes, "new_perm", data->perm);
    cJSON_AddNumberToObject(fim_attributes, "new_uid", data->uid);
    cJSON_AddNumberToObject(fim_attributes, "new_gid", data->gid);
    cJSON_AddStringToObject(fim_attributes, "new_user_name", data->user_name);
    cJSON_AddNumberToObject(fim_attributes, "new_mtime", data->mtime);
    cJSON_AddNumberToObject(fim_attributes, "new_inode", data->inode);
    cJSON_AddStringToObject(fim_attributes, "new_hash_md5", data->hash_md5);
    cJSON_AddStringToObject(fim_attributes, "new_hash_sha1", data->hash_sha1);
    cJSON_AddStringToObject(fim_attributes, "new_hash_sha256", data->hash_sha256);
    if(w_evt) {
        fim_audit = cJSON_CreateObject();
        cJSON_AddStringToObject(fim_audit, "user_id", w_evt->user_id);
        cJSON_AddStringToObject(fim_audit, "user_name", w_evt->user_name);
        cJSON_AddStringToObject(fim_audit, "group_id", w_evt->group_id);
        cJSON_AddStringToObject(fim_audit, "group_name", w_evt->group_name);
        cJSON_AddStringToObject(fim_audit, "process_name", w_evt->process_name);
        cJSON_AddStringToObject(fim_audit, "path", w_evt->path);
        cJSON_AddStringToObject(fim_audit, "audit_uid", w_evt->audit_uid);
        cJSON_AddStringToObject(fim_audit, "audit_name", w_evt->audit_name);
        cJSON_AddStringToObject(fim_audit, "effective_uid", w_evt->effective_uid);
        cJSON_AddStringToObject(fim_audit, "effective_name", w_evt->effective_name);
        cJSON_AddStringToObject(fim_audit, "inode", w_evt->inode);
        cJSON_AddNumberToObject(fim_audit, "ppid", w_evt->ppid);
#ifndef WIN32
        cJSON_AddNumberToObject(fim_audit, "process_id", w_evt->process_id);
#else
        cJSON_AddNumberToObject(fim_audit, "process_id", w_evt->process_id);
        cJSON_AddNumberToObject(fim_audit, "mask", w_evt->mask);
#endif
    }

    response = cJSON_CreateObject();
    cJSON_AddItemToObject(response, "data", fim_report);
    cJSON_AddItemToObject(response, "attributes", fim_attributes);
    if(w_evt) {
        cJSON_AddItemToObject(response, "audit", fim_audit);
    }
    return response;
}

cJSON * fim_json_alert_delete (char * file_name, fim_entry_data * data, whodata_evt * w_evt) {
    cJSON * response = NULL;
    cJSON * fim_report = NULL;
    cJSON * fim_attributes = NULL;
    cJSON * fim_audit = NULL;

    fim_report = cJSON_CreateObject();
    cJSON_AddStringToObject(fim_report, "path", file_name);
    cJSON_AddNumberToObject(fim_report, "options", data->options);
    cJSON_AddStringToObject(fim_report, "alert", TYPE_ALERT_DELETED);

    fim_attributes = cJSON_CreateObject();
    cJSON_AddNumberToObject(fim_attributes, "last_size", data->size);
    cJSON_AddNumberToObject(fim_attributes, "last_perm", data->perm);
    cJSON_AddNumberToObject(fim_attributes, "last_uid", data->uid);
    cJSON_AddNumberToObject(fim_attributes, "last_gid", data->gid);
    cJSON_AddStringToObject(fim_attributes, "last_user_name", data->user_name);
    cJSON_AddNumberToObject(fim_attributes, "last_mtime", data->mtime);
    cJSON_AddNumberToObject(fim_attributes, "last_inode", data->inode);
    cJSON_AddStringToObject(fim_attributes, "last_hash_md5", data->hash_md5);
    cJSON_AddStringToObject(fim_attributes, "last_hash_sha1", data->hash_sha1);
    cJSON_AddStringToObject(fim_attributes, "last_hash_sha256", data->hash_sha256);
    if(w_evt) {
        fim_audit = cJSON_CreateObject();
        cJSON_AddStringToObject(fim_audit, "user_id", w_evt->user_id);
        cJSON_AddStringToObject(fim_audit, "user_name", w_evt->user_name);
        cJSON_AddStringToObject(fim_audit, "group_id", w_evt->group_id);
        cJSON_AddStringToObject(fim_audit, "group_name", w_evt->group_name);
        cJSON_AddStringToObject(fim_audit, "process_name", w_evt->process_name);
        cJSON_AddStringToObject(fim_audit, "path", w_evt->path);
        cJSON_AddStringToObject(fim_audit, "audit_uid", w_evt->audit_uid);
        cJSON_AddStringToObject(fim_audit, "audit_name", w_evt->audit_name);
        cJSON_AddStringToObject(fim_audit, "effective_uid", w_evt->effective_uid);
        cJSON_AddStringToObject(fim_audit, "effective_name", w_evt->effective_name);
        cJSON_AddStringToObject(fim_audit, "inode", w_evt->inode);
        cJSON_AddNumberToObject(fim_audit, "ppid", w_evt->ppid);
#ifndef WIN32
        cJSON_AddNumberToObject(fim_audit, "process_id", w_evt->process_id);
#else
        cJSON_AddNumberToObject(fim_audit, "process_id", w_evt->process_id);
        cJSON_AddNumberToObject(fim_audit, "mask", w_evt->mask);
#endif
    }

    response = cJSON_CreateObject();
    cJSON_AddItemToObject(response, "data", fim_report);
    cJSON_AddItemToObject(response, "attributes", fim_attributes);
    if(w_evt) {
        cJSON_AddItemToObject(response, "audit", fim_audit);
    }

    return response;
}


cJSON * fim_json_alert_changes (char * file_name, fim_entry_data * old_data, fim_entry_data * new_data, whodata_evt * w_evt) {
    cJSON * response = NULL;
    cJSON * fim_report = NULL;
    cJSON * fim_attributes = NULL;
    cJSON * fim_audit = NULL;
    int report_alert = 0;

    if ( (old_data->size != new_data->size) && (old_data->options & CHECK_SIZE) ) {
        report_alert = 1;
    }

    if ( (old_data->perm != new_data->perm) && (old_data->options & CHECK_PERM) ) {
        report_alert = 1;
    }

    if ( (old_data->uid != new_data->uid) && (old_data->options & CHECK_OWNER) ) {
        report_alert = 1;
    }

    if ( (old_data->gid != new_data->gid) && (old_data->options & CHECK_GROUP) ) {
        report_alert = 1;
    }

    if ( (old_data->mtime != new_data->mtime) && (old_data->options & CHECK_MTIME) ) {
        report_alert = 1;
    }

    if ( (old_data->inode != new_data->inode) && (old_data->options & CHECK_INODE) ) {
        report_alert = 1;
    }

    if ( (strcmp(old_data->hash_md5, new_data->hash_md5) != 0) &&
            (old_data->options & CHECK_MD5SUM) ) {
        report_alert = 1;
    }

    if ( (strcmp(old_data->hash_sha1, new_data->hash_sha1) != 0) &&
            (old_data->options & CHECK_SHA1SUM) ) {
        report_alert = 1;
    }

    if ( (strcmp(old_data->hash_sha256, new_data->hash_sha256) != 0) &&
            (old_data->options & CHECK_SHA256SUM) ) {
        report_alert = 1;
    }

    if (report_alert) {
        fim_report = cJSON_CreateObject();
        cJSON_AddStringToObject(fim_report, "path", file_name);
        cJSON_AddNumberToObject(fim_report, "options", old_data->options);
        cJSON_AddStringToObject(fim_report, "alert", TYPE_ALERT_MODIFIED);

        fim_attributes = cJSON_CreateObject();
        cJSON_AddNumberToObject(fim_attributes, "old_size", old_data->size);
        cJSON_AddNumberToObject(fim_attributes, "new_size", new_data->size);
        cJSON_AddNumberToObject(fim_attributes, "old_perm", old_data->perm);
        cJSON_AddNumberToObject(fim_attributes, "new_perm", new_data->perm);
        cJSON_AddNumberToObject(fim_attributes, "old_uid", old_data->uid);
        cJSON_AddNumberToObject(fim_attributes, "new_uid", new_data->uid);
        cJSON_AddNumberToObject(fim_attributes, "old_gid", old_data->gid);
        cJSON_AddNumberToObject(fim_attributes, "new_gid", new_data->gid);
        cJSON_AddStringToObject(fim_attributes, "old_user_name", old_data->user_name);
        cJSON_AddStringToObject(fim_attributes, "new_user_name", new_data->user_name);
        cJSON_AddNumberToObject(fim_attributes, "old_mtime", old_data->mtime);
        cJSON_AddNumberToObject(fim_attributes, "new_mtime", new_data->mtime);
        cJSON_AddNumberToObject(fim_attributes, "old_inode", old_data->inode);
        cJSON_AddNumberToObject(fim_attributes, "new_inode", new_data->inode);
        cJSON_AddStringToObject(fim_attributes, "old_hash_md5", old_data->hash_md5);
        cJSON_AddStringToObject(fim_attributes, "new_hash_md5", new_data->hash_md5);
        cJSON_AddStringToObject(fim_attributes, "old_hash_sha1", old_data->hash_sha1);
        cJSON_AddStringToObject(fim_attributes, "new_hash_sha1", new_data->hash_sha1);
        cJSON_AddStringToObject(fim_attributes, "old_hash_sha256", old_data->hash_sha256);
        cJSON_AddStringToObject(fim_attributes, "new_hash_sha256", new_data->hash_sha256);
        if(w_evt) {
            fim_audit = cJSON_CreateObject();
            cJSON_AddStringToObject(fim_audit, "user_id", w_evt->user_id);
            cJSON_AddStringToObject(fim_audit, "user_name", w_evt->user_name);
            cJSON_AddStringToObject(fim_audit, "group_id", w_evt->group_id);
            cJSON_AddStringToObject(fim_audit, "group_name", w_evt->group_name);
            cJSON_AddStringToObject(fim_audit, "process_name", w_evt->process_name);
            cJSON_AddStringToObject(fim_audit, "path", w_evt->path);
            cJSON_AddStringToObject(fim_audit, "audit_uid", w_evt->audit_uid);
            cJSON_AddStringToObject(fim_audit, "audit_name", w_evt->audit_name);
            cJSON_AddStringToObject(fim_audit, "effective_uid", w_evt->effective_uid);
            cJSON_AddStringToObject(fim_audit, "effective_name", w_evt->effective_name);
            cJSON_AddStringToObject(fim_audit, "inode", w_evt->inode);
            cJSON_AddNumberToObject(fim_audit, "ppid", w_evt->ppid);
#ifndef WIN32
            cJSON_AddNumberToObject(fim_audit, "process_id", w_evt->process_id);
#else
            cJSON_AddNumberToObject(fim_audit, "process_id", w_evt->process_id);
            cJSON_AddNumberToObject(fim_audit, "mask", w_evt->mask);
#endif
    }

        response = cJSON_CreateObject();
        cJSON_AddItemToObject(response, "data", fim_report);
        cJSON_AddItemToObject(response, "attributes", fim_attributes);
        if(w_evt) {
            cJSON_AddItemToObject(response, "audit", fim_audit);
        }
    }

    return response;
}


void free_entry_data(fim_entry_data * data) {
    os_free(data->user_name);
    os_free(data->group_name);
}


void free_inode_data(fim_inode_data * data) {
    int i;

    for (i = 0; i < data->items; i++) {
        os_free(data->paths[i]);
    }
    os_free(data->paths);
}


/* ================================================================================================ */
/* ================================================================================================ */
/* ================================================================================================ */
/* ================================================================================================ */



static void print_file_info(struct stat path_stat) {
    //switch(path_stat.st_mode & S_IFMT) {
    //case S_IFBLK:
    //    minfo("Block special.");
    //    break;
    //case S_IFCHR:
    //    minfo("Character special.");
    //    break;
    //case S_IFIFO:
    //    minfo("FIFO special.");
    //    break;
    //case S_IFREG:
    //    minfo("Regular.");
    //    break;
    //case S_IFDIR:
    //    minfo("Directory.");
    //    break;
    //case S_IFLNK:
    //    minfo("Symbolic link.");
    //    break;
    //case S_IFSOCK:
    //    minfo("Socket.");
    //    break;
    //default:
    //    minfo("I dont know");
    //}

    minfo("Stat st_dev '%d'", (int)path_stat.st_dev);     /* ID of device containing file */
    minfo("Stat st_ino '%ld'", (long int)path_stat.st_ino);     /* inode number */
    minfo("Stat st_mode '%d'", (int)path_stat.st_mode);    /* protection */
    minfo("Stat st_nlink '%d'", (int)path_stat.st_nlink);   /* number of hard links */
    minfo("Stat st_uid '%d'", (int)path_stat.st_uid);     /* user ID of owner */
    minfo("Stat st_gid '%d'", (int)path_stat.st_gid);     /* group ID of owner */
    minfo("Stat st_rdev '%d'", (int)path_stat.st_rdev);    /* device ID (if special file) */
    minfo("Stat st_size '%ld'", (long int)path_stat.st_size);    /* total size, in bytes */
    //minfo("Stat st_blksize '%d'", (int)path_stat.st_blksize); /* blocksize for file system I/O */
    //minfo("Stat st_blocks '%d'", (int)path_stat.st_blocks);  /* number of 512B blocks allocated */
    minfo("Stat st_atime '%d'", (int)path_stat.st_atime);   /* time of last access */
    minfo("Stat st_mtime '%d'", (int)path_stat.st_mtime);   /* time of last modification */
    minfo("Stat st_ctime '%d'", (int)path_stat.st_ctime);   /* time of last status change */

}


int print_hash_tables() {
    OSHashNode * hash_node;
    fim_entry_data * fim_entry_data;
    fim_inode_data * fim_inode_data;
    char * files = NULL;
    unsigned int * inode_it;
    int element_sch = 0;
    int element_rt = 0;
    int element_wd = 0;
    int element_total = 0;
    int i;

    os_calloc(1, sizeof(unsigned int), inode_it);

    hash_node = OSHash_Begin(syscheck.fim_entry, inode_it);
    while(hash_node) {
        fim_entry_data = hash_node->data;
        minfo("ENTRY (%d) => '%s'->'%lu' scanned:'%u'\n", element_total, (char*)hash_node->key, fim_entry_data->inode, fim_entry_data->scanned);
        switch(fim_entry_data->mode) {
            case FIM_SCHEDULED: element_sch++; break;
            case FIM_REALTIME: element_rt++; break;
            case FIM_WHODATA: element_wd++; break;
        }
        hash_node = OSHash_Next(syscheck.fim_entry, inode_it, hash_node);

        element_total++;
    }

    *inode_it = 0;
    element_total = 0;

    hash_node = OSHash_Begin(syscheck.fim_inode, inode_it);
    while(hash_node) {
        fim_inode_data = hash_node->data;
        os_free(files);
        os_calloc(1, sizeof(char), files);
        *files = '\0';
        for(i = 0; i < fim_inode_data->items; i++) {
            wm_strcat(&files, fim_inode_data->paths[i], ',');
        }
        minfo("INODE (%u) => '%s'->(%d)'%s'\n", element_total, (char*)hash_node->key, fim_inode_data->items, files);
        hash_node = OSHash_Next(syscheck.fim_inode, inode_it, hash_node);

        element_total++;
    }

    minfo("SCH '%d'", element_sch);
    minfo("RT '%d'", element_rt);
    minfo("WD '%d'", element_wd);

    os_free(inode_it);
    os_free(files);

    return 0;
}




int generate_dirtree(OSDirTree * tree) {
    OSHashNode * hash_node;
    fim_entry_data * fim_node;
    char ** key;
    unsigned int * inode_it;
    unsigned int element = 0;
    unsigned int i;

    os_calloc(syscheck.n_entries, sizeof(char *), key);
    os_calloc(1, sizeof(unsigned int), inode_it);

    hash_node = OSHash_Begin(syscheck.fim_entry, inode_it);
    while(hash_node) {
        fim_node = hash_node->data;
        if(element < syscheck.n_entries) {
            os_strdup(hash_node->key, key[element]);
        } else {
            merror("Cant add '%s' into keys array", hash_node->key);
        }

        hash_node = OSHash_Next(syscheck.fim_entry, inode_it, hash_node);
        element++;
    }

    qsort(key, syscheck.n_entries, sizeof(char *), strcompare);

    tree = OSDirTree_Create();

    for(i = 0; i < syscheck.n_entries; i++) {
        minfo("1File: '%s'", key[i]);
        OSDirTree_AddToTree(tree, key[i], NULL, PATH_SEP);
    }

    return 0;
}


static int strcompare(const void *s1, const void *s2) {
    return strcmp(* (char * const *) s1,* (char * const *)  s2);
}


void print_tree(OSTreeNode * tree) {
    OSTreeNode * node;
    char ** elements = NULL;
    int i = 0;

    if (tree) {

        os_calloc(1, sizeof(char *), elements);

        node = tree;

        while(node) {
            if (node->child) {
                print_tree(node->child->first_node);
            } else {
                if (elements) {
                    os_realloc(elements, i + 2, elements);
                    elements[i + 1] = NULL;
                } else {
                    os_calloc(2, sizeof(char *), elements);
                    elements[1] = NULL;
                }
                os_strdup(node->data, elements[i]);
            }

            node = node->next;
            i++;
        }

        minfo("Value: '%s'", tree->value);
        for(i = 0; elements[i]; i++) {
            minfo("data: '%s'", elements[i]);
        }
    }
}
