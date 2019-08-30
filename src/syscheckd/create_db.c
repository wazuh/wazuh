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
#include "integrity_op.h"

// delete this functions
// ==================================
static void print_file_info(struct stat path_stat);
int print_hash_tables();
// ==================================

// Global variables
static int _base_line = 0;

typedef enum fim_alert_type {
    FIM_ADD,
    FIM_DELETE,
    FIM_MODIFICATION
}fim_alert_type;

static const char *FIM_ALERT[] = {
    "Added",
    "Deleted",
    "Modified"
};

static const char *FIM_ALERT_MODE[] = {
    "Scheduled",
    "Real-time",
    "Whodata"
};


int fim_scan() {
    int position = 0;

    minfo(FIM_FREQUENCY_STARTED);

    clock_t begin = clock();

    while (syscheck.dir[position] != NULL) {
        minfo("fim_scan(%d): '%s'", FIM_MODE(syscheck.opts[position]), syscheck.dir[position]);
        fim_process_event(syscheck.dir[position], FIM_MODE(syscheck.opts[position]), NULL);
        position++;
    }

    clock_t end = clock();
    minfo("The scan has been running during: %f sec.", (double)(end - begin) / CLOCKS_PER_SEC);
    print_hash_tables();

    if (_base_line == 0) {
        _base_line = 1;
    } else {
        check_deleted_files();
    }

    minfo(FIM_FREQUENCY_ENDED);

    return 0;
}


int fim_directory (char * path, int dir_position, whodata_evt * w_evt) {
    DIR *dp;
    struct dirent *entry;
    char *f_name;
    char *s_name;
    char linked_read_file[PATH_MAX + 1] = {'\0'};
    int options;
    int mode = 0;
    size_t path_size;
    short is_nfs;

    if (!path) {
        merror(NULL_ERROR);
        return OS_INVALID;
    }

    options = syscheck.opts[dir_position];

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
    cJSON * json_event = NULL;
    fim_entry_data * entry_data = NULL;
    fim_entry_data * saved_data = NULL;
    struct stat file_stat;
    char * json_formated;
    int options;
    int deleted_flag = 0;

    options = syscheck.opts[dir_position];

    if (w_stat(file_name, &file_stat) < 0) {
        deleted_flag = 1;
    }

    //File attributes
    if (entry_data = fim_get_data(file_name, file_stat, mode, options), !entry_data) {
        merror("Couldn't get attributes for file: '%s'", file_name);
        return OS_INVALID;
    }

    if (!_base_line && options & CHECK_SEECHANGES && !deleted_flag) {
        seechanges_addfile(file_name);
    }

    w_mutex_lock(&syscheck.fim_entry_mutex);
    if (saved_data = (fim_entry_data *) OSHash_Get(syscheck.fim_entry, file_name), !saved_data) {
        // New entry. Insert into hash table
        if (fim_insert (file_name, entry_data) == -1) {
            free_entry_data(entry_data);
            os_free(entry_data);
            w_mutex_unlock(&syscheck.fim_entry_mutex);
            return OS_INVALID;
        }

        if (_base_line) {
            json_event = fim_json_event(file_name, NULL, entry_data, dir_position, FIM_ADD, mode, w_evt);
        }
    } else {
        // Delete file. Sending alert.
        if (deleted_flag) {
            if(json_event = fim_json_event (file_name, NULL, saved_data, dir_position, FIM_DELETE, mode, w_evt), json_event) {
                // minfo("File '%s' checksum: '%s'", file_name, checksum);
                fim_delete (file_name);
            }
        // Checking for changes
        } else {
            saved_data->scanned = 1;
            if (json_event = fim_json_event(file_name, saved_data, entry_data, dir_position, FIM_MODIFICATION, mode, w_evt), json_event) {
                if (fim_update (file_name, entry_data) == -1) {
                    free_entry_data(entry_data);
                    os_free(entry_data);
                    w_mutex_unlock(&syscheck.fim_entry_mutex);
                    return OS_INVALID;
                }
                //set_integrity_index(file_name, entry_data);
            } else {
                free_entry_data(entry_data);
                os_free(entry_data);
            }
        }
    }
    w_mutex_unlock(&syscheck.fim_entry_mutex);

    if (json_event) {
        // minfo("File '%s' checksum: '%s'", file_name, checksum);
        if (_base_line || mode == FIM_WHODATA || mode == FIM_REALTIME) {
            json_formated = cJSON_PrintUnformatted(json_event);
            minfo("%s", json_formated);
            send_syscheck_msg(json_formated);
            os_free(json_formated);
        }
        cJSON_Delete(json_event);
    }

    return 0;
}


int fim_process_event(char * file, int mode, whodata_evt *w_evt) {
    struct stat file_stat;
    int dir_position = 0;
    int depth = 0;

    if (fim_check_ignore(file) == 1) {
        return (0);
    }

    if (fim_check_restrict (file, syscheck.filerestrict[dir_position]) == 1) {
        return (0);
    }

    // If the directory have another configuration will come back
    if (dir_position = fim_configuration_directory(file), dir_position < 0) {
        minfo("No configuration founded for file: '%s'", file);
        return(0);
    }

    mdebug1("~~ fim_process_event mode('%d'):'%s' config:'%s'", mode, file, syscheck.dir[dir_position]);

    if (FIM_MODE(syscheck.opts[dir_position]) == mode) {
        depth = fim_check_depth(file, dir_position);
        //minfo("~~Depth from parent path: '%d' recursion level:'%d'", depth, syscheck.recursion_level[dir_position]);
        if(depth >= syscheck.recursion_level[dir_position]) {
            minfo("~~ Maximum depth reached: %s", file);
            return 0;
        }

        // If w_stat fails can be a deleted file
        if (w_stat(file, &file_stat) < 0) {
            // Regular file
            if (fim_check_file(file, dir_position, mode, w_evt) < 0) {
                merror("Skiping file: '%s'", file);
            }
        } else {
            switch(file_stat.st_mode & S_IFMT) {
                case FIM_REGULAR:
                    // Regular file
                    if (fim_check_file(file, dir_position, mode, w_evt) < 0) {
                        merror("Skip event: '%s'", file);
                    }
                    break;

                case FIM_DIRECTORY:
                    // Directory path
                    fim_directory(file, dir_position, w_evt);
                    break;
#ifndef WIN32
                case FIM_LINK:
                    // Symbolic links add link and follow if it is configured
                    // TODO: implement symbolic links
                    break;
#endif
                default:
                    // Unsupported file type
                    return -1;
            }
        }
    } else {
        minfo("Different configuration applied to file '%s'", file);
    }

    return 0;
}


// Returns the position of the path into directories array
int fim_configuration_directory(char * path) {
    int it = 0;
    int max = 0;
    int res = 0;
    int position = -1;

    while(syscheck.dir[it]) {
        res = w_compare_str(syscheck.dir[it], path);
        if (max < res) {
            position = it;
            max = res;
        }
        it++;
    }

    return position;
}


// Evaluates the depth of the directory or file to check if it exceeds the configured max_depth value
int fim_check_depth(char * path, int dir_position) {
    char * pos;
    int depth = 0;
    unsigned int parent_path_size;

    if (!syscheck.dir[dir_position]) {
        minfo("~~Invalid parent path.");
        return -1;
    }

    parent_path_size = strlen(syscheck.dir[dir_position]);

    if (parent_path_size > strlen(path)) {
        minfo("~~Parent directory < path: %s < %s", syscheck.dir[dir_position], path);
        return -1;
    }

    pos = path + parent_path_size;
    while (pos) {
        if (pos = strchr(pos, '/'), pos) {
            depth++;
        } else {
            break;
        }
        pos++;
    }

    return depth;
}


// Get data from file
fim_entry_data * fim_get_data (const char * file_name, struct stat file_stat, int mode, int options) {
    fim_entry_data * data = NULL;

    os_calloc(1, sizeof(fim_entry_data), data);

    data->size = file_stat.st_size;
    data->perm = file_stat.st_mode;
    data->mtime = file_stat.st_mtime;
    data->inode = file_stat.st_ino;
    data->uid = file_stat.st_uid;
    data->gid = file_stat.st_gid;

#ifdef WIN32
    data->user_name = get_user(file_name, file_stat.st_uid, &data->sid);
    os_strdup((char*)get_group(file_stat.st_gid), data->group_name);
#else
    os_strdup((char*)get_user(file_name, file_stat.st_uid, NULL), data->user_name);
    os_strdup((char*)get_user(file_name, file_stat.st_uid, NULL), data->group_name);
#endif

    snprintf(data->hash_md5, sizeof(os_md5), "%s", "d41d8cd98f00b204e9800998ecf8427e");
    snprintf(data->hash_sha1, sizeof(os_sha1), "%s", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    snprintf(data->hash_sha256, sizeof(os_sha256), "%s", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // The file exists and we don't have to delete it from the hash tables
    data->scanned = 1;

    // We won't calculate hash for symbolic links, empty or large files
#ifdef __linux__
    if ((file_stat.st_mode & S_IFMT) == FIM_REGULAR)
#endif
        if (file_stat.st_size > 0 && (size_t)file_stat.st_size < syscheck.file_max_size) {
            if (OS_MD5_SHA1_SHA256_File(file_name,
                                        syscheck.prefilter_cmd,
                                        data->hash_md5,
                                        data->hash_sha1,
                                        data->hash_sha256,
                                        OS_BINARY,
                                        syscheck.file_max_size) < 0) {
                merror("Couldn't generate hashes for '%s'", file_name);
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
        merror("Wrong size, can't get checksum: %s", checksum);
        *checksum = '\0';
    } else if (size >= OS_SIZE_128) {
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

    // TODO: Check time difference between functions OS_SHA1_Str and OS_SHA1_Str2

    // minfo("checksum '%s'\n", checksum);
    char * output;
    os_calloc(1, sizeof(os_sha1), output);
    OS_SHA1_Str(checksum, sizeof(checksum), output);
    // minfo("var 1 SHA1 '%s'\n", output);
    // OS_SHA1_Str2(checksum, sizeof(checksum), output);
    // minfo("var 2 SHA1 '%s'\n", output);
    os_free(checksum);

    return output;
}


// Inserts a file in the syscheck hash table structure (inodes and paths)
int fim_insert (char * file, fim_entry_data * data) {
    char * inode_key = NULL;
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

    if (inode_data = OSHash_Get(syscheck.fim_inode, inode_key), !inode_data) {
        os_calloc(1, sizeof(fim_inode_data), inode_data);

        inode_data->paths = os_AddStrArray(file, inode_data->paths);
        inode_data->items = 1;

        if (OSHash_Add(syscheck.fim_inode, inode_key, inode_data) != 2) {
            merror("Unable to add inode to db: '%s' => '%s'", inode_key, file);
            os_free(inode_key);
            return (-1);
        }

        syscheck.n_inodes++;
    } else {
        // TODO: Maybe create a function to modularize this section
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
            fim_delete(to_delete[i++]);
        }

        free_strarray(to_delete);
        free_strarray(inode_data->paths);
        inode_data->paths = new_paths;

    }
#endif

    os_free(inode_key);
    return 0;
}


// Update an entry in the syscheck hash table structure (inodes and paths)
int fim_update (char * file, fim_entry_data * data) {
    char * inode_key;

    os_calloc(OS_SIZE_16, sizeof(char), inode_key);
    snprintf(inode_key, OS_SIZE_16, "%ld", data->inode);

    if (!file || strcmp(file, "") == 0 || !inode_key || strcmp(inode_key, "") == 0) {
        merror("Can't update entry invalid file or inode");
        // TODO: Consider if we should exit here. Change to debug message
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
int fim_delete (char * file_name) {
    fim_entry_data * saved_data;
    char * file_to_delete = NULL;

    if (saved_data = OSHash_Get(syscheck.fim_entry, file_name), saved_data) {
        os_strdup(file_name, file_to_delete);
#ifndef WIN32
        char * inode = NULL;
        os_calloc(OS_SIZE_16, sizeof(char), inode);
        snprintf(inode, OS_SIZE_16, "%ld", saved_data->inode);
        delete_inode_item(inode, file_to_delete);
        // TODO: Send alert to manager (send_msg())
#endif
        OSHash_Delete(syscheck.fim_entry, file_to_delete);
        free_entry_data(saved_data);
        os_free(saved_data);
#ifndef WIN32
        os_free(inode);
#endif
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
            minfo("File '%s' has been deleted.", hash_node->key);
            os_strdup(hash_node->key, key);
            // We must save the next node before deteling the current one
            hash_node = OSHash_Next(syscheck.fim_entry, inode_it, hash_node);
            fim_delete(key);
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

cJSON * fim_json_event(char * file_name, fim_entry_data * old_data, fim_entry_data * new_data, int dir_position, int type, int mode, whodata_evt * w_evt) {
    cJSON * json_event = cJSON_CreateObject();
    cJSON * json_alert = NULL;

    if (old_data) {
        json_alert = fim_json_alert_changes(file_name, old_data, new_data, dir_position, type, mode, w_evt);
    }
    else {
        json_alert = fim_json_alert(file_name, new_data, dir_position, type, mode, w_evt);
    }

    if (json_alert != NULL) {
        cJSON_AddStringToObject(json_event, "type", "event");
        cJSON_AddItemToObject(json_event, "event", json_alert);
        return json_event;
    }
    else {
        cJSON_Delete(json_event);
        return NULL;
    }
}

cJSON * fim_json_alert(char * file_name, fim_entry_data * data, int dir_position, int type, int mode, whodata_evt * w_evt) {
    cJSON * response = NULL;
    cJSON * fim_report = NULL;
    cJSON * fim_attributes = NULL;
    cJSON * extra_data = NULL;
    cJSON * fim_audit = NULL;
    char * checksum = NULL;
    char * tags = syscheck.tag[dir_position];
    char * diff = NULL;

    checksum = fim_get_checksum(data);

    fim_report = cJSON_CreateObject();
    cJSON_AddStringToObject(fim_report, "path", file_name);
    cJSON_AddNumberToObject(fim_report, "options", data->options);
    cJSON_AddStringToObject(fim_report, "alert", FIM_ALERT[type]);
    cJSON_AddStringToObject(fim_report, "mode", FIM_ALERT_MODE[mode]);
    cJSON_AddNumberToObject(fim_report, "level0", data->level0);
    cJSON_AddNumberToObject(fim_report, "level1", data->level1);
    cJSON_AddNumberToObject(fim_report, "level2", data->level2);
    cJSON_AddStringToObject(fim_report, "integrity", checksum);

    fim_attributes = cJSON_CreateObject();
    cJSON_AddNumberToObject(fim_attributes, "size", data->size);
    cJSON_AddNumberToObject(fim_attributes, "perm", data->perm);
    cJSON_AddStringToObject(fim_attributes, "user_name", data->user_name);
    cJSON_AddStringToObject(fim_attributes, "group_name", data->group_name);
#ifdef __linux__
    cJSON_AddNumberToObject(fim_attributes, "uid", data->uid);
    cJSON_AddNumberToObject(fim_attributes, "gid", data->gid);
    cJSON_AddNumberToObject(fim_attributes, "inode", data->inode);
#elif WIN32
        cJSON_AddStringToObject(fim_attributes, "sid", data->sid);
#endif
    cJSON_AddNumberToObject(fim_attributes, "mtime", data->mtime);
    cJSON_AddStringToObject(fim_attributes, "hash_md5", data->hash_md5);
    cJSON_AddStringToObject(fim_attributes, "hash_sha1", data->hash_sha1);
    cJSON_AddStringToObject(fim_attributes, "hash_sha256", data->hash_sha256);
#ifdef WIN32
    cJSON_AddNumberToObject(fim_attributes, "win_attributes", w_get_file_attrs(file_name));
#endif

    extra_data = cJSON_CreateObject();
    if (tags != NULL) {
        cJSON_AddStringToObject(extra_data, "tags", tags);
    }

    if (syscheck.opts[dir_position] & CHECK_SEECHANGES) {
        if (diff = seechanges_addfile(file_name), diff) {
            cJSON_AddStringToObject(extra_data, "diff", diff);
            os_free(diff);
        }
    }

    if (w_evt) {
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
    cJSON_AddItemToObject(response, "extra_data", extra_data);

    if (w_evt) {
        cJSON_AddItemToObject(response, "audit", fim_audit);
    }
    os_free(checksum);

    return response;
}

cJSON * fim_json_alert_changes (char * file_name, fim_entry_data * old_data, fim_entry_data * new_data, int dir_position, int type, int mode, whodata_evt * w_evt) {
    cJSON * response = NULL;
    cJSON * fim_report = NULL;
    cJSON * fim_attributes = NULL;
    cJSON * fim_old_attributes = NULL;
    cJSON * extra_data = NULL;
    cJSON * fim_audit = NULL;
    char * checksum = NULL;
    char * tags = syscheck.tag[dir_position];
    char * diff = NULL;
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
        checksum = fim_get_checksum(new_data);

        fim_report = cJSON_CreateObject();
        cJSON_AddStringToObject(fim_report, "path", file_name);
        cJSON_AddNumberToObject(fim_report, "options", old_data->options);
        cJSON_AddStringToObject(fim_report, "alert", FIM_ALERT[type]);
        cJSON_AddStringToObject(fim_report, "mode", FIM_ALERT_MODE[mode]);
        cJSON_AddNumberToObject(fim_report, "level0", old_data->level0);
        cJSON_AddNumberToObject(fim_report, "level1", old_data->level1);
        cJSON_AddNumberToObject(fim_report, "level2", old_data->level2);
        cJSON_AddStringToObject(fim_report, "integrity", checksum);

        fim_attributes = cJSON_CreateObject();
        cJSON_AddNumberToObject(fim_attributes, "size", new_data->size);
        cJSON_AddNumberToObject(fim_attributes, "perm", new_data->perm);
        cJSON_AddStringToObject(fim_attributes, "user_name", new_data->user_name);
        cJSON_AddStringToObject(fim_attributes, "group_name", new_data->group_name);
#ifdef __linux__
        cJSON_AddNumberToObject(fim_attributes, "uid", new_data->uid);
        cJSON_AddNumberToObject(fim_attributes, "gid", new_data->gid);
        cJSON_AddNumberToObject(fim_attributes, "inode", new_data->inode);
#elif WIN32
        cJSON_AddStringToObject(fim_attributes, "sid", new_data->sid);
#endif
        cJSON_AddNumberToObject(fim_attributes, "mtime", new_data->mtime);
        cJSON_AddStringToObject(fim_attributes, "hash_md5", new_data->hash_md5);
        cJSON_AddStringToObject(fim_attributes, "hash_sha1", new_data->hash_sha1);
        cJSON_AddStringToObject(fim_attributes, "hash_sha256", new_data->hash_sha256);
#ifdef WIN32
        cJSON_AddNumberToObject(fim_attributes, "win_attributes", w_get_file_attrs(file_name));
#endif

        fim_old_attributes = cJSON_CreateObject();
        cJSON_AddNumberToObject(fim_old_attributes, "old_size", old_data->size);
        cJSON_AddNumberToObject(fim_old_attributes, "old_perm", old_data->perm);
        cJSON_AddStringToObject(fim_old_attributes, "old_user_name", old_data->user_name);
        cJSON_AddStringToObject(fim_old_attributes, "old_group_name", old_data->group_name);
#ifdef __linux__
        cJSON_AddNumberToObject(fim_old_attributes, "old_uid", old_data->uid);
        cJSON_AddNumberToObject(fim_old_attributes, "old_gid", old_data->gid);
        cJSON_AddNumberToObject(fim_old_attributes, "old_inode", old_data->inode);
#elif WIN32
        cJSON_AddStringToObject(fim_attributes, "sid", old_data->sid);
#endif
        cJSON_AddNumberToObject(fim_old_attributes, "old_mtime", old_data->mtime);
        cJSON_AddStringToObject(fim_old_attributes, "old_hash_md5", old_data->hash_md5);
        cJSON_AddStringToObject(fim_old_attributes, "old_hash_sha1", old_data->hash_sha1);
        cJSON_AddStringToObject(fim_old_attributes, "old_hash_sha256", old_data->hash_sha256);

        extra_data = cJSON_CreateObject();
        if (tags != NULL) {
            cJSON_AddStringToObject(extra_data, "tags", tags);
        }

        if (syscheck.opts[dir_position] & CHECK_SEECHANGES) {
            if (diff = seechanges_addfile(file_name), diff) {
                cJSON_AddStringToObject(extra_data, "diff", diff);
                os_free(diff);
            }
        }

        if (w_evt) {
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
        cJSON_AddItemToObject(response, "old_attributes", fim_old_attributes);
        cJSON_AddItemToObject(response, "extra_data", extra_data);

        if (w_evt) {
            cJSON_AddItemToObject(response, "audit", fim_audit);
        }
        os_free(checksum);
    }

    return response;
}


int fim_check_ignore (const char *file_name) {
    /* Check if the file should be ignored */
    if (syscheck.ignore) {
        int i = 0;
        while (syscheck.ignore[i] != NULL) {
            if (strncasecmp(syscheck.ignore[i], file_name, strlen(syscheck.ignore[i])) == 0) {
                mdebug2(FIM_IGNORE_ENTRY, "file", file_name, syscheck.ignore[i]);
                return (1);
            }
            i++;
        }
    }

    /* Check in the regex entry */
    if (syscheck.ignore_regex) {
        int i = 0;
        while (syscheck.ignore_regex[i] != NULL) {
            if (OSMatch_Execute(file_name, strlen(file_name), syscheck.ignore_regex[i])) {
                mdebug2(FIM_IGNORE_SREGEX, "file", file_name, syscheck.ignore_regex[i]->raw);
                return (1);
            }
            i++;
        }
    }

    return (0);
}

int fim_check_restrict (const char *file_name, OSMatch *restriction) {
    /* Restrict file types */
    if (restriction) {
        if (!OSMatch_Execute(file_name, strlen(file_name), restriction)) {
            mdebug1(FIM_FILE_IGNORE_RESTRICT, file_name);
            return (1);
        }
    }

    return (0);
}


// Get and set index of the integrity levels in data structure
void set_integrity_index(char * file_name, fim_entry_data * data) {
    unsigned int rows = syscheck.fim_entry->rows;
    unsigned int tl2 = cbrt(rows);
    unsigned int tl1 = tl2 * tl2;
    unsigned int div = rows / tl1;
    unsigned int rest = rows % tl1;
    unsigned int aux = (rest * (div + 1));

    data->level0 = OSHash_GetIndex(syscheck.fim_entry, file_name);

    if (data->level0 <= aux) {
        data->level1 = data->level0 / (div + 1);
    } else {
        data->level1 = ((data->level0 - aux) / div) + rest;
    }

    data->level2 = data->level1 / tl2;
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
    char * files = NULL;
    unsigned int * inode_it;
    int element_sch = 0;
    int element_rt = 0;
    int element_wd = 0;
    int element_total = 0;

    os_calloc(1, sizeof(unsigned int), inode_it);

    hash_node = OSHash_Begin(syscheck.fim_entry, inode_it);
    while(hash_node) {
        fim_entry_data = hash_node->data;
        //minfo("ENTRY (%d) => '%s'->'%lu' scanned:'%u' L0:'%d' L1:'%d' L2:'%d'\n", element_total, (char*)hash_node->key, fim_entry_data->inode, fim_entry_data->scanned, fim_entry_data->level0, fim_entry_data->level1, fim_entry_data->level2);
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
#ifndef WIN32
    fim_inode_data * fim_inode_data;
    int i;
    hash_node = OSHash_Begin(syscheck.fim_inode, inode_it);
    while(hash_node) {
        fim_inode_data = hash_node->data;
        os_free(files);
        os_calloc(1, sizeof(char), files);
        *files = '\0';
        for(i = 0; i < fim_inode_data->items; i++) {
            wm_strcat(&files, fim_inode_data->paths[i], ',');
        }
        //minfo("INODE (%u) => '%s'->(%d)'%s'\n", element_total, (char*)hash_node->key, fim_inode_data->items, files);
        hash_node = OSHash_Next(syscheck.fim_inode, inode_it, hash_node);

        element_total++;
    }
#endif
    minfo("SCH '%d'", element_sch);
    minfo("RT '%d'", element_rt);
    minfo("WD '%d'", element_wd);

    os_free(inode_it);
    os_free(files);

    return 0;
}
