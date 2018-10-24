/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "remoted.h"
#include "os_crypto/md5/md5_op.h"
#include "os_net/os_net.h"
#include "shared_download.h"
#include <pthread.h>

#if defined(__FreeBSD__) || defined(__MACH__) || defined(__sun__)
#define HOST_NAME_MAX 64
#endif

/* Internal structures */
typedef struct _file_sum {
    int mark;
    char *name;
    os_md5 sum;
} file_sum;

typedef struct group_t {
    char *group;
    file_sum **f_sum;
} group_t;

/* Internal functions prototypes */
static void read_controlmsg(const char *agent_id, char *msg);
static int send_file_toagent(const char *agent_id, const char *group, const char *name, const char *sum);
static void c_group(const char *group, char ** files, file_sum ***_f_sum);
static void c_files(void);
static file_sum** find_sum(const char *group);
static file_sum ** find_group(const char * file, const char * md5, char group[KEYSIZE]);

/* Global vars */
static group_t **groups;
static time_t _stime;

/* For the last message tracking */
static char pending_queue[MAX_AGENTS][9];
static volatile int queue_i = 0;
static volatile int queue_j = 0;
OSHash *pending_data;

/* pthread mutex variables */
static pthread_mutex_t lastmsg_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t files_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t awake_mutex = PTHREAD_COND_INITIALIZER;


/* Interval polling */
static int poll_interval_time = 0;

/* Save a control message received from an agent
 * read_controlmsg (other thread) is going to deal with it
 * (only if message changed)
 */
void save_controlmsg(unsigned int agentid, char *r_msg, size_t msg_length)
{
    char msg_ack[OS_FLSIZE + 1];
    char *end;
    char *uname = "";
    pending_data_t *data;
    FILE * fp;
    mode_t oldmask;
    int is_startup = 0;

    if (strncmp(r_msg, HC_REQUEST, strlen(HC_REQUEST)) == 0) {
        char * counter = r_msg + strlen(HC_REQUEST);
        char * payload;

        if (payload = strchr(counter, ' '), !payload) {
            merror("Request control format error.");
            mdebug2("r_msg = \"%s\"", r_msg);
            return;
        }

        *(payload++) = '\0';

        req_save(counter, payload, msg_length - (payload - r_msg));
        return;
    }

    /* Reply to the agent */
    snprintf(msg_ack, OS_FLSIZE, "%s%s", CONTROL_HEADER, HC_ACK);
    send_msg(keys.keyentries[agentid]->id, msg_ack, -1);

    if (strcmp(r_msg, HC_STARTUP) == 0) {
        mdebug1("Agent %s sent HC_STARTUP from %s.", keys.keyentries[agentid]->name, inet_ntoa(keys.keyentries[agentid]->peer_info.sin_addr));
        is_startup = 1;
    } else {
        /* Clean uname and shared files (remove random string) */
        uname = r_msg;

        if ((r_msg = strchr(r_msg, '\n'))) {
            /* Forward to random string (pass shared files) */
            for (r_msg++; (end = strchr(r_msg, '\n')); r_msg = end + 1);
            *r_msg = '\0';
        } else {
            mwarn("Invalid message from agent id: '%d'(uname)", agentid);
            return;
        }
    }

    /* Lock mutex */
    w_mutex_lock(&lastmsg_mutex)

    /* Check if there is a keep alive already for this agent */
    if (data = OSHash_Get(pending_data, keys.keyentries[agentid]->id), data && data->changed && data->message && strcmp(data->message, uname) == 0) {
        w_mutex_unlock(&lastmsg_mutex);
        utimes(data->keep_alive, NULL);
    } else {
        if (!data) {
            os_calloc(1, sizeof(pending_data_t), data);

            if (OSHash_Add(pending_data, keys.keyentries[agentid]->id, data) != 2) {
                merror("Couldn't add pending data into hash table.");

                /* Unlock mutex */
                w_mutex_unlock(&lastmsg_mutex);

                free(data);
                return;
            }
        }

        if (!data->keep_alive) {
            char agent_file[PATH_MAX];

            /* Write to the agent file */
            snprintf(agent_file, PATH_MAX, "%s/%s-%s",
                     AGENTINFO_DIR,
                     keys.keyentries[agentid]->name,
                     keys.keyentries[agentid]->ip->ip);

            os_strdup(agent_file, data->keep_alive);
        }

        if (is_startup) {
            w_mutex_unlock(&lastmsg_mutex);
            oldmask = umask(0006);

            if (fp = fopen(data->keep_alive, "a"), fp) {
                fclose(fp);
            } else {
                merror(FOPEN_ERROR, data->keep_alive, errno, strerror(errno));
            }

            umask(oldmask);
        } else {
            /* Update message */
            mdebug2("save_controlmsg(): inserting '%s'", uname);
            free(data->message);
            os_strdup(uname, data->message);

            /* Mark data as changed and insert into queue */

            if (!data->changed) {
                if (full(queue_i, queue_j)) {
                    merror("Pending message queue full.");
                } else {
                    strncpy(pending_queue[queue_i], keys.keyentries[agentid]->id, 8);
                    forward(queue_i);

                    /* Signal that new data is available */
                    w_cond_signal(&awake_mutex);

                    data->changed = 1;
                }
            }

            /* Unlock mutex */
            w_mutex_unlock(&lastmsg_mutex);

            /* Write uname to the file */

            oldmask = umask(0006);
            fp = fopen(data->keep_alive, "w");
            umask(oldmask);

            if (fp) {
                /* Get manager name before chroot */
                char hostname[HOST_NAME_MAX + 1];

                fprintf(fp, "%s\n", uname);

                /* Write manager hostname to the file */

                if (gethostname(hostname, HOST_NAME_MAX) < 0){
                    mwarn("Unable to get hostname due to: '%s'", strerror(errno));
                } else {
                    fprintf(fp, "#\"manager_hostname\":%s\n", hostname);
                }

                /* Write Cluster's node name to the agent-info file */
                char nodename[OS_MAXSTR];

                snprintf(nodename, OS_MAXSTR - 1, "#\"node_name\":%s\n", node_name);
                fprintf(fp, "%s", nodename);

                fclose(fp);
            } else {
                merror(FOPEN_ERROR, data->keep_alive, errno, strerror(errno));
            }
        }
    }
}

void c_group(const char *group, char ** files, file_sum ***_f_sum) {
    os_md5 md5sum;
    unsigned int f_size = 0;
    file_sum **f_sum;
    char merged_tmp[PATH_MAX + 1];
    char merged[PATH_MAX + 1];
    char file[PATH_MAX + 1];
    unsigned int i;
    remote_files_group *r_group = NULL;

    /* Create merged file */
    os_calloc(2, sizeof(file_sum *), f_sum);
    os_calloc(1, sizeof(file_sum), f_sum[f_size]);
    *_f_sum = f_sum;

    f_sum[f_size]->mark = 0;
    f_sum[f_size]->name = NULL;
    f_sum[f_size]->sum[0] = '\0';

    snprintf(merged, PATH_MAX + 1, "%s/%s/%s", SHAREDCFG_DIR, group, SHAREDCFG_FILENAME);

    if (!logr.nocmerged && (r_group = w_parser_get_group(group), r_group)) {
        if(r_group->current_polling_time <= 0){
            r_group->current_polling_time = r_group->poll;

            char *file_url;
            char *file_name;
            char destination_path[PATH_MAX + 1];
            char download_path[PATH_MAX + 1];
            int downloaded;

            // Check if we have merged.mg file in this group
            if(r_group->merge_file_index >= 0){
                file_url = r_group->files[r_group->merge_file_index].url;
                file_name = SHAREDCFG_FILENAME;
                snprintf(destination_path, PATH_MAX + 1, "%s/%s", DOWNLOAD_DIR, file_name);
                mdebug1("Downloading shared file '%s' from '%s'", merged, file_url);
                downloaded = wurl_request(file_url,destination_path);
                w_download_status(downloaded,file_url,destination_path);
                r_group->merged_is_downloaded = !downloaded;

                // Validate the file
                if(r_group->merged_is_downloaded){

                    // File is invalid
                    if(!TestUnmergeFiles(destination_path,OS_TEXT))
                    {
                        int fd = unlink(destination_path);

                        merror("The downloaded file '%s' is corrupted.",destination_path);

                        if(fd == -1){
                            merror("Failed to delete file '%s'",destination_path);
                        }
                        return;
                    }

                    OS_MoveFile(destination_path,merged);
                }
            }
            else{ // Download all files
                int i;

                if(r_group->files){
                    for(i = 0; r_group->files[i].name; i++)
                    {
                        file_url = r_group->files[i].url;
                        file_name = r_group->files[i].name;
                        snprintf(destination_path, PATH_MAX + 1, "%s/%s/%s", SHAREDCFG_DIR, group, file_name);
                        snprintf(download_path, PATH_MAX + 1, "%s/%s", DOWNLOAD_DIR, file_name);
                        mdebug1("Downloading shared file '%s' from '%s'", destination_path, file_url);
                        downloaded = wurl_request(file_url,download_path);

                        if (!w_download_status(downloaded, file_url, destination_path)) {
                            OS_MoveFile(download_path, destination_path);
                        }
                    }
                }
            }
        }
        else{
            r_group->current_polling_time -= poll_interval_time;
        }
    }

    f_size++;

    if(r_group && r_group->merged_is_downloaded){

        // Validate the file
        if (OS_MD5_File(merged, md5sum, OS_TEXT) != 0) {
            f_sum[0]->sum[0] = '\0';
            merror("Accessing file '%s'", merged);
        }
        else{
            strncpy(f_sum[0]->sum, md5sum, 32);
            os_strdup(SHAREDCFG_FILENAME, f_sum[0]->name);
        }

        f_sum[f_size] = NULL;
    }
    else{
        // Merge ar.conf always

        if (!logr.nocmerged) {
            snprintf(merged_tmp, PATH_MAX + 1, "%s.tmp", merged);
            // First call, truncate merged file
            MergeAppendFile(merged_tmp, NULL, group, -1);
        }

        if (OS_MD5_File(DEFAULTAR, md5sum, OS_TEXT) == 0) {
            os_realloc(f_sum, (f_size + 2) * sizeof(file_sum *), f_sum);
            *_f_sum = f_sum;
            os_calloc(1, sizeof(file_sum), f_sum[f_size]);
            strncpy(f_sum[f_size]->sum, md5sum, 32);
            os_strdup(DEFAULTAR_FILE, f_sum[f_size]->name);

            if (!logr.nocmerged) {
                MergeAppendFile(merged_tmp, DEFAULTAR, NULL, -1);
            }

            f_size++;
        }

        /* Read directory */
        for (i = 0; files[i]; ++i) {
            /* Ignore hidden files  */
            /* Leave the shared config file for later */
            /* Also discard merged.mg.tmp */
            if (files[i][0] == '.' || !strncmp(files[i], SHAREDCFG_FILENAME, strlen(SHAREDCFG_FILENAME))) {
                continue;
            }

            snprintf(file, PATH_MAX + 1, "%s/%s/%s", SHAREDCFG_DIR, group, files[i]);

            if (OS_MD5_File(file, md5sum, OS_TEXT) != 0) {
                merror("Accessing file '%s'", file);
                continue;
            }

            os_realloc(f_sum, (f_size + 2) * sizeof(file_sum *), f_sum);
            *_f_sum = f_sum;
            os_calloc(1, sizeof(file_sum), f_sum[f_size]);
            strncpy(f_sum[f_size]->sum, md5sum, 32);
            os_strdup(files[i], f_sum[f_size]->name);

            if (!logr.nocmerged) {
                MergeAppendFile(merged_tmp, file, NULL, -1);
            }

            f_size++;
        }

        f_sum[f_size] = NULL;

        if (!logr.nocmerged) {
            OS_MoveFile(merged_tmp, merged);
        }

        if (OS_MD5_File(merged, md5sum, OS_TEXT) != 0) {
            if (!logr.nocmerged) {
                merror("Accessing file '%s'", merged);
            }

            f_sum[0]->sum[0] = '\0';
        }

        strncpy(f_sum[0]->sum, md5sum, 32);
        os_strdup(SHAREDCFG_FILENAME, f_sum[0]->name);
    }
}

/* Create the structure with the files and checksums */
static void c_files()
{
    DIR *dp;
    char ** subdir;
    struct dirent *entry;
    unsigned int p_size = 0;
    char path[PATH_MAX + 1];

    mdebug2("Updating shared files sums.");

    /* Lock mutex */
    w_mutex_lock(&files_mutex);

    // Free groups set, and set to NULL
    {
        int i;
        int j;
        file_sum **f_sum;

        if (groups) {
            for (i = 0; groups[i]; i++) {
                f_sum = groups[i]->f_sum;

                for (j = 0; f_sum[j]; j++) {
                    free(f_sum[j]->name);
                    free(f_sum[j]);
                }

                free(f_sum);
                free(groups[i]->group);
            }

            free(groups);
            groups = NULL;
        }
    }

    // Initialize main groups structure
    os_calloc(1, sizeof(group_t *), groups);

    // Scan directory, look for groups (subdirectories)

    dp = opendir(SHAREDCFG_DIR);

    if (!dp) {
        /* Unlock mutex */
        w_mutex_unlock(&files_mutex);

        merror("Opening directory: '%s': %s", SHAREDCFG_DIR, strerror(errno));
        return;
    }

    while (entry = readdir(dp), entry) {
        // Skip "." and ".."
        if (entry->d_name[0] == '.' && (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
            continue;
        }

        if (snprintf(path, PATH_MAX + 1, SHAREDCFG_DIR "/%s", entry->d_name) > PATH_MAX) {
            merror("At c_files(): path too long.");
            break;
        }

        // Try to open directory, avoid TOCTOU hazard

        if (subdir = wreaddir(path), !subdir) {
            if (errno != ENOTDIR) {
                merror("Could not open directory '%s'", path);
            }

            continue;
        }

        os_realloc(groups, (p_size + 2) * sizeof(group_t *), groups);
        os_calloc(1, sizeof(group_t), groups[p_size]);
        groups[p_size]->group = strdup(entry->d_name);
        groups[p_size + 1] = NULL;
        c_group(entry->d_name, subdir, &groups[p_size]->f_sum);
        free_strarray(subdir);
        p_size++;
    }

    /* Unlock mutex */
    w_mutex_unlock(&files_mutex);

    closedir(dp);
    mdebug2("End updating shared files sums.");
}

file_sum** find_sum(const char *group) {
    int i;

    for (i = 0; groups[i]; i++) {
        if (!strcmp(groups[i]->group, group)) {
            return groups[i]->f_sum;
        }
    }

    // Group not found
    return NULL;
}

file_sum ** find_group(const char * file, const char * md5, char group[KEYSIZE]) {
    int i;
    int j;
    file_sum ** f_sum;

    for (i = 0; groups[i]; i++) {
        f_sum = groups[i]->f_sum;

        for (j = 0; f_sum[j]; j++) {
            if (!(strcmp(f_sum[j]->name, file) || strcmp(f_sum[j]->sum, md5))) {
                strncpy(group, groups[i]->group, KEYSIZE);
                return f_sum;
            }
        }
    }

    return NULL;
}

/* Send a file to the agent
 * Returns -1 on error
 */
int send_file_toagent(const char *agent_id, const char *group, const char *name, const char *sum)
{
    int i = 0;
    size_t n = 0;
    char file[OS_SIZE_1024 + 1];
    char buf[OS_SIZE_1024 + 1];
    FILE *fp;

    snprintf(file, OS_SIZE_1024, "%s/%s/%s", SHAREDCFG_DIR, group, name);
    fp = fopen(file, "r");
    if (!fp) {
        merror(FOPEN_ERROR, file, errno, strerror(errno));
        return (-1);
    }

    /* Send the file name first */
    snprintf(buf, OS_SIZE_1024, "%s%s%s %s\n",
             CONTROL_HEADER, FILE_UPDATE_HEADER, sum, name);

    if (send_msg(agent_id, buf, -1) < 0) {
        fclose(fp);
        return (-1);
    }

    /* Send the file contents */
    while ((n = fread(buf, 1, 900, fp)) > 0) {
        buf[n] = '\0';

        if (send_msg(agent_id, buf, -1) < 0) {
            fclose(fp);
            return (-1);
        }

        if (logr.proto[logr.position] == UDP_PROTO) {
            /* Sleep 1 every 30 messages -- no flood */
            if (i > 30) {
                sleep(1);
                i = 0;
            }
            i++;
        }
    }

    /* Send the message to close the file */
    snprintf(buf, OS_SIZE_1024, "%s%s", CONTROL_HEADER, FILE_CLOSE_HEADER);

    if (send_msg(agent_id, buf, -1) < 0) {
        fclose(fp);
        return (-1);
    }

    fclose(fp);

    return (0);
}

/* Read the available control message from the agent */
static void read_controlmsg(const char *agent_id, char *msg)
{
    int i;
    char group[KEYSIZE];
    file_sum **f_sum = NULL;
    os_md5 tmp_sum;
    char *end;
    agent_group *agt_group;

    if (!groups) {
        /* Nothing to share with agent */
        return;
    }

    mdebug2("read_controlmsg(): reading '%s'", msg);

    // Skip agent-info and label data

    if (msg = strchr(msg, '\n'), !msg) {
        merror("Invalid message from agent ID '%s' (strchr \\n)", agent_id);
        return;
    }

    for (msg++; (*msg == '\"' || *msg == '!') && (end = strchr(msg, '\n')); msg = end + 1);


    // Get agent group

    if (agt_group = w_parser_get_agent(agent_id), agt_group) {
        strncpy(group, agt_group->group, KEYSIZE);
        group[KEYSIZE - 1] = '\0';
        set_agent_group(agent_id, group);
    } else if (get_agent_group(agent_id, group, KEYSIZE) < 0) {
        group[0] = '\0';
    }

    /* Lock mutex */
    w_mutex_lock(&files_mutex);

    // If group was got, get file sum array

    if (group[0]) {
        if (f_sum = find_sum(group), !f_sum) {
            /* Unlock mutex */
            w_mutex_unlock(&files_mutex);

            merror("No such group '%s' for agent '%s'", group, agent_id);
            return;
        }
    }

    /* Parse message */
    while (*msg != '\0') {
        char *md5;
        char *file;

        md5 = msg;
        file = msg;

        msg = strchr(msg, '\n');
        if (!msg) {
            merror("Invalid message from agent ID '%s' (strchr \\n)", agent_id);
            break;
        }

        *msg = '\0';
        msg++;

        // Skip labeled data

        if (*md5 == '\"' || *md5 == '!') {
            continue;
        }

        file = strchr(file, ' ');
        if (!file) {
            merror("Invalid message from agent ID '%s' (strchr ' ')", agent_id);
            break;
        }

        *file = '\0';
        file++;

        // If group was not got, guess it by matching sum

        if (!f_sum) {
            if (f_sum = find_group(file, md5, group), !f_sum) {
                // If the group could not be guessed, set to "default"
                strncpy(group, "default", KEYSIZE);

                if (f_sum = find_sum(group), !f_sum) {
                    /* Unlock mutex */
                    w_mutex_unlock(&files_mutex);

                    merror("No such group '%s' for agent '%s'", group, agent_id);
                    return;
                }
            }

            set_agent_group(agent_id, group);
        }

        /* New agents only have merged.mg */
        if (strcmp(file, SHAREDCFG_FILENAME) == 0) {
            for (i = 0; f_sum[i]; i++) {
                f_sum[i]->mark = 0;
            }

            // Copy sum before unlock mutex
            memcpy(tmp_sum, f_sum[0]->sum, sizeof(tmp_sum));

            /* Unlock mutex */
            w_mutex_unlock(&files_mutex);

            if (tmp_sum[0] && strcmp(tmp_sum, md5) != 0) {
                mdebug1("Sending file '%s/%s' to agent '%s'.", group, SHAREDCFG_FILENAME, agent_id);

                if (send_file_toagent(agent_id, group, SHAREDCFG_FILENAME, tmp_sum) < 0) {
                    merror(SHARED_ERROR, SHAREDCFG_FILENAME, agent_id);
                }

                mdebug2("End sending file '%s/%s' to agent '%s'.", group, SHAREDCFG_FILENAME, agent_id);
            }

            return;
        }

        for (i = 1; f_sum[i]; i++) {
            if (strcmp(f_sum[i]->name, file) != 0) {
                continue;
            }

            else if (strcmp(f_sum[i]->sum, md5) != 0) {
                f_sum[i]->mark = 1;    /* Marked to update */
            }

            else {
                f_sum[i]->mark = 2;
            }
            break;
        }
    }

    /* Update each marked file */
    for (i = 1; f_sum && f_sum[i]; i++) {
        if ((f_sum[i]->mark == 1) ||
                (f_sum[i]->mark == 0)) {

            mdebug1("Sending file '%s/%s' to agent '%s'.", group, f_sum[i]->name, agent_id);
            if (send_file_toagent(agent_id, group, f_sum[i]->name, f_sum[i]->sum) < 0) {
                merror(SHARED_ERROR, f_sum[i]->name, agent_id);
            }
        }

        f_sum[i]->mark = 0;
    }

    /* Unlock mutex */
    w_mutex_unlock(&files_mutex);

    return;
}

/* Wait for new messages to read
 * The messages will be sent using save_controlmsg
 */
void *wait_for_msgs(__attribute__((unused)) void *none)
{
    char msg[OS_SIZE_1024 + 2];
    char agent_id[9];
    pending_data_t *data;

    /* Initialize the memory */
    memset(msg, '\0', OS_SIZE_1024 + 2);

    /* Should never leave this loop */
    while (1) {
        /* Lock mutex */
        w_mutex_lock(&lastmsg_mutex);

        /* If no agent changed, wait for signal */
        while (empty(queue_i, queue_j)) {
            w_cond_wait(&awake_mutex, &lastmsg_mutex);
        }

        /* Pop data from queue */
        if ((data = OSHash_Get(pending_data, pending_queue[queue_j]))) {
            strncpy(agent_id, pending_queue[queue_j], 8);
            strncpy(msg, data->message, OS_SIZE_1024);
        } else {
            merror("Couldn't get pending data from hash table for agent ID '%s'.", pending_queue[queue_j]);
            *agent_id = '\0';
            *msg = '\0';
        }

        forward(queue_j);

        /* Unlock mutex */
        w_mutex_unlock(&lastmsg_mutex);

        if (*agent_id) {
            read_controlmsg(agent_id, msg);
        }

        // Mark message as dispatched
        w_mutex_lock(&lastmsg_mutex);
        data->changed = 0;
        w_mutex_unlock(&lastmsg_mutex);
    }

    return (NULL);
}
/* Update shared files */
void *update_shared_files(__attribute__((unused)) void *none) {
    const int INTERVAL = getDefine_Int("remoted", "shared_reload", 1, 18000);
    poll_interval_time = INTERVAL;

    while (1) {
        time_t _ctime = time(0);

        /* Every INTERVAL seconds, re-read the files
         * If something changed, notify all agents
         */

        if ((_ctime - _stime) >= INTERVAL) {
            // Check if the yaml file has changed and reload it
            if(w_yaml_file_has_changed()){
                w_yaml_file_update_structs();
                w_yaml_create_groups();
            }

            c_files();
            _stime = _ctime;
        }

        sleep(1);
    }

    return NULL;
}

/* Should be called before anything here */
void manager_init()
{
    _stime = time(0);
    mdebug1("Running manager_init");
    c_files();
    w_yaml_create_groups();
    memset(pending_queue, 0, MAX_AGENTS * 9);
    pending_data = OSHash_Create();
}
