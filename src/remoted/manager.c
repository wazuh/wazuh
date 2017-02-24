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
#include <pthread.h>

/* Internal structures */
typedef struct _file_sum {
    int mark;
    char *name;
    os_md5 sum;
} file_sum;

/* Internal functions prototypes */
static void read_controlmsg(const char *agent_id, char *msg);
static int send_file_toagent(const char *agent_id, const char *name, const char *sum);
static void f_files(void);
static void c_files(void);

/* Global vars */
static file_sum **f_sum;
static time_t _ctime;
static time_t _stime;

/* For the last message tracking */
static char pending_queue[MAX_AGENTS][9];
static volatile int queue_i = 0;
static volatile int queue_j = 0;
OSHash *pending_data;

/* pthread mutex variables */
static pthread_mutex_t lastmsg_mutex;
static pthread_cond_t awake_mutex;


/* Save a control message received from an agent
 * read_contromsg (other thread) is going to deal with it
 * (only if message changed)
 */
void save_controlmsg(unsigned int agentid, char *r_msg)
{
    char msg_ack[OS_FLSIZE + 1];
    char *begin_shared;
    char *end;
    pending_data_t *data;

    /* Reply to the agent */
    snprintf(msg_ack, OS_FLSIZE, "%s%s", CONTROL_HEADER, HC_ACK);

    send_msg(agentid, msg_ack);

    /* Check if there is a keep alive already for this agent */
    if ((data = OSHash_Get(pending_data, keys.keyentries[agentid]->id)) &&
        data->message && strcmp(data->message, r_msg) == 0) {
        utimes(data->keep_alive, NULL);
    } else if (strcmp(r_msg, HC_STARTUP) == 0) {
        debug1("%s: DEBUG: Agent %s sent HC_STARTUP from %s.", ARGV0, keys.keyentries[agentid]->name, inet_ntoa(keys.keyentries[agentid]->peer_info.sin_addr));
        return;
    } else {
        FILE *fp;
        char *uname = r_msg;

        /* Clean uname and shared files (remove random string) */

        if ((r_msg = strchr(r_msg, '\n'))) {
            /* Forward to shared files sums (pass labeled data) */
            for (r_msg++; (*r_msg == '\"' || *r_msg == '!') && (end = strchr(r_msg, '\n')); r_msg = end + 1);
            /* Forward to random string (pass shared files) */
            for (begin_shared = r_msg; (end = strchr(r_msg, '\n')); r_msg = end + 1);
            *r_msg = '\0';
        } else {
            merror("%s: WARN: Invalid message from agent id: '%d'(uname)",
                   ARGV0,
                   agentid);
            return;
        }

        /* Lock mutex */
        if (pthread_mutex_lock(&lastmsg_mutex) != 0) {
            merror(MUTEX_ERROR, ARGV0);
            return;
        }

        if (data || (data = OSHash_Get(pending_data, keys.keyentries[agentid]->id))) {
            free(data->message);
        } else {
            os_calloc(1, sizeof(pending_data_t), data);

            if (OSHash_Add(pending_data, keys.keyentries[agentid]->id, data) != 2) {
                merror("%s: ERROR: Couldn't add pending data into hash table.", ARGV0);

                /* Unlock mutex */
                if (pthread_mutex_unlock(&lastmsg_mutex) != 0) {
                    merror(MUTEX_ERROR, ARGV0);
                }

                free(data);
                return;
            }
        }

        /* Update message */
        debug2("%s: DEBUG: save_controlmsg(): inserting '%s'", ARGV0, uname);
        os_strdup(uname, data->message);

        /* Mark data as changed and insert into queue */

        if (!data->changed) {
            if (full(queue_i, queue_j)) {
                merror("%s: ERROR: Pending message queue full.", ARGV0);
            } else {
                strncpy(pending_queue[queue_i], keys.keyentries[agentid]->id, 8);
                forward(queue_i);

                /* Signal that new data is available */
                pthread_cond_signal(&awake_mutex);
            }

            data->changed = 1;
        }

        /* Unlock mutex */
        if (pthread_mutex_unlock(&lastmsg_mutex) != 0) {
            merror(MUTEX_ERROR, ARGV0);

            return;
        }

        /* This is not critical section since is not used by another thread */

        if (!data->keep_alive) {
            char agent_file[PATH_MAX];

            /* Write to the agent file */
            snprintf(agent_file, PATH_MAX, "%s/%s-%s",
                     AGENTINFO_DIR,
                     keys.keyentries[agentid]->name,
                     keys.keyentries[agentid]->ip->ip);

            os_strdup(agent_file, data->keep_alive);
        }

        /* Write uname to the file */

        if ((fp = fopen(data->keep_alive, "w"))) {
            *begin_shared = '\0';
            fprintf(fp, "%s\n", uname);
            fclose(fp);
        } else {
            merror(FOPEN_ERROR, ARGV0, data->keep_alive, errno, strerror(errno));
        }
    }
}

/* Free the files memory */
static void f_files()
{
    int i;
    if (!f_sum) {
        return;
    }
    for (i = 0;; i++) {
        if (f_sum[i] == NULL) {
            break;
        }

        if (f_sum[i]->name) {
            free(f_sum[i]->name);
        }

        free(f_sum[i]);
        f_sum[i] = NULL;
    }

    free(f_sum);
    f_sum = NULL;
}

/* Create the structure with the files and checksums */
static void c_files()
{
    DIR *dp;
    struct dirent *entry;
    os_md5 md5sum;
    unsigned int f_size = 0;

    f_sum = NULL;

    /* Create merged file */
    os_realloc(f_sum, (f_size + 2) * sizeof(file_sum *), f_sum);
    os_calloc(1, sizeof(file_sum), f_sum[f_size]);
    f_sum[f_size]->mark = 0;
    f_sum[f_size]->name = NULL;
    f_sum[f_size]->sum[0] = '\0';
    MergeAppendFile(SHAREDCFG_FILE, NULL);
    f_size++;

    /* Open directory */
    dp = opendir(SHAREDCFG_DIR);
    if (!dp) {
        merror("%s: Error opening directory: '%s': %s ",
               ARGV0,
               SHAREDCFG_DIR,
               strerror(errno));
        return;
    }

    /* Read directory */
    while ((entry = readdir(dp)) != NULL) {
        char tmp_dir[512];

        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        snprintf(tmp_dir, 512, "%s/%s", SHAREDCFG_DIR, entry->d_name);

        /* Leave the shared config file for later */
        if (strcmp(tmp_dir, SHAREDCFG_FILE) == 0) {
            continue;
        }

        if (OS_MD5_File(tmp_dir, md5sum, OS_TEXT) != 0) {
            merror("%s: Error accessing file '%s'", ARGV0, tmp_dir);
            continue;
        }

        f_sum = (file_sum **)realloc(f_sum, (f_size + 2) * sizeof(file_sum *));
        if (!f_sum) {
            ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
        }

        f_sum[f_size] = (file_sum *) calloc(1, sizeof(file_sum));
        if (!f_sum[f_size]) {
            ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
        }

        strncpy(f_sum[f_size]->sum, md5sum, 32);
        os_strdup(entry->d_name, f_sum[f_size]->name);
        f_sum[f_size]->mark = 0;

        MergeAppendFile(SHAREDCFG_FILE, tmp_dir);
        f_size++;
    }

    if (f_sum != NULL) {
        f_sum[f_size] = NULL;
    }

    closedir(dp);

    if (OS_MD5_File(SHAREDCFG_FILE, md5sum, OS_TEXT) != 0) {
        merror("%s: Error accessing file '%s'", ARGV0, SHAREDCFG_FILE);
        f_sum[0]->sum[0] = '\0';
    }
    strncpy(f_sum[0]->sum, md5sum, 32);

    os_strdup(SHAREDCFG_FILENAME, f_sum[0]->name);

    return;
}

/* Send a file to the agent
 * Returns -1 on error
 */
static int send_file_toagent(const char *agent_id, const char *name, const char *sum)
{
    int i = 0;
    int key_id;
    size_t n = 0;
    char file[OS_SIZE_1024 + 1];
    char buf[OS_SIZE_1024 + 1];
    FILE *fp;

    key_lock();
    key_id = OS_IsAllowedID(&keys, agent_id);
    key_unlock();

    if (key_id < 0) {
        merror("%s: ERROR: Couldn't get key for agent ID '%s'.", ARGV0, agent_id);
        return -1;
    }

    snprintf(file, OS_SIZE_1024, "%s/%s", SHAREDCFG_DIR, name);
    fp = fopen(file, "r");
    if (!fp) {
        merror(FOPEN_ERROR, ARGV0, file, errno, strerror(errno));
        return (-1);
    }

    /* Send the file name first */
    snprintf(buf, OS_SIZE_1024, "%s%s%s %s\n",
             CONTROL_HEADER, FILE_UPDATE_HEADER, sum, name);

    key_lock();
    if (send_msg(key_id, buf) == -1) {
        key_unlock();
        merror(SEC_ERROR, ARGV0);
        fclose(fp);
        return (-1);
    }

    key_unlock();

    /* Send the file contents */
    while ((n = fread(buf, 1, 900, fp)) > 0) {
        buf[n] = '\0';

        key_lock();

        if (send_msg(key_id, buf) == -1) {
            key_unlock();
            merror(SEC_ERROR, ARGV0);
            fclose(fp);
            return (-1);
        }

        key_unlock();

        /* Sleep 1 every 30 messages -- no flood */
        if (i > 30) {
            sleep(1);
            i = 0;
        }
        i++;
    }

    /* Send the message to close the file */
    snprintf(buf, OS_SIZE_1024, "%s%s", CONTROL_HEADER, FILE_CLOSE_HEADER);
    key_lock();

    if (send_msg(key_id, buf) == -1) {
        key_unlock();
        merror(SEC_ERROR, ARGV0);
        fclose(fp);
        return (-1);
    }

    key_unlock();
    fclose(fp);

    return (0);
}

/* Read the available control message from the agent */
static void read_controlmsg(const char *agent_id, char *msg)
{
    int i;

    if (!f_sum) {
        /* Nothing to share with agent */
        return;
    }

    debug2("%s: DEBUG: read_controlmsg(): reading '%s'", ARGV0, msg);

    /* Parse message */
    while (*msg != '\0') {
        char *md5;
        char *file;

        md5 = msg;
        file = msg;

        msg = strchr(msg, '\n');
        if (!msg) {
            merror("%s: Invalid message from agent ID '%s' (strchr \\n)",
                   ARGV0,
                   agent_id);
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
            merror("%s: Invalid message from agent ID '%s' (strchr ' ')",
                   ARGV0,
                   agent_id);
            break;
        }

        *file = '\0';
        file++;

        /* New agents only have merged.mg */
        if (strcmp(file, SHAREDCFG_FILENAME) == 0) {
            if (strcmp(f_sum[0]->sum, md5) != 0) {
                debug1("%s: DEBUG Sending file '%s' to agent.", ARGV0,
                       f_sum[0]->name);
                if (send_file_toagent(agent_id, f_sum[0]->name, f_sum[0]->sum) < 0) {
                    merror(SHARED_ERROR, ARGV0, f_sum[0]->name, agent_id);
                }
            }

            i = 0;
            while (f_sum[i]) {
                f_sum[i]->mark = 0;
                i++;
            }

            return;
        }

        for (i = 1;; i++) {
            if (f_sum[i] == NULL) {
                break;
            }

            else if (strcmp(f_sum[i]->name, file) != 0) {
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
    for (i = 1;; i++) {
        if (f_sum[i] == NULL) {
            break;
        }

        if ((f_sum[i]->mark == 1) ||
                (f_sum[i]->mark == 0)) {

            debug1("%s: Sending file '%s' to agent.", ARGV0, f_sum[i]->name);
            if (send_file_toagent(agent_id, f_sum[i]->name, f_sum[i]->sum) < 0) {
                merror(SHARED_ERROR, ARGV0, f_sum[i]->name, agent_id);
            }
        }

        f_sum[i]->mark = 0;
    }

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
        /* Every NOTIFY * 30 minutes, re-read the files
         * If something changed, notify all agents
         */
        _ctime = time(0);
        if ((_ctime - _stime) > (NOTIFY_TIME * 30)) {
            f_files();
            c_files();

            _stime = _ctime;
        }

        /* Lock mutex */
        if (pthread_mutex_lock(&lastmsg_mutex) != 0) {
            merror(MUTEX_ERROR, ARGV0);
            return (NULL);
        }

        /* If no agent changed, wait for signal */
        while (empty(queue_i, queue_j)) {
            pthread_cond_wait(&awake_mutex, &lastmsg_mutex);
        }

        /* Pop data from queue */
        if ((data = OSHash_Get(pending_data, pending_queue[queue_j]))) {
            strncpy(agent_id, pending_queue[queue_j], 8);
            strncpy(msg, data->message, OS_SIZE_1024);
            data->changed = 0;
        } else {
            merror("%s: CRITICAL: Couldn't get pending data from hash table for agent ID '%s'.", ARGV0, pending_queue[queue_j]);
            *agent_id = '\0';
            *msg = '\0';
        }

        forward(queue_j);

        /* Unlock mutex */
        if (pthread_mutex_unlock(&lastmsg_mutex) != 0) {
            merror(MUTEX_ERROR, ARGV0);
            break;
        }

        if (*agent_id) {
            read_controlmsg(agent_id, msg);
        }
    }

    return (NULL);
}

/* Should be called before anything here */
void manager_init(int isUpdate)
{
    _stime = time(0);
    queue_i = 0;
    queue_j = 0;

    f_files();
    c_files();

    debug1("%s: DEBUG: Running manager_init", ARGV0);

    memset(pending_queue, 0, MAX_AGENTS * 9);
    pending_data = OSHash_Create();

    /* Initialize mutexes */
    if (isUpdate == 0) {
        pthread_mutex_init(&lastmsg_mutex, NULL);
        pthread_cond_init(&awake_mutex, NULL);
    }
}
