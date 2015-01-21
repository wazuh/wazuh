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
static void read_controlmsg(unsigned int agentid, char *msg);
static int send_file_toagent(unsigned int agentid, const char *name, const char *sum);
static void f_files(void);
static void c_files(void);

/* Global vars */
static file_sum **f_sum;
static time_t _ctime;
static time_t _stime;

/* For the last message tracking */
static char *_msg[MAX_AGENTS + 1];
static char *_keep_alive[MAX_AGENTS + 1];
static int _changed[MAX_AGENTS + 1];
static int modified_agentid;

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

    /* Reply to the agent */
    snprintf(msg_ack, OS_FLSIZE, "%s%s", CONTROL_HEADER, HC_ACK);
    send_msg(agentid, msg_ack);

    /* Check if there is a keep alive already for this agent */
    if (_keep_alive[agentid] && _msg[agentid] &&
            (strcmp(_msg[agentid], r_msg) == 0)) {
        utimes(_keep_alive[agentid], NULL);
    }

    else if (strcmp(r_msg, HC_STARTUP) == 0) {
        return;
    }

    else {
        FILE *fp;
        char *uname = r_msg;
        char *random_leftovers;

        /* Lock mutex */
        if (pthread_mutex_lock(&lastmsg_mutex) != 0) {
            merror(MUTEX_ERROR, ARGV0);
            return;
        }

        /* Update rmsg */
        if (_msg[agentid]) {
            free(_msg[agentid]);
        }
        os_strdup(r_msg, _msg[agentid]);

        /* Unlock mutex */
        if (pthread_mutex_unlock(&lastmsg_mutex) != 0) {
            merror(MUTEX_ERROR, ARGV0);
            return;
        }

        r_msg = strchr(r_msg, '\n');
        if (!r_msg) {
            merror("%s: WARN: Invalid message from agent id: '%d'(uname)",
                   ARGV0,
                   agentid);
            return;
        }

        *r_msg = '\0';
        random_leftovers = strchr(r_msg, '\n');
        if (random_leftovers) {
            *random_leftovers = '\0';
        }

        /* Update the keep alive */
        if (!_keep_alive[agentid]) {
            char agent_file[OS_SIZE_1024 + 1];
            agent_file[OS_SIZE_1024] = '\0';

            /* Write to the agent file */
            snprintf(agent_file, OS_SIZE_1024, "%s/%s-%s",
                     AGENTINFO_DIR,
                     keys.keyentries[agentid]->name,
                     keys.keyentries[agentid]->ip->ip);
            os_strdup(agent_file, _keep_alive[agentid]);
        }

        /* Write to the file */
        fp = fopen(_keep_alive[agentid], "w");
        if (fp) {
            fprintf(fp, "%s\n", uname);
            fclose(fp);
        }
    }

    /* Lock now to notify of change */
    if (pthread_mutex_lock(&lastmsg_mutex) != 0) {
        merror(MUTEX_ERROR, ARGV0);
        return;
    }

    /* Assign new values */
    _changed[agentid] = 1;
    modified_agentid = (int) agentid;

    /* Signal that new data is available */
    pthread_cond_signal(&awake_mutex);

    /* Unlock mutex */
    if (pthread_mutex_unlock(&lastmsg_mutex) != 0) {
        merror(MUTEX_ERROR, ARGV0);
        return;
    }

    return;
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

        if (OS_MD5_File(tmp_dir, md5sum) != 0) {
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

    if (OS_MD5_File(SHAREDCFG_FILE, md5sum) != 0) {
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
static int send_file_toagent(unsigned int agentid, const char *name, const char *sum)
{
    int i = 0;
    size_t n = 0;
    char file[OS_SIZE_1024 + 1];
    char buf[OS_SIZE_1024 + 1];
    FILE *fp;

    snprintf(file, OS_SIZE_1024, "%s/%s", SHAREDCFG_DIR, name);
    fp = fopen(file, "r");
    if (!fp) {
        merror(FOPEN_ERROR, ARGV0, file, errno, strerror(errno));
        return (-1);
    }

    /* Send the file name first */
    snprintf(buf, OS_SIZE_1024, "%s%s%s %s\n",
             CONTROL_HEADER, FILE_UPDATE_HEADER, sum, name);
    if (send_msg(agentid, buf) == -1) {
        merror(SEC_ERROR, ARGV0);
        fclose(fp);
        return (-1);
    }

    /* Send the file contents */
    while ((n = fread(buf, 1, 900, fp)) > 0) {
        buf[n] = '\0';

        if (send_msg(agentid, buf) == -1) {
            merror(SEC_ERROR, ARGV0);
            fclose(fp);
            return (-1);
        }

        /* Sleep 1 every 30 messages -- no flood */
        if (i > 30) {
            sleep(1);
            i = 0;
        }
        i++;
    }

    /* Send the message to close the file */
    snprintf(buf, OS_SIZE_1024, "%s%s", CONTROL_HEADER, FILE_CLOSE_HEADER);
    if (send_msg(agentid, buf) == -1) {
        merror(SEC_ERROR, ARGV0);
        fclose(fp);
        return (-1);
    }

    fclose(fp);

    return (0);
}

/* Read the available control message from the agent */
static void read_controlmsg(unsigned int agentid, char *msg)
{
    int i;

    /* Remove uname */
    msg = strchr(msg, '\n');
    if (!msg) {
        merror("%s: Invalid message from '%d' (uname)", ARGV0, agentid);
        return;
    }

    *msg = '\0';
    msg++;

    if (!f_sum) {
        /* Nothing to share with agent */
        return;
    }

    /* Parse message */
    while (*msg != '\0') {
        char *md5;
        char *file;

        md5 = msg;
        file = msg;

        msg = strchr(msg, '\n');
        if (!msg) {
            merror("%s: Invalid message from '%s' (strchr \\n)",
                   ARGV0,
                   keys.keyentries[agentid]->ip->ip);
            break;
        }

        *msg = '\0';
        msg++;

        file = strchr(file, ' ');
        if (!file) {
            merror("%s: Invalid message from '%s' (strchr ' ')",
                   ARGV0,
                   keys.keyentries[agentid]->ip->ip);
            break;
        }

        *file = '\0';
        file++;

        /* New agents only have merged.mg */
        if (strcmp(file, SHAREDCFG_FILENAME) == 0) {
            if (strcmp(f_sum[0]->sum, md5) != 0) {
                debug1("%s: DEBUG Sending file '%s' to agent.", ARGV0,
                       f_sum[0]->name);
                if (send_file_toagent(agentid, f_sum[0]->name, f_sum[0]->sum) < 0) {
                    merror("%s: ERROR: Unable to send file '%s' to agent.",
                           ARGV0,
                           f_sum[0]->name);
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
            if (send_file_toagent(agentid, f_sum[i]->name, f_sum[i]->sum) < 0) {
                merror("%s: Error sending file '%s' to agent.",
                       ARGV0,
                       f_sum[i]->name);
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
    int id;
    char msg[OS_SIZE_1024 + 2];

    /* Initialize the memory */
    memset(msg, '\0', OS_SIZE_1024 + 2);

    /* Should never leave this loop */
    while (1) {
        unsigned int i;
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
        if (modified_agentid == -1) {
            pthread_cond_wait(&awake_mutex, &lastmsg_mutex);
        }

        /* Unlock mutex */
        if (pthread_mutex_unlock(&lastmsg_mutex) != 0) {
            merror(MUTEX_ERROR, ARGV0);
            return (NULL);
        }

        /* Check if any agent is ready */
        for (i = 0; i < keys.keysize; i++) {
            /* If agent wasn't changed, try next */
            if (_changed[i] != 1) {
                continue;
            }

            id = 0;

            /* Lock mutex */
            if (pthread_mutex_lock(&lastmsg_mutex) != 0) {
                merror(MUTEX_ERROR, ARGV0);
                break;
            }

            if (_msg[i]) {
                /* Copy the message to be analyzed */
                strncpy(msg, _msg[i], OS_SIZE_1024);
                _changed[i] = 0;

                if (modified_agentid >= (int) i) {
                    modified_agentid = -1;
                }

                id = 1;
            }

            /* Unlock mutex */
            if (pthread_mutex_unlock(&lastmsg_mutex) != 0) {
                merror(MUTEX_ERROR, ARGV0);
                break;
            }

            if (id) {
                read_controlmsg(i, msg);
            }
        }
    }

    return (NULL);
}

/* Should be called before anything here */
void manager_init(int isUpdate)
{
    int i;

    _stime = time(0);

    f_files();
    c_files();

    debug1("%s: DEBUG: Running manager_init", ARGV0);

    for (i = 0; i < MAX_AGENTS + 1; i++) {
        _keep_alive[i] = NULL;
        _msg[i] = NULL;
        _changed[i] = 0;
    }

    /* Initialize mutexes */
    if (isUpdate == 0) {
        pthread_mutex_init(&lastmsg_mutex, NULL);
        pthread_cond_init(&awake_mutex, NULL);
    }

    modified_agentid = -1;

    return;
}

