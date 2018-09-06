/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Syscheck decoder */

#include "eventinfo.h"
#include "os_regex/os_regex.h"
#include "config.h"
#include "alerts/alerts.h"
#include "decoder.h"
#include "syscheck_op.h"
#include "wazuh_modules/wmodules.h"
#include "os_net/os_net.h"

// Add events into sqlite DB for FIM
static int fim_db_search (char *f_name, char *c_sum, char *w_sum, Eventinfo *lf);
// Send msg to wazuh-db
static int send_query_wazuhdb (char *wazuhdb_query, char **output);
// Build FIM alert
static int fim_alert (char *f_name, sk_sum_t *oldsum, sk_sum_t *newsum, Eventinfo *lf);
// Build fileds whodata alert
static void InsertWhodata (const sk_sum_t * sum);
// Compare the first common fields between sum strings
static int SumCompare (const char *s1, const char *s2);
// Clean sdb memory
static void fim_clean_sdb_mem ();
// Check for exceed num of changes
static int fim_check_changes (int saved_frequency, long saved_time, Eventinfo *lf);
// Send control message to wazuhdb
static int fim_control_msg (char *key, time_t value, Eventinfo *lf);
//Update field date at last event generated
int fim_update_date (char *file, Eventinfo *lf);
// Clean for old entries
int fim_database_clean(Eventinfo *lf);


// Initialize the necessary information to process the syscheck information
void SyscheckInit()
{
    int i = 0;

    sdb.db_err = 0;

    for (; i <= MAX_AGENTS; i++) {
        sdb.agent_ips[i] = NULL;
        sdb.agent_fps[i] = NULL;
        sdb.agent_cp[i][0] = '0';
    }

    // Clear db memory
    fim_clean_sdb_mem();

    // Create decoder
    os_calloc(1, sizeof(OSDecoderInfo), sdb.syscheck_dec);
    sdb.syscheck_dec->id = getDecoderfromlist(SYSCHECK_MOD);
    sdb.syscheck_dec->name = SYSCHECK_MOD;
    sdb.syscheck_dec->type = OSSEC_RL;
    sdb.syscheck_dec->fts = 0;

    os_calloc(Config.decoder_order_size, sizeof(char *), sdb.syscheck_dec->fields);
    sdb.syscheck_dec->fields[SK_FILE] = "file";
    sdb.syscheck_dec->fields[SK_SIZE] = "size";
    sdb.syscheck_dec->fields[SK_PERM] = "perm";
    sdb.syscheck_dec->fields[SK_UID] = "uid";
    sdb.syscheck_dec->fields[SK_GID] = "gid";
    sdb.syscheck_dec->fields[SK_MD5] = "md5";
    sdb.syscheck_dec->fields[SK_SHA1] = "sha1";
    sdb.syscheck_dec->fields[SK_SHA256] = "sha256";
    sdb.syscheck_dec->fields[SK_UNAME] = "uname";
    sdb.syscheck_dec->fields[SK_GNAME] = "gname";
    sdb.syscheck_dec->fields[SK_INODE] = "inode";
    sdb.syscheck_dec->fields[SK_MTIME] = "mtime";
    sdb.syscheck_dec->fields[SK_CHFIELDS] = "changed_fields";

    sdb.syscheck_dec->fields[SK_USER_ID] = "user_id";
    sdb.syscheck_dec->fields[SK_USER_NAME] = "user_name";
    sdb.syscheck_dec->fields[SK_GROUP_ID] = "group_id";
    sdb.syscheck_dec->fields[SK_GROUP_NAME] = "group_name";
    sdb.syscheck_dec->fields[SK_PROC_NAME] = "process_name";
    sdb.syscheck_dec->fields[SK_AUDIT_ID] = "audit_uid";
    sdb.syscheck_dec->fields[SK_AUDIT_NAME] = "audit_name";
    sdb.syscheck_dec->fields[SK_EFFECTIVE_UID] = "effective_uid";
    sdb.syscheck_dec->fields[SK_EFFECTIVE_NAME] = "effective_name";
    sdb.syscheck_dec->fields[SK_PPID] = "ppid";
    sdb.syscheck_dec->fields[SK_PROC_ID] = "process_id";

    sdb.id1 = getDecoderfromlist(SYSCHECK_MOD);
    sdb.idn = getDecoderfromlist(SYSCHECK_NEW);
    sdb.idd = getDecoderfromlist(SYSCHECK_DEL);

    mdebug1("SyscheckInit completed.");
}


/* Special decoder for syscheck
 * Not using the default decoding lib for simplicity
 * and to be less resource intensive
 */
int DecodeSyscheck(Eventinfo *lf)
{
    char *c_sum;
    char *w_sum;
    char *f_name;

    // Clean sdb memory
    fim_clean_sdb_mem();
    minfo("~~~~ DecodeSyscheck");

    /* Every syscheck message must be in the following format:
     * checksum filename
     * or
     * checksum!whodatasum filename
     * or
     * checksum!whodatasum filename\nextradata
     */
    f_name = wstr_chr(lf->log, ' ');
    if (f_name == NULL) {
        mdebug2("Saved control value for syscheck: '%s'", lf->log);
        if (fim_control_msg(lf->log, lf->time.tv_sec, lf) > 0) {
            return(0);
        } else {
            merror(SK_INV_MSG);
            return (-1);
        }
    }

    // Zero to get the check sum
    *f_name = '\0';
    f_name++;

    //Change in Windows paths all slashes for backslashes for compatibility agent<3.4 with manager>=3.4
    normalize_path(f_name);

    // Get diff
    lf->data = strchr(f_name, '\n');
    if (lf->data) {
        *lf->data = '\0';
        lf->data++;
    } else {
        lf->data = NULL;
    }

    // Check if file is supposed to be ignored
    if (Config.syscheck_ignore) {
        char **ff_ig = Config.syscheck_ignore;

        while (*ff_ig) {
            if (strncasecmp(*ff_ig, f_name, strlen(*ff_ig)) == 0) {
                lf->data = NULL;
                return (0);
            }

            ff_ig++;
        }
    }

    // Checksum is at the beginning of the log
    c_sum = lf->log;

    // Get w_sum
    if (w_sum = strchr(c_sum, '!'), w_sum) {
        *(w_sum++) = '\0';
    }

    // Search for file changes
    return (fim_db_search(f_name, c_sum, w_sum, lf));
}


int fim_db_search(char *f_name, char *c_sum, char *w_sum, Eventinfo *lf) {
    int decode_newsum = 0;
    int db_result = 0;
    int changes = 0;
    char *wazuhdb_query = NULL;
    char *new_check_sum = NULL;
    char *old_check_sum = NULL;
    char *response = NULL;
    char *check_sum = NULL;
    sk_sum_t oldsum = { .size = NULL };
    sk_sum_t newsum = { .size = NULL };

    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);
    os_strdup(c_sum, new_check_sum);

    snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck load %s", lf->agent_id, f_name);
    //snprintf(wazuhdb_query, OS_SIZE_6144 - 1, "agent %s syscheck save %s %s", lf->agent_id, c_sum, f_name);
    //snprintf(wazuhdb_query, OS_SIZE_6144 - 1, "agent %s syscheck save %s %s", lf->agent_id, c_sum, f_name);

    db_result = send_query_wazuhdb(wazuhdb_query, &response);

    // Fail trying load info from DDBB
    if (db_result != 0) {
        merror("at fim_db_search(): Bad load query");
        lf->data = NULL;
        free(new_check_sum);
        free(wazuhdb_query);
        free(response);
        return (-1);
    }
    check_sum = strchr(response, ' ');
    *(check_sum++) = '\0';
    os_strdup(check_sum, old_check_sum);
    mdebug2("Old checksum '%s'", old_check_sum);
    mdebug2("New checksum '%s'", new_check_sum);

    // Checksum match, we can just return and keep going
    if (SumCompare(old_check_sum, new_check_sum) == 0) {
        mdebug1("Alert discarded '%s' same check_sum", f_name);
        lf->data = NULL;
        fim_update_date (f_name, lf);
        free(wazuhdb_query);
        free(new_check_sum);
        free(old_check_sum);
        free(response);
        return (0);
    }

    if (decode_newsum = sk_decode_sum(&newsum, c_sum, w_sum), decode_newsum != -1) {
        InsertWhodata(&newsum);
    }

    wazuhdb_query[0] = '\0';
    switch (decode_newsum) {
        case 1: // File deleted
            lf->event_type = FIM_DELETED;

            snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck delete %s",
                    lf->agent_id,
                    f_name
            );
            free(response);
            response = NULL;
            db_result = send_query_wazuhdb(wazuhdb_query, &response);

            if (db_result != 0) {
                merror("at fim_db_search(): Bad delete query");
                sk_sum_clean(&newsum);
                free(wazuhdb_query);
                free(new_check_sum);
                free(old_check_sum);
                free(response);
                return (-1);
            }

            mdebug1("File %s deleted from FIM DDBB", f_name);

            break;
        case 0:
            if (*old_check_sum) {
                // File modified
                lf->event_type = FIM_MODIFIED;
                sk_decode_sum(&oldsum, old_check_sum, NULL);
                changes = fim_check_changes(oldsum.changes, oldsum.date_alert, lf);

                // Alert discarded, frequency exceeded
                if (changes == -1) {
                    mdebug1("Alert discarded '%s' frequency exceeded", f_name);
                    lf->data = NULL;
                    free(wazuhdb_query);
                    free(new_check_sum);
                    free(old_check_sum);
                    free(response);
                    return (0);
                }
            } else {
                // File added
                lf->event_type = FIM_ADDED;
            }

            snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck save file %s:%d %s",
                    lf->agent_id,
                    new_check_sum,
                    changes,
                    f_name
            );
            free(response);
            response = NULL;
            minfo("~~~~ sending to wdb '%s'", wazuhdb_query);
            db_result = send_query_wazuhdb(wazuhdb_query, &response);

            if (db_result != 0) {
                merror("at fim_db_search(): Bad save query");
                sk_sum_clean(&newsum);
                free(wazuhdb_query);
                free(new_check_sum);
                free(old_check_sum);
                free(response);
                return (-1);
            }

            mdebug2("File %s saved/updated in FIM DDBB", f_name);

            break;

        default: // Error in fim check sum
            merror("at fim_db_search: Couldn't decode fim sum '%s' from file '%s'.",
                    new_check_sum, f_name);
            lf->data = NULL;
            sk_sum_clean(&newsum);
            free(wazuhdb_query);
            free(new_check_sum);
            free(old_check_sum);
            free(response);
            return (-1);
    }

    sk_fill_event(lf, f_name, &newsum);
    fim_alert (f_name, &oldsum, &newsum, lf);

    sk_sum_clean(&newsum);
    free(response);
    free(new_check_sum);
    free(old_check_sum);
    free(wazuhdb_query);
    return (1);
}


int send_query_wazuhdb(char *wazuhdb_query, char **output) {
    static int sock = -1;
    char response[OS_SIZE_6144];
    ssize_t length;
    fd_set fdset;
    struct timeval timeout = {0, 1000};
    int size = strlen(wazuhdb_query);
    int retval = -1;
    static time_t last_attempt = 0;
    time_t mtime;

    // Connect to socket if disconnected
    if (sock < 0) {
        if (mtime = time(NULL), mtime > last_attempt + 10) {
            if (sock = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_SIZE_6144), sock < 0) {
                last_attempt = mtime;
                mterror(ARGV0, "at send_query_wazuhdb(): Unable connect to socket '%s':'%s'(%d)",
                        WDB_LOCAL_SOCK, strerror(errno), errno);
                return (-1);
            }
        } else {
            // Return silently
            return (-1);
        }
    }

    // Send query to Wazuh DB
    if (send(sock, wazuhdb_query, size + 1, MSG_DONTWAIT) < size) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            mterror(ARGV0, "at send_query_wazuhdb(): database socket is full");
        } else if (errno == EPIPE) {
            if (mtime = time(NULL), mtime > last_attempt + 10) {
                // Retry to connect
                mterror(ARGV0, "at send_query_wazuhdb(): Connection with wazuh-db lost. Reconnecting.");
                close(sock);

                if (sock = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_SIZE_6144), sock < 0) {
                    last_attempt = mtime;
                    mterror(ARGV0, "at send_query_wazuhdb(): Unable connect to socket '%s':'%s'(%d)",
                            WDB_LOCAL_SOCK, strerror(errno), errno);
                    return (-1);
                }

                if (send(sock, wazuhdb_query, size + 1, MSG_DONTWAIT) < size) {
                    last_attempt = mtime;
                    mterror(ARGV0, "at send_query_wazuhdb(): in send reattempt (%d)'%s'.", errno, strerror(errno));
                    return (-1);
                }
            } else {
                // Return silently
                return (-1);
            }

        } else {
            mterror(ARGV0, "at send_query_wazuhdb(): in send (%d)'%s'.", errno, strerror(errno));
        }
    }

    // Wait for socket
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    if (select(sock + 1, &fdset, NULL, NULL, &timeout) < 0) {
        mterror(ARGV0, "at send_query_wazuhdb(): in select (%d)'%s'.", errno, strerror(errno));
        return (-1);
    }

    // Receive response from socket
    length = recv(sock, response, OS_SIZE_6144 - 1, 0);
    response[length] = '\0';

    if (length > 0) {
        os_strdup(response, *output);

        if (response[0] == 'o' && response[1] == 'k') {
            retval = 0;
        } else {
            mterror(ARGV0, "at send_query_wazuhdb(): bad response '%s'.", response);
            return retval;
        }
    } else {
        mterror(ARGV0, "at send_query_wazuhdb(): no response from wazuh-db.");
        return retval;
    }

    return retval;
}


int fim_alert (char *f_name, sk_sum_t *oldsum, sk_sum_t *newsum, Eventinfo *lf) {
    int changes = 0;
    int comment_buf = 0;
    char msg_type[OS_FLSIZE];

    // Set decoder
    lf->decoder_info = sdb.syscheck_dec;

    switch (lf->event_type) {
        case FIM_DELETED:
            snprintf(msg_type, sizeof(msg_type), "was deleted.");
            break;
        case FIM_ADDED:
            snprintf(msg_type, sizeof(msg_type), "was added.");
            break;
        case FIM_MODIFIED:
            snprintf(msg_type, sizeof(msg_type), "checksum changed.");
            // Generate size message
            if (strcmp(oldsum->size, newsum->size) == 0) {
                *sdb.size = '\0';
            } else {
                changes = 1;
                wm_strcat(&lf->fields[SK_CHFIELDS].value, "size", ',');
                snprintf(sdb.size, OS_FLSIZE,
                        "Size changed from '%s' to '%s'\n",
                        oldsum->size, newsum->size);

                os_strdup(oldsum->size, lf->size_before);
            }

            // Permission message
            if (oldsum->perm == newsum->perm) {
                *sdb.perm = '\0';
            } else if (oldsum->perm > 0 && newsum->perm > 0) {
                changes = 1;
                wm_strcat(&lf->fields[SK_CHFIELDS].value, "perm", ',');
                char opstr[10];
                char npstr[10];

                strncpy(opstr, agent_file_perm(oldsum->perm), sizeof(opstr) - 1);
                strncpy(npstr, agent_file_perm(newsum->perm), sizeof(npstr) - 1);
                opstr[9] = npstr[9] = '\0';

                snprintf(sdb.perm, OS_FLSIZE, "Permissions changed from "
                            "'%9.9s' to '%9.9s'\n", opstr, npstr);

                lf->perm_before = oldsum->perm;
            } else {
                *sdb.perm = '\0';
            }

            // Ownership message
            if (newsum->uid && oldsum->uid) {
                if (strcmp(newsum->uid, oldsum->uid) == 0) {
                    *sdb.owner = '\0';
                } else {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "uid", ',');
                    if (oldsum->uname && newsum->uname) {
                        snprintf(sdb.owner, OS_FLSIZE, "Ownership was '%s (%s)', now it is '%s (%s)'\n", oldsum->uname, oldsum->uid, newsum->uname, newsum->uid);
                        os_strdup(oldsum->uname, lf->uname_before);
                    } else {
                        snprintf(sdb.owner, OS_FLSIZE, "Ownership was '%s', now it is '%s'\n", oldsum->uid, newsum->uid);
                    }
                    os_strdup(oldsum->uid, lf->owner_before);
                }
            } else {
                *sdb.owner = '\0';
            }

            // Group ownership message
            if (newsum->gid && oldsum->gid) {
                if (strcmp(newsum->gid, oldsum->gid) == 0) {
                    *sdb.gowner = '\0';
                } else {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "gid", ',');
                    if (oldsum->gname && newsum->gname) {
                        snprintf(sdb.gowner, OS_FLSIZE, "Group ownership was '%s (%s)', now it is '%s (%s)'\n", oldsum->gname, oldsum->gid, newsum->gname, newsum->gid);
                        os_strdup(oldsum->gname, lf->gname_before);
                    } else {
                        snprintf(sdb.gowner, OS_FLSIZE, "Group ownership was '%s', now it is '%s'\n", oldsum->gid, newsum->gid);
                    }
                    os_strdup(oldsum->gid, lf->gowner_before);
                }
            } else {
                *sdb.gowner = '\0';
            }
            // MD5 message
            if (!*newsum->md5 || !*oldsum->md5 || strcmp(newsum->md5, oldsum->md5) == 0) {
                *sdb.md5 = '\0';
            } else {
                changes = 1;
                wm_strcat(&lf->fields[SK_CHFIELDS].value, "md5", ',');
                snprintf(sdb.md5, OS_FLSIZE, "Old md5sum was: '%s'\nNew md5sum is : '%s'\n",
                            oldsum->md5, newsum->md5);
                os_strdup(oldsum->md5, lf->md5_before);
            }

            // SHA-1 message
            if (!*newsum->sha1 || !*oldsum->sha1 || strcmp(newsum->sha1, oldsum->sha1) == 0) {
                *sdb.sha1 = '\0';
            } else {
                changes = 1;
                wm_strcat(&lf->fields[SK_CHFIELDS].value, "sha1", ',');
                snprintf(sdb.sha1, OS_FLSIZE, "Old sha1sum was: '%s'\nNew sha1sum is : '%s'\n",
                            oldsum->sha1, newsum->sha1);
                os_strdup(oldsum->sha1, lf->sha1_before);
            }

            // SHA-256 message
            if(newsum->sha256 && *newsum->sha256)
            {
                if(oldsum->sha256) {
                    if (strcmp(newsum->sha256, oldsum->sha256) == 0) {
                        *sdb.sha256 = '\0';
                    } else {
                        changes = 1;
                        wm_strcat(&lf->fields[SK_CHFIELDS].value, "sha256", ',');
                        snprintf(sdb.sha256, OS_FLSIZE, "Old sha256sum was: '%s'\nNew sha256sum is : '%s'\n",
                                oldsum->sha256, newsum->sha256);
                        os_strdup(oldsum->sha256, lf->sha256_before);
                    }
                } else {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "sha256", ',');
                    snprintf(sdb.sha256, OS_FLSIZE, "New sha256sum is : '%s'\n", newsum->sha256);
                }
            } else {
                *sdb.sha256 = '\0';
            }

            // Modification time message
            if (oldsum->mtime && newsum->mtime && oldsum->mtime != newsum->mtime) {
                changes = 1;
                wm_strcat(&lf->fields[SK_CHFIELDS].value, "mtime", ',');
                char *old_ctime = strdup(ctime(&oldsum->mtime));
                char *new_ctime = strdup(ctime(&newsum->mtime));
                old_ctime[strlen(old_ctime) - 1] = '\0';
                new_ctime[strlen(new_ctime) - 1] = '\0';

                snprintf(sdb.mtime, OS_FLSIZE, "Old modification time was: '%s', now it is '%s'\n", old_ctime, new_ctime);
                lf->mtime_before = oldsum->mtime;
                free(old_ctime);
                free(new_ctime);
            } else {
                *sdb.mtime = '\0';
            }

            // Inode message
            if (oldsum->inode && newsum->inode && oldsum->inode != newsum->inode) {
                changes = 1;
                wm_strcat(&lf->fields[SK_CHFIELDS].value, "inode", ',');
                snprintf(sdb.mtime, OS_FLSIZE, "Old inode was: '%ld', now it is '%ld'\n", oldsum->inode, newsum->inode);
                lf->inode_before = oldsum->inode;
            } else {
                *sdb.inode = '\0';
            }
            break;
        default:
            return (-1);
            break;
    }

    // Provide information about the file
    comment_buf = snprintf(sdb.comment, OS_SIZE_6144, "File"
            " '%.756s' "
            "%s\n"
            "%s"
            "%s"
            "%s"
            "%s"
            "%s"
            "%s"
            "%s"
            "%s"
            "%s"
            "%s"
            "%s"
            "%s"
            "%s",
            f_name,
            msg_type,
            sdb.size,
            sdb.perm,
            sdb.owner,
            sdb.gowner,
            sdb.md5,
            sdb.sha1,
            sdb.sha256,
            sdb.user_name,
            sdb.audit_name,
            sdb.effective_name,
            sdb.group_name,
            sdb.process_id,
            sdb.process_name
    );

    if(!changes) {
        lf->data = NULL;
        sk_sum_clean(newsum);
    } else {
        wm_strcat(&lf->fields[SK_CHFIELDS].value, ",", '\0');
    }

    if(lf->data) {
        snprintf(sdb.comment+comment_buf, OS_SIZE_6144-comment_buf, "What changed:\n%s", lf->data);
        os_strdup(lf->data, lf->diff);
    }

    // Create a new log message
    free(lf->full_log);
    os_strdup(sdb.comment, lf->full_log);
    lf->log = lf->full_log;

    return (0);
}

void InsertWhodata(const sk_sum_t * sum) {
    // Whodata user
    if(sum->wdata.user_id && sum->wdata.user_name && *sum->wdata.user_id != '\0') {
        snprintf(sdb.user_name, OS_FLSIZE, "(Audit) User: '%s (%s)'\n",
                sum->wdata.user_name, sum->wdata.user_id);
    } else {
        *sdb.user_name = '\0';
    }

    // Whodata effective user
    if(sum->wdata.effective_uid && sum->wdata.effective_name && *sum->wdata.effective_uid != '\0') {
        snprintf(sdb.effective_name, OS_FLSIZE, "(Audit) Effective user: '%s (%s)'\n",
                sum->wdata.effective_name, sum->wdata.effective_uid);
    } else {
        *sdb.effective_name = '\0';
    }

    // Whodata Audit user
    if(sum->wdata.audit_uid && sum->wdata.audit_name && *sum->wdata.audit_uid != '\0') {
        snprintf(sdb.audit_name, OS_FLSIZE, "(Audit) Login user: '%s (%s)'\n",
                sum->wdata.audit_name, sum->wdata.audit_uid);
    } else {
        *sdb.audit_name = '\0';
    }

    // Whodata Group
    if(sum->wdata.group_id && sum->wdata.group_name && *sum->wdata.group_id != '\0') {
        snprintf(sdb.group_name, OS_FLSIZE, "(Audit) Group: '%s (%s)'\n",
                sum->wdata.group_name, sum->wdata.group_id);
    } else {
        *sdb.group_name = '\0';
    }

    // Whodata process
    if(sum->wdata.process_id && *sum->wdata.process_id != '\0') {
        snprintf(sdb.process_id, OS_FLSIZE, "(Audit) Process id: '%s'\n",
                sum->wdata.process_id);
    } else {
        *sdb.process_id = '\0';
    }

    if(sum->wdata.process_name && *sum->wdata.process_name != '\0') {
        snprintf(sdb.process_name, OS_FLSIZE, "(Audit) Process name: '%s'\n",
                sum->wdata.process_name);
    } else {
        *sdb.process_name = '\0';
    }
}


// Compare the first common fields between sum strings
int SumCompare(const char *s1, const char *s2) {
    const char *ptr1 = strchr(s1, ':');
    const char *ptr2 = strchr(s2, ':');
    size_t size1;
    size_t size2;

    while (ptr1 && ptr2) {
        ptr1 = strchr(ptr1 + 1, ':');
        ptr2 = strchr(ptr2 + 1, ':');
    }

    size1 = ptr1 ? (size_t)(ptr1 - s1) : strlen(s1);
    size2 = ptr2 ? (size_t)(ptr2 - s2) : strlen(s2);

    return size1 == size2 ? strncmp(s1, s2, size1) : 1;
}

// Clean sdb memory
void fim_clean_sdb_mem() {
    memset(sdb.buf, '\0', OS_SIZE_6144 + 1);
    memset(sdb.comment, '\0', OS_SIZE_6144 + 1);

    memset(sdb.size, '\0', OS_FLSIZE + 1);
    memset(sdb.perm, '\0', OS_FLSIZE + 1);
    memset(sdb.owner, '\0', OS_FLSIZE + 1);
    memset(sdb.gowner, '\0', OS_FLSIZE + 1);
    memset(sdb.md5, '\0', OS_FLSIZE + 1);
    memset(sdb.sha1, '\0', OS_FLSIZE + 1);
    memset(sdb.sha256, '\0', OS_FLSIZE + 1);
    memset(sdb.mtime, '\0', OS_FLSIZE + 1);
    memset(sdb.inode, '\0', OS_FLSIZE + 1);

    // Whodata fields
    memset(sdb.user_name, '\0', OS_FLSIZE + 1);
    memset(sdb.group_name, '\0', OS_FLSIZE + 1);
    memset(sdb.process_name, '\0', OS_FLSIZE + 1);
    memset(sdb.audit_name, '\0', OS_FLSIZE + 1);
    memset(sdb.effective_name, '\0', OS_FLSIZE + 1);
    memset(sdb.ppid, '\0', OS_FLSIZE + 1);
    memset(sdb.process_id, '\0', OS_FLSIZE + 1);
}

int fim_check_changes (int saved_frequency, long saved_time, Eventinfo *lf) {
    int freq = 0;

    sdb.syscheck_dec->id = sdb.id1;
    if (!Config.syscheck_auto_ignore) {
        freq = 0;
    } else {
        if (lf->time.tv_sec - saved_time < Config.syscheck_ignore_time) {
            if (saved_frequency >= Config.syscheck_ignore_frequency) {
                // No send alert
                freq = -1;
            }
            else {
                freq = saved_frequency + 1;
            }
        }
    }

    return freq;
}

int fim_control_msg(char *key, time_t value, Eventinfo *lf) {
    char *wazuhdb_query = NULL;
    char *response = NULL;
    int db_result;

    // If we don't have a valid syscheck message, it may be a scan control message

    if (strcmp(key, HC_SK_DB_COMPLETED) == 0 || strcmp(key, HC_FIM_DB_SFS) == 0 ||
            strcmp(key, HC_FIM_DB_EFS) == 0 || strcmp(key, HC_FIM_DB_SS) == 0 ||
            strcmp(key, HC_FIM_DB_ES) == 0) {
        os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);

        snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck control %s %ld",
                lf->agent_id,
                key,
                (long int)value
        );

        db_result = send_query_wazuhdb(wazuhdb_query, &response);

        if (db_result != 0) {
            merror("at fim_control_msg(): Bad save query");
            free(wazuhdb_query);
            free(response);
            return (-1);
        }

        if (strcmp(key, HC_FIM_DB_EFS) == 0) {
            fim_database_clean(lf);
        }

        free(wazuhdb_query);
        free(response);
        return (1);
    }

    return (0);
}

int fim_update_date (char *file, Eventinfo *lf) {
    // If any entry has a date less than last_check it should be deleted.
    char *wazuhdb_query = NULL;
    char *response = NULL;
    int db_result;

    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);

    snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck updatedate %s %ld",
            lf->agent_id,
            file,
            (long int)lf->time.tv_sec
    );

    db_result = send_query_wazuhdb(wazuhdb_query, &response);

    if (db_result != 0) {
        merror("at fim_update_date(): Bad save query");
        free(wazuhdb_query);
        free(response);
        return (-1);
    }

    mdebug1("FIM file %s update timestamp for last event", file);

    free(wazuhdb_query);
    free(response);
    return (1);

}

int fim_database_clean(Eventinfo *lf) {
    // If any entry has a date less than last_check it should be deleted.
    char *wazuhdb_query = NULL;
    char *response = NULL;
    int db_result;

    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);

    snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck cleandb %ld",
            lf->agent_id,
            (unsigned long)lf->time.tv_sec
    );

    db_result = send_query_wazuhdb(wazuhdb_query, &response);

    if (db_result != 0) {
        merror("at fim_database_clean(): Bad save query");
        free(wazuhdb_query);
        free(response);
        return (-1);
    }

    mdebug1("FIM database has been cleaned");

    free(wazuhdb_query);
    free(response);
    return (1);

}