/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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
static int fim_db_search (char *f_name, char *c_sum, char *w_sum, Eventinfo *lf, _sdb *sdb);
// Send msg to wazuh-db
static int send_query_wazuhdb (char *wazuhdb_query, char **output, _sdb *sdb);
// Build FIM alert
static int fim_alert (char *f_name, sk_sum_t *oldsum, sk_sum_t *newsum, Eventinfo *lf, _sdb *localsdb);
// Build fileds whodata alert
static void InsertWhodata (const sk_sum_t * sum, _sdb *localsdb);
// Compare the first common fields between sum strings
static int SumCompare (const char *s1, const char *s2);
// Check for exceed num of changes
static int fim_check_changes (int saved_frequency, long saved_time, Eventinfo *lf);
// Send control message to wazuhdb
static int fim_control_msg (char *key, time_t value, Eventinfo *lf, _sdb *sdb);
//Update field date at last event generated
int fim_update_date (char *file, Eventinfo *lf, _sdb *sdb);
// Clean for old entries
int fim_database_clean (Eventinfo *lf, _sdb *sdb);
// Clean sdb memory
void sdb_clean(_sdb *localsdb);
// Get timestamp for last scan from wazuhdb
int fim_get_scantime (long *ts, Eventinfo *lf, _sdb *sdb);

// Mutexes
static pthread_mutex_t control_msg_mutex = PTHREAD_MUTEX_INITIALIZER;


// Initialize the necessary information to process the syscheck information
int fim_init(void) {
    //Create hash table for agent information
    fim_agentinfo = OSHash_Create();
    if (fim_agentinfo == NULL) return 0;
    return 1;
}

// Initialize the necessary information to process the syscheck information
void sdb_init(_sdb *localsdb, OSDecoderInfo *fim_decoder) {
    localsdb->db_err = 0;
    localsdb->socket = -1;

    sdb_clean(localsdb);

    // Create decoder
    fim_decoder->id = getDecoderfromlist(SYSCHECK_MOD);
    fim_decoder->name = SYSCHECK_MOD;
    fim_decoder->type = OSSEC_RL;
    fim_decoder->fts = 0;

    os_calloc(Config.decoder_order_size, sizeof(char *), fim_decoder->fields);
    fim_decoder->fields[SK_FILE] = "file";
    fim_decoder->fields[SK_SIZE] = "size";
    fim_decoder->fields[SK_PERM] = "perm";
    fim_decoder->fields[SK_UID] = "uid";
    fim_decoder->fields[SK_GID] = "gid";
    fim_decoder->fields[SK_MD5] = "md5";
    fim_decoder->fields[SK_SHA1] = "sha1";
    fim_decoder->fields[SK_SHA256] = "sha256";
    fim_decoder->fields[SK_ATTRS] = "attributes";
    fim_decoder->fields[SK_UNAME] = "uname";
    fim_decoder->fields[SK_GNAME] = "gname";
    fim_decoder->fields[SK_INODE] = "inode";
    fim_decoder->fields[SK_MTIME] = "mtime";
    fim_decoder->fields[SK_CHFIELDS] = "changed_fields";

    fim_decoder->fields[SK_USER_ID] = "user_id";
    fim_decoder->fields[SK_USER_NAME] = "user_name";
    fim_decoder->fields[SK_GROUP_ID] = "group_id";
    fim_decoder->fields[SK_GROUP_NAME] = "group_name";
    fim_decoder->fields[SK_PROC_NAME] = "process_name";
    fim_decoder->fields[SK_AUDIT_ID] = "audit_uid";
    fim_decoder->fields[SK_AUDIT_NAME] = "audit_name";
    fim_decoder->fields[SK_EFFECTIVE_UID] = "effective_uid";
    fim_decoder->fields[SK_EFFECTIVE_NAME] = "effective_name";
    fim_decoder->fields[SK_PPID] = "ppid";
    fim_decoder->fields[SK_PROC_ID] = "process_id";
    fim_decoder->fields[SK_TAG] = "tag";
}

// Initialize the necessary information to process the syscheck information
void sdb_clean(_sdb *localsdb) {
    *localsdb->comment = '\0';
    *localsdb->size = '\0';
    *localsdb->perm = '\0';
    *localsdb->attrs = '\0';
    *localsdb->owner = '\0';
    *localsdb->gowner = '\0';
    *localsdb->md5 = '\0';
    *localsdb->sha1 = '\0';
    *localsdb->sha256 = '\0';
    *localsdb->mtime = '\0';
    *localsdb->inode = '\0';

    // Whodata fields
    *localsdb->user_id = '\0';
    *localsdb->user_name = '\0';
    *localsdb->group_id = '\0';
    *localsdb->group_name = '\0';
    *localsdb->process_name = '\0';
    *localsdb->audit_uid = '\0';
    *localsdb->audit_name = '\0';
    *localsdb->effective_uid = '\0';
    *localsdb->effective_name = '\0';
    *localsdb->ppid = '\0';
    *localsdb->process_id = '\0';
}

/* Special decoder for syscheck
 * Not using the default decoding lib for simplicity
 * and to be less resource intensive
 */
int DecodeSyscheck(Eventinfo *lf, _sdb *sdb)
{
    char *c_sum;
    char *w_sum = NULL;
    char *f_name;

    /* Every syscheck message must be in the following format:
     * 'checksum' 'filename'
     * or
     * 'checksum'!'extradata' 'filename'
     * or
     *                                             |v2.1       v3.4   |v3.4         v3.6  |
     *                                             |->         |->    |->           |->   |
     * "size:permision:uid:gid:md5:sha1:uname:gname:mtime:inode:sha256!w:h:o:d:a:t:a:tags filename\nreportdiff"
     *  ^^^^^^^^^^^^^^^^^^^^^^^^^^^checksum^^^^^^^^^^^^^^^^^^^^^^^^^^^!^^^^extradata^^^^^ filename\n^^^diff^^^'
     */
    sdb_clean(sdb);
    f_name = wstr_chr(lf->log, ' ');
    if (f_name == NULL) {
        mdebug2("Scan's control message agent '%s': '%s'", lf->log, lf->agent_id);
        switch (fim_control_msg(lf->log, lf->time.tv_sec, lf, sdb)) {
        case -2:
        case -1:
            return (-1);
        case 0:
            merror(SK_INV_MSG);
            return (-1);
        default:
            return(0);
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
        *(lf->data++) = '\0';
        os_strdup(lf->data, lf->data);
    }

    // Check if file is supposed to be ignored
    if (Config.syscheck_ignore) {
        char **ff_ig = Config.syscheck_ignore;

        while (*ff_ig) {
            if (strncasecmp(*ff_ig, f_name, strlen(*ff_ig)) == 0) {
                os_free(lf->data);
                mdebug1("Ignoring file '%s'", f_name);;
                return (0);
            }

            ff_ig++;
        }
    }

    // Checksum is at the beginning of the log
    c_sum = lf->log;

    // Get w_sum
    if (w_sum = wstr_chr(c_sum, '!'), w_sum) {
        *(w_sum++) = '\0';
    }

    // Search for file changes
    return (fim_db_search(f_name, c_sum, w_sum, lf, sdb));
}


int fim_db_search(char *f_name, char *c_sum, char *w_sum, Eventinfo *lf, _sdb *sdb) {
    int decode_newsum = 0;
    int db_result = 0;
    int changes = 0;
    int i = 0;
    char *ttype[OS_SIZE_128];
    char *wazuhdb_query = NULL;
    char *new_check_sum = NULL;
    char *old_check_sum = NULL;
    char *response = NULL;
    char *check_sum = NULL;
    sk_sum_t oldsum = { .size = NULL };
    sk_sum_t newsum = { .size = NULL };
    time_t *end_first_scan = NULL;
    time_t end_scan = 0;

    memset(&oldsum, 0, sizeof(sk_sum_t));
    memset(&newsum, 0, sizeof(sk_sum_t));

    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);
    os_strdup(c_sum, new_check_sum);

    snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck load %s", lf->agent_id, f_name);

    db_result = send_query_wazuhdb(wazuhdb_query, &response, sdb);

    // Fail trying load info from DDBB

    switch (db_result) {
    case -2:
        merror("FIM decoder: Bad load query: '%s'.", wazuhdb_query);
        // Fallthrough
    case -1:
        os_free(lf->data);
        goto exit_fail;
    }

    if(check_sum = wstr_chr(response, ' '), !check_sum) {
        merror("FIM decoder: Bad response: '%s' '%s'.", wazuhdb_query, response);
        goto exit_fail;
    }
    *(check_sum++) = '\0';

    //extract changes and date_alert fields only available from wazuh_db
    if(sk_decode_extradata(&oldsum, check_sum) > 0) {
        merror("at fim_db_search(): Error decoding agent: '%s' extradata '%s' from '%s'", lf->agent_id, check_sum, f_name);
    }

    os_strdup(check_sum, old_check_sum);
    mdebug2("Agent '%s' File '%s'", lf->agent_id, f_name);
    mdebug2("Agent '%s' Old checksum '%s'", lf->agent_id, old_check_sum);
    mdebug2("Agent '%s' New checksum '%s'", lf->agent_id, new_check_sum);

    // Checksum match, we can just return and keep going
    if (SumCompare(old_check_sum, new_check_sum) == 0) {
        mdebug1("Agent '%s' Alert discarded '%s' same check_sum", lf->agent_id, f_name);
        fim_update_date (f_name, lf, sdb);
        goto exit_ok;
    }

    if (decode_newsum = sk_decode_sum(&newsum, c_sum, w_sum), decode_newsum != -1) {
        InsertWhodata(&newsum, sdb);
    }

    wazuhdb_query[0] = '\0';
    switch (decode_newsum) {
        case 1: // File deleted
            lf->event_type = FIM_DELETED;

            if(!*old_check_sum){
                mdebug2("Agent '%s' Alert already reported (double delete alert)", lf->agent_id);
                goto exit_ok;
            }

            snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck delete %s",
                    lf->agent_id,
                    f_name
            );
            os_free(response);
            response = NULL;
            db_result = send_query_wazuhdb(wazuhdb_query, &response, sdb);

            switch (db_result) {
            case -2:
                merror("FIM decoder: Bad delete query: '%s'.", wazuhdb_query);
                // Fallthrough
            case -1:
                goto exit_fail;
            }

            mdebug2("Agent '%s' File %s deleted from FIM DDBB", lf->agent_id, f_name);

            break;
        case 0:
            if (*old_check_sum) {
                // File modified
                lf->event_type = FIM_MODIFIED;
                changes = fim_check_changes(oldsum.changes, oldsum.date_alert, lf);
                sk_decode_sum(&oldsum, old_check_sum, NULL);

                // Alert discarded, frequency exceeded
                if (changes == -1) {
                    mdebug1("Agent '%s' Alert discarded '%s' frequency exceeded", lf->agent_id, f_name);
                    goto exit_ok;
                }
            } else {
                // File added
                lf->event_type = FIM_ADDED;
            }

            if (strstr(lf->location, "syscheck-registry")) {
                *ttype = "registry";
            } else {
                *ttype = "file";
            }

            snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck save %s %s!%d:%ld %s",
                    lf->agent_id,
                    *ttype,
                    new_check_sum,
                    changes,
                    lf->time.tv_sec,
                    f_name
            );
            os_free(response);
            response = NULL;
            db_result = send_query_wazuhdb(wazuhdb_query, &response, sdb);

            switch (db_result) {
            case -2:
                merror("FIM decoder: Bad save/update query: '%s'.", wazuhdb_query);
                // Fallthrough
            case -1:
                goto exit_fail;
            }

            mdebug2("Agent '%s' File %s saved/updated in FIM DDBB", lf->agent_id, f_name);

            if(end_first_scan = (time_t*)OSHash_Get_ex(fim_agentinfo, lf->agent_id), end_first_scan == NULL) {
                fim_get_scantime(&end_scan, lf, sdb);
                os_calloc(1, sizeof(time_t), end_first_scan);
                *end_first_scan = end_scan;
                int res;
                if(res = OSHash_Add_ex(fim_agentinfo, lf->agent_id, end_first_scan), res != 2) {
                    os_free(end_first_scan);
                    if(res == 0) {
                        merror("Unable to add scan_info to hash table for agent: %s", lf->agent_id);
                    }
                }
            } else {
                end_scan = *end_first_scan;
            }

            if(lf->event_type == FIM_ADDED) {
                if(end_scan == 0) {
                    mdebug2("Agent '%s' Alert discarded, first scan. File '%s'", lf->agent_id, f_name);
                    goto exit_ok;
                } else if(lf->time.tv_sec < end_scan) {
                    mdebug2("Agent '%s' Alert discarded, first scan (delayed event). File '%s'", lf->agent_id, f_name);
                    goto exit_ok;
                } else if(Config.syscheck_alert_new == 0) {
                    mdebug2("Agent '%s' Alert discarded (alert_new_files = no). File '%s'", lf->agent_id, f_name);
                    goto exit_ok;
                }
            }

            mdebug2("Agent '%s' End end_scan is '%ld' (lf->time: '%ld')", lf->agent_id, end_scan, lf->time.tv_sec);
            break;

        default: // Error in fim check sum
            mwarn("at fim_db_search: Agent '%s' Couldn't decode fim sum '%s' from file '%s'.",
                    lf->agent_id, new_check_sum, f_name);
            goto exit_fail;
    }

    sk_fill_event(lf, f_name, &newsum);

    /* Dyanmic Fields */
    lf->nfields = SK_NFIELDS;
    for (i = 0; i < SK_NFIELDS; i++) {
        os_strdup(lf->decoder_info->fields[i], lf->fields[i].key);
    }

    if(fim_alert(f_name, &oldsum, &newsum, lf, sdb) == -1) {
        //No changes in checksum
        goto exit_ok;
    }
    sk_sum_clean(&newsum);
    sk_sum_clean(&oldsum);
    os_free(response);
    os_free(new_check_sum);
    os_free(old_check_sum);
    os_free(wazuhdb_query);
    return (1);

exit_ok:
    sk_sum_clean(&newsum);
    sk_sum_clean(&oldsum);
    os_free(response);
    os_free(new_check_sum);
    os_free(old_check_sum);
    os_free(wazuhdb_query);
    return (0);

exit_fail:
    sk_sum_clean(&newsum);
    sk_sum_clean(&oldsum);
    os_free(response);
    os_free(new_check_sum);
    os_free(old_check_sum);
    os_free(wazuhdb_query);
    return (-1);
}


int send_query_wazuhdb(char *wazuhdb_query, char **output, _sdb *sdb) {
    char response[OS_SIZE_6144];
    fd_set fdset;
    struct timeval timeout = {0, 1000};
    int size = strlen(wazuhdb_query);
    int retval = -2;
    int attempts;

    // Connect to socket if disconnected
    if (sdb->socket < 0) {
        for (attempts = 1; attempts <= FIM_MAX_WAZUH_DB_ATTEMPS && (sdb->socket = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_SIZE_6144)) < 0; attempts++) {
            switch (errno) {
            case ENOENT:
                mtinfo(ARGV0, "FIM decoder: Cannot find '%s'. Waiting %d seconds to reconnect.", WDB_LOCAL_SOCK, attempts);
                break;
            default:
                mtinfo(ARGV0, "FIM decoder: Cannot connect to '%s': %s (%d). Waiting %d seconds to reconnect.", WDB_LOCAL_SOCK, strerror(errno), errno, attempts);
            }
            sleep(attempts);
        }

        if (sdb->socket < 0) {
            mterror(ARGV0, "FIM decoder: Unable to connect to socket '%s'.", WDB_LOCAL_SOCK);
            return retval;
        }
    }

    // Send query to Wazuh DB
    if (OS_SendSecureTCP(sdb->socket, size + 1, wazuhdb_query) != 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            mterror(ARGV0, "FIM decoder: database socket is full");
        } else if (errno == EPIPE) {
            // Retry to connect
            mterror(ARGV0, "FIM decoder: Connection with wazuh-db lost. Reconnecting.");
            close(sdb->socket);

            if (sdb->socket = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_SIZE_6144), sdb->socket < 0) {
                switch (errno) {
                case ENOENT:
                    mterror(ARGV0, "FIM decoder: Cannot find '%s'. Please check that Wazuh DB is running.", WDB_LOCAL_SOCK);
                    break;
                default:
                    mterror(ARGV0, "FIM decoder: Cannot connect to '%s': %s (%d)", WDB_LOCAL_SOCK, strerror(errno), errno);
                }
                return retval;
            }

            if (OS_SendSecureTCP(sdb->socket, size + 1, wazuhdb_query)) {
                mterror(ARGV0, "FIM decoder: in send reattempt (%d) '%s'.", errno, strerror(errno));
                return retval;
            }
        } else {
            mterror(ARGV0, "FIM decoder: in send (%d) '%s'.", errno, strerror(errno));
        }
    }

    // Wait for socket
    FD_ZERO(&fdset);
    FD_SET(sdb->socket, &fdset);

    if (select(sdb->socket + 1, &fdset, NULL, NULL, &timeout) < 0) {
        mterror(ARGV0, "FIM decoder: in select (%d) '%s'.", errno, strerror(errno));
        return retval;
    }
    retval = -1;

    // Receive response from socket
    if (OS_RecvSecureTCP(sdb->socket, response, OS_SIZE_6144 - 1) > 0) {
        os_strdup(response, *output);

        if (response[0] == 'o' && response[1] == 'k') {
            retval = 0;
        } else {
            mterror(ARGV0, "FIM decoder: Bad response '%s'.", response);
        }
    } else {
        mterror(ARGV0, "FIM decoder: no response from wazuh-db.");
    }

    return retval;
}

int fim_alert (char *f_name, sk_sum_t *oldsum, sk_sum_t *newsum, Eventinfo *lf, _sdb *localsdb) {
    int changes = 0;
    int comment_buf = 0;
    char msg_type[OS_FLSIZE];

    switch (lf->event_type) {
        case FIM_DELETED:
            snprintf(msg_type, sizeof(msg_type), "was deleted.");
            lf->decoder_info->id = getDecoderfromlist(SYSCHECK_DEL);
            lf->decoder_syscheck_id = lf->decoder_info->id;
            lf->decoder_info->name = SYSCHECK_MOD;
            changes=1;
            break;
        case FIM_ADDED:
            snprintf(msg_type, sizeof(msg_type), "was added.");
            lf->decoder_info->id = getDecoderfromlist(SYSCHECK_NEW);
            lf->decoder_syscheck_id = lf->decoder_info->id;
            lf->decoder_info->name = SYSCHECK_NEW;
            changes=1;
            break;
        case FIM_MODIFIED:
            snprintf(msg_type, sizeof(msg_type), "checksum changed.");
            lf->decoder_info->id = getDecoderfromlist(SYSCHECK_MOD);
            lf->decoder_syscheck_id = lf->decoder_info->id;
            lf->decoder_info->name = SYSCHECK_MOD;
            if (oldsum->size && newsum->size) {
                if (strcmp(oldsum->size, newsum->size) == 0) {
                    localsdb->size[0] = '\0';
                } else {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "size", ',');
                    snprintf(localsdb->size, OS_FLSIZE,
                             "Size changed from '%s' to '%s'\n",
                             oldsum->size, newsum->size);

                    os_strdup(oldsum->size, lf->size_before);
                }
            }

            /* Permission message */
            if (oldsum->perm && newsum->perm) {
                if (oldsum->perm == newsum->perm) {
                    localsdb->perm[0] = '\0';
                } else if (oldsum->perm > 0 && newsum->perm > 0) {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "perm", ',');
                    char opstr[10];
                    char npstr[10];
                    char *old_perm =  agent_file_perm(oldsum->perm);
                    char *new_perm =  agent_file_perm(newsum->perm);

                    strncpy(opstr, old_perm, sizeof(opstr) - 1);
                    strncpy(npstr, new_perm, sizeof(npstr) - 1);
                    free(old_perm);
                    free(new_perm);

                    opstr[9] = npstr[9] = '\0';
                    snprintf(localsdb->perm, OS_FLSIZE, "Permissions changed from "
                             "'%9.9s' to '%9.9s'\n", opstr, npstr);

                    lf->perm_before = oldsum->perm;
                }
            } else if (oldsum->win_perm && newsum->win_perm) { // Check for Windows permissions
                if (!strcmp(oldsum->win_perm, newsum->win_perm)) {
                    localsdb->perm[0] = '\0';
                } else if (*oldsum->win_perm != '\0' && *newsum->win_perm != '\0') {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "perm", ',');
                    if (!decode_win_permissions(localsdb->perm, OS_FLSIZE, newsum->win_perm, 1, NULL)) {
                        localsdb->perm[0] = '\0';
                    }

                    lf->win_perm_before = oldsum->win_perm;
                }
            }

            /* Ownership message */
            if (newsum->uid && oldsum->uid) {
                if (strcmp(newsum->uid, oldsum->uid) == 0) {
                    localsdb->owner[0] = '\0';
                } else {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "uid", ',');
                    if (oldsum->uname && newsum->uname) {
                        snprintf(localsdb->owner, OS_FLSIZE, "Ownership was '%s (%s)', now it is '%s (%s)'\n", oldsum->uname, oldsum->uid, newsum->uname, newsum->uid);
                        os_strdup(oldsum->uname, lf->uname_before);
                    } else {
                        snprintf(localsdb->owner, OS_FLSIZE, "Ownership was '%s', now it is '%s'\n", oldsum->uid, newsum->uid);
                    }
                    os_strdup(oldsum->uid, lf->owner_before);
                }
            }

            /* Group ownership message */
            if (newsum->gid && oldsum->gid) {
                if (strcmp(newsum->gid, oldsum->gid) == 0) {
                    localsdb->gowner[0] = '\0';
                } else {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "gid", ',');
                    if (oldsum->gname && newsum->gname) {
                        snprintf(localsdb->gowner, OS_FLSIZE, "Group ownership was '%s (%s)', now it is '%s (%s)'\n", oldsum->gname, oldsum->gid, newsum->gname, newsum->gid);
                        os_strdup(oldsum->gname, lf->gname_before);
                    } else {
                        snprintf(localsdb->gowner, OS_FLSIZE, "Group ownership was '%s', now it is '%s'\n", oldsum->gid, newsum->gid);
                    }
                    os_strdup(oldsum->gid, lf->gowner_before);
                }
            }
            /* MD5 message */
            if (!*newsum->md5 || !*oldsum->md5 || strcmp(newsum->md5, oldsum->md5) == 0) {
                localsdb->md5[0] = '\0';
            } else {
                changes = 1;
                wm_strcat(&lf->fields[SK_CHFIELDS].value, "md5", ',');
                snprintf(localsdb->md5, OS_FLSIZE, "Old md5sum was: '%s'\nNew md5sum is : '%s'\n",
                         oldsum->md5, newsum->md5);
                os_strdup(oldsum->md5, lf->md5_before);
            }

            /* SHA-1 message */
            if (!*newsum->sha1 || !*oldsum->sha1 || strcmp(newsum->sha1, oldsum->sha1) == 0) {
                localsdb->sha1[0] = '\0';
            } else {
                changes = 1;
                wm_strcat(&lf->fields[SK_CHFIELDS].value, "sha1", ',');
                snprintf(localsdb->sha1, OS_FLSIZE, "Old sha1sum was: '%s'\nNew sha1sum is : '%s'\n",
                         oldsum->sha1, newsum->sha1);
                os_strdup(oldsum->sha1, lf->sha1_before);
            }

            /* SHA-256 message */
            if(newsum->sha256 && newsum->sha256[0] != '\0')
            {
                if(oldsum->sha256) {
                    if (strcmp(newsum->sha256, oldsum->sha256) == 0) {
                        localsdb->sha256[0] = '\0';
                    } else {
                        changes = 1;
                        wm_strcat(&lf->fields[SK_CHFIELDS].value, "sha256", ',');
                        snprintf(localsdb->sha256, OS_FLSIZE, "Old sha256sum was: '%s'\nNew sha256sum is : '%s'\n",
                                oldsum->sha256, newsum->sha256);
                        os_strdup(oldsum->sha256, lf->sha256_before);
                    }
                } else {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "sha256", ',');
                    snprintf(localsdb->sha256, OS_FLSIZE, "New sha256sum is : '%s'\n", newsum->sha256);
                }
            } else {
                localsdb->sha256[0] = '\0';
            }

            /* Modification time message */
            if (oldsum->mtime && newsum->mtime && oldsum->mtime != newsum->mtime) {
                changes = 1;
                wm_strcat(&lf->fields[SK_CHFIELDS].value, "mtime", ',');
                char *old_ctime = strdup(ctime(&oldsum->mtime));
                char *new_ctime = strdup(ctime(&newsum->mtime));
                old_ctime[strlen(old_ctime) - 1] = '\0';
                new_ctime[strlen(new_ctime) - 1] = '\0';

                snprintf(localsdb->mtime, OS_FLSIZE, "Old modification time was: '%s', now it is '%s'\n", old_ctime, new_ctime);
                lf->mtime_before = oldsum->mtime;
                os_free(old_ctime);
                os_free(new_ctime);
            } else {
                localsdb->mtime[0] = '\0';
            }

            /* Inode message */
            if (oldsum->inode && newsum->inode && oldsum->inode != newsum->inode) {
                changes = 1;
                wm_strcat(&lf->fields[SK_CHFIELDS].value, "inode", ',');
                snprintf(localsdb->inode, OS_FLSIZE, "Old inode was: '%ld', now it is '%ld'\n", oldsum->inode, newsum->inode);
                lf->inode_before = oldsum->inode;
            } else {
                localsdb->inode[0] = '\0';
            }

            /* Attributes message */
            if (oldsum->attrs && newsum->attrs && oldsum->attrs != newsum->attrs) {
                char *str_attr_before;
                char *str_attr_after;
                changes = 1;
                os_calloc(OS_SIZE_256 + 1, sizeof(char), str_attr_before);
                os_calloc(OS_SIZE_256 + 1, sizeof(char), str_attr_after);
                decode_win_attributes(str_attr_before, oldsum->attrs);
                decode_win_attributes(str_attr_after, newsum->attrs);
                wm_strcat(&lf->fields[SK_ATTRS].value, "attributes", ',');
                snprintf(localsdb->attrs, OS_SIZE_1024, "Old attributes were: '%s'\nNow they are '%s'\n", str_attr_before, str_attr_after);
                lf->attrs_before = oldsum->attrs;
                free(str_attr_before);
                free(str_attr_after);
            } else {
                localsdb->attrs[0] = '\0';
            }

            break;
        default:
            return (-1);
            break;
    }

    // Provide information about the file
    comment_buf = snprintf(localsdb->comment, OS_MAXSTR, "File"
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
            "%s"
            "%s"
            "%s"
            "%s",
            f_name,
            msg_type,
            localsdb->size,
            localsdb->perm,
            localsdb->owner,
            localsdb->gowner,
            localsdb->md5,
            localsdb->sha1,
            localsdb->sha256,
            localsdb->attrs,
            localsdb->mtime,
            localsdb->inode,
            localsdb->user_name,
            localsdb->audit_name,
            localsdb->effective_name,
            localsdb->group_name,
            localsdb->process_id,
            localsdb->process_name
    );
    if(!changes) {
        os_free(lf->data);
        return(-1);
    } else {
        wm_strcat(&lf->fields[SK_CHFIELDS].value, ",", '\0');
    }

    if(lf->data) {
        snprintf(localsdb->comment+comment_buf, OS_MAXSTR-comment_buf, "What changed:\n%s",
                lf->data);
        os_strdup(lf->data, lf->diff);
    }

    // Create a new log message
    free(lf->full_log);
    os_strdup(localsdb->comment, lf->full_log);
    lf->log = lf->full_log;

    return (0);
}

void InsertWhodata(const sk_sum_t * sum, _sdb *sdb) {
    // Whodata user
    if(sum->wdata.user_id && sum->wdata.user_name && *sum->wdata.user_id != '\0') {
        snprintf(sdb->user_name, OS_FLSIZE, "(Audit) User: '%s (%s)'\n",
                sum->wdata.user_name, sum->wdata.user_id);
    } else {
        *sdb->user_name = '\0';
    }

    // Whodata effective user
    if(sum->wdata.effective_uid && sum->wdata.effective_name && *sum->wdata.effective_uid != '\0') {
        snprintf(sdb->effective_name, OS_FLSIZE, "(Audit) Effective user: '%s (%s)'\n",
                sum->wdata.effective_name, sum->wdata.effective_uid);
    } else {
        *sdb->effective_name = '\0';
    }

    // Whodata Audit user
    if(sum->wdata.audit_uid && sum->wdata.audit_name && *sum->wdata.audit_uid != '\0') {
        snprintf(sdb->audit_name, OS_FLSIZE, "(Audit) Login user: '%s (%s)'\n",
                sum->wdata.audit_name, sum->wdata.audit_uid);
    } else {
        *sdb->audit_name = '\0';
    }

    // Whodata Group
    if(sum->wdata.group_id && sum->wdata.group_name && *sum->wdata.group_id != '\0') {
        snprintf(sdb->group_name, OS_FLSIZE, "(Audit) Group: '%s (%s)'\n",
                sum->wdata.group_name, sum->wdata.group_id);
    } else {
        *sdb->group_name = '\0';
    }

    // Whodata process
    if(sum->wdata.process_id && *sum->wdata.process_id != '\0' && strcmp(sum->wdata.process_id, "0")) {
        snprintf(sdb->process_id, OS_FLSIZE, "(Audit) Process id: '%s'\n",
                sum->wdata.process_id);
    } else {
        *sdb->process_id = '\0';
    }

    if(sum->wdata.process_name && *sum->wdata.process_name != '\0') {
        snprintf(sdb->process_name, OS_FLSIZE, "(Audit) Process name: '%s'\n",
                sum->wdata.process_name);
    } else {
        *sdb->process_name = '\0';
    }
}


// Compare the first common fields between sum strings
int SumCompare(const char *s1, const char *s2) {
    unsigned int longs1;
    unsigned int longs2;

    longs1 = strlen(s1);
    longs2 = strlen(s2);

    if(longs1 != longs2) {
        return 1;
    }

    const char *ptr1 = strchr(s1, ':');
    const char *ptr2 = strchr(s2, ':');
    size_t size1;
    size_t size2;

    while (ptr1 && ptr2) {
        ptr1 = strchr(ptr1 + 1, ':');
        ptr2 = strchr(ptr2 + 1, ':');
    }

    size1 = ptr1 ? (size_t)(ptr1 - s1) : longs1;
    size2 = ptr2 ? (size_t)(ptr2 - s2) : longs2;

    return size1 == size2 ? strncmp(s1, s2, size1) : 1;
}

int fim_check_changes (int saved_frequency, long saved_time, Eventinfo *lf) {
    int freq = 1;

    if (!Config.syscheck_auto_ignore) {
        freq = 1;
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

int fim_control_msg(char *key, time_t value, Eventinfo *lf, _sdb *sdb) {
    char *wazuhdb_query = NULL;
    char *response = NULL;
    char *msg = NULL;
    int db_result;
    int result;
    time_t *ts_end;

    os_calloc(OS_SIZE_128, sizeof(char), msg);

    // If we don't have a valid syscheck message, it may be a scan control message
    if(strcmp(key, HC_FIM_DB_SFS) == 0) {
        snprintf(msg, OS_SIZE_128, "first_start");
    }
    if(strcmp(key, HC_FIM_DB_EFS) == 0) {
        snprintf(msg, OS_SIZE_128, "first_end");
    }
    if(strcmp(key, HC_FIM_DB_SS) == 0) {
        snprintf(msg, OS_SIZE_128, "start_scan");
    }
    if(strcmp(key, HC_FIM_DB_ES) == 0) {
        snprintf(msg, OS_SIZE_128, "end_scan");
    }
    if(strcmp(key, HC_SK_DB_COMPLETED) == 0) {
        snprintf(msg, OS_SIZE_128, "end_scan");
    }

    if (msg) {
        os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);

        snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck scan_info_update %s %ld",
                lf->agent_id,
                msg,
                (long int)value
        );

        db_result = send_query_wazuhdb(wazuhdb_query, &response, sdb);

        switch (db_result) {
        case -2:
            merror("FIM decoder: Bad result from scan_info query: '%s'.", wazuhdb_query);
            // Fallthrough
        case -1:
            os_free(wazuhdb_query);
            os_free(response);
            os_free(msg);
            return db_result;
        }

        // If end first scan store timestamp in a hash table
        w_mutex_lock(&control_msg_mutex);
        if(strcmp(key, HC_FIM_DB_EFS) == 0 || strcmp(key, HC_FIM_DB_ES) == 0 ||
                strcmp(key, HC_SK_DB_COMPLETED) == 0) {
            if (ts_end = (time_t *) OSHash_Get_ex(fim_agentinfo, lf->agent_id),
                    !ts_end) {
                os_calloc(1, sizeof(time_t), ts_end);
                *ts_end = value + 2;

                if (result = OSHash_Add_ex(fim_agentinfo, lf->agent_id, ts_end), result != 2) {
                    os_free(ts_end);
                    merror("Unable to add last scan_info to hash table for agent: %s. Error: %d.",
                            lf->agent_id, result);
                }
            }
            else {
                *ts_end = value;
                if (!OSHash_Update_ex(fim_agentinfo, lf->agent_id, ts_end)) {
                    os_free(ts_end);
                    merror("Unable to update metadata to hash table for agent: %s",
                            lf->agent_id);
                }
            }
        }
        w_mutex_unlock(&control_msg_mutex);

        // Start scan 3rd_check=2nd_check 2nd_check=1st_check 1st_check=value
        if (strcmp(key, HC_FIM_DB_SFS) == 0) {
            snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck control %ld",
                    lf->agent_id,
                    (long int)value
            );

            os_free(response);
            db_result = send_query_wazuhdb(wazuhdb_query, &response, sdb);

            switch (db_result) {
            case -2:
                merror("FIM decoder: Bad result from checks control query: '%s'.", wazuhdb_query);
                // Fallthrough
            case -1:
                os_free(wazuhdb_query);
                os_free(response);
                os_free(msg);
                return db_result;
            }
        }

        // At the end of first scan check and clean DB
        if (strcmp(key, HC_FIM_DB_EFS) == 0) {
            fim_database_clean(lf, sdb);
        }

        os_free(wazuhdb_query);
        os_free(response);
        os_free(msg);
        return (1);
    }

    os_free(msg);
    return (0);
}

int fim_update_date (char *file, Eventinfo *lf, _sdb *sdb) {
    char *wazuhdb_query = NULL;
    char *response = NULL;
    int db_result;

    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);

    snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck updatedate %s",
            lf->agent_id,
            file
    );

    db_result = send_query_wazuhdb(wazuhdb_query, &response, sdb);

    switch (db_result) {
    case -2:
        merror("FIM decoder: Bad result updating date field: '%s'.", wazuhdb_query);
        // Fallthrough
    case -1:
        os_free(wazuhdb_query);
        os_free(response);
        return (-1);
    }

    mdebug2("FIM Agent '%s' file %s update timestamp for last event", lf->agent_id, file);

    os_free(wazuhdb_query);
    os_free(response);
    return (1);
}

int fim_database_clean (Eventinfo *lf, _sdb *sdb) {
    // If any entry has a date less than last_check it should be deleted.
    char *wazuhdb_query = NULL;
    char *response = NULL;
    int db_result;

    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);

    snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck cleandb ",
            lf->agent_id
    );

    db_result = send_query_wazuhdb(wazuhdb_query, &response, sdb);

    switch (db_result) {
    case -2:
        merror("FIM decoder: Bad result from cleandb query: '%s'.", wazuhdb_query);
        // Fallthrough
    case -1:
        os_free(wazuhdb_query);
        os_free(response);
        return (-1);
    }

    mdebug2("Agent '%s' FIM database has been cleaned", lf->agent_id);

    os_free(wazuhdb_query);
    os_free(response);
    return (1);

}

int fim_get_scantime (long *ts, Eventinfo *lf, _sdb *sdb) {
    char *wazuhdb_query = NULL;
    char *response = NULL;
    char *output;
    int db_result;

    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);

    snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck scan_info_get end_scan",
            lf->agent_id
    );

    db_result = send_query_wazuhdb(wazuhdb_query, &response, sdb);

    switch (db_result) {
    case -2:
        merror("FIM decoder: Bad result getting scan date '%s'.", wazuhdb_query);
        // Fallthrough
    case -1:
        os_free(wazuhdb_query);
        os_free(response);
        return (-1);
    }

    output = strchr(response, ' ');
    *(output++) = '\0';

    *ts = atol(output);

    mdebug2("Agent '%s' FIM end_scan '%ld'", lf->agent_id, *ts);

    os_free(wazuhdb_query);
    os_free(response);
    return (1);
}
