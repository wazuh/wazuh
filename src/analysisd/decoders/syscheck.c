/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
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
#include "wazuhdb_op.h"

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when testing */
#define static

/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#endif

// Add events into sqlite DB for FIM
static int fim_db_search (char *f_name, char *c_sum, char *w_sum, Eventinfo *lf, _sdb *sdb);

// Build FIM alert
static int fim_alert (char *f_name, sk_sum_t *oldsum, sk_sum_t *newsum, Eventinfo *lf, _sdb *localsdb, syscheck_event_t event_type);

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
int fim_get_scantime (long *ts, Eventinfo *lf, _sdb *sdb, const char *param);

// Process fim alert
static int fim_process_alert(_sdb *sdb, Eventinfo *lf, cJSON *event);

// Generate fim alert

/**
 * @brief Generate fim alert
 *
 * @param lf Event information
 * @param attributes New file attributes
 * @param old_attributes File attributes before the alert
 * @param audit Audit information
 *
 * @returns 0 on success, -1 on failure
*/
static int fim_generate_alert(Eventinfo *lf, syscheck_event_t event_type, cJSON *attributes, cJSON *old_attributes, cJSON *audit);

// Send save query to Wazuh DB
static void fim_send_db_save(_sdb * sdb, const char * agent_id, cJSON * data);

// Send delete query to Wazuh DB
void fim_send_db_delete(_sdb * sdb, const char * agent_id, const char * path);

// Send a query to Wazuh DB
void fim_send_db_query(int * sock, const char * query);

// Build change comment
static size_t fim_generate_comment(char * str, long size, const char * format, const char * a1, const char * a2);

// Process scan info event
static void fim_process_scan_info(_sdb * sdb, const char * agent_id, fim_scan_event event, cJSON * data);

// Extract the file attributes from the JSON object
static int fim_fetch_attributes(cJSON *new_attrs, cJSON *old_attrs, Eventinfo *lf);
static int fim_fetch_attributes_state(cJSON *attr, Eventinfo *lf, char new_state);

// Replace the coded fields with the decoded ones in the checksum
static void fim_adjust_checksum(sk_sum_t *newsum, char **checksum);

/**
 * @brief Decode a cJSON with Windows permissions and convert to old format string
 *
 * @param perm_json cJSON with the permissions
 *
 * @returns A string with the old format Windows permissions
*/
static char *perm_json_to_old_format(cJSON *perm_json);

// Mutexes
static pthread_mutex_t control_msg_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct _fim_decoders_t {
    int add_id;
    char *add_name;
    int modify_id;
    char *modify_name;
    int delete_id;
    char *delete_name;
} fim_decoders_t;

typedef enum DECODER_TYPE { FILE_DECODER, REGISTRY_KEY_DECODER, REGISTRY_VALUE_DECODER } DECODER_TYPE;

static fim_decoders_t file_decoders;
static fim_decoders_t registry_key_decoders;
static fim_decoders_t registry_value_decoders;
static fim_decoders_t *fim_decoders[] = {
    [FILE_DECODER] = &file_decoders,
    [REGISTRY_KEY_DECODER] = &registry_key_decoders,
    [REGISTRY_VALUE_DECODER] = &registry_value_decoders,
};
OSHash *fim_agentinfo;

// Initialize the necessary information to process the syscheck information
// LCOV_EXCL_START
int fim_init(void) {
    //Create hash table for agent information
    fim_agentinfo = OSHash_Create();
    fim_decoders[FILE_DECODER]->add_id = getDecoderfromlist(FIM_NEW, &os_analysisd_decoder_store);
    fim_decoders[FILE_DECODER]->add_name = FIM_NEW;
    fim_decoders[FILE_DECODER]->modify_id = getDecoderfromlist(FIM_MOD, &os_analysisd_decoder_store);
    fim_decoders[FILE_DECODER]->modify_name = FIM_MOD;
    fim_decoders[FILE_DECODER]->delete_id = getDecoderfromlist(FIM_DEL, &os_analysisd_decoder_store);
    fim_decoders[FILE_DECODER]->delete_name = FIM_DEL;
    fim_decoders[REGISTRY_KEY_DECODER]->add_id = getDecoderfromlist(FIM_REG_KEY_NEW, &os_analysisd_decoder_store);
    fim_decoders[REGISTRY_KEY_DECODER]->add_name = FIM_REG_KEY_NEW;
    fim_decoders[REGISTRY_KEY_DECODER]->modify_id = getDecoderfromlist(FIM_REG_KEY_MOD, &os_analysisd_decoder_store);
    fim_decoders[REGISTRY_KEY_DECODER]->modify_name = FIM_REG_KEY_MOD;
    fim_decoders[REGISTRY_KEY_DECODER]->delete_id = getDecoderfromlist(FIM_REG_KEY_DEL, &os_analysisd_decoder_store);
    fim_decoders[REGISTRY_KEY_DECODER]->delete_name = FIM_REG_KEY_DEL;
    fim_decoders[REGISTRY_VALUE_DECODER]->add_id = getDecoderfromlist(FIM_REG_VAL_NEW, &os_analysisd_decoder_store);
    fim_decoders[REGISTRY_VALUE_DECODER]->add_name = FIM_REG_VAL_NEW;
    fim_decoders[REGISTRY_VALUE_DECODER]->modify_id = getDecoderfromlist(FIM_REG_VAL_MOD, &os_analysisd_decoder_store);
    fim_decoders[REGISTRY_VALUE_DECODER]->modify_name = FIM_REG_VAL_MOD;
    fim_decoders[REGISTRY_VALUE_DECODER]->delete_id = getDecoderfromlist(FIM_REG_VAL_DEL, &os_analysisd_decoder_store);
    fim_decoders[REGISTRY_VALUE_DECODER]->delete_name = FIM_REG_VAL_DEL;
    if (fim_agentinfo == NULL) return 0;
    return 1;
}

// Initialize the necessary information to process the syscheck information
void sdb_init(_sdb *localsdb, OSDecoderInfo *fim_decoder) {
    localsdb->db_err = 0;
    localsdb->socket = -1;

    sdb_clean(localsdb);

    // Create decoder
    fim_decoder->id = getDecoderfromlist(FIM_MOD, &os_analysisd_decoder_store);
    fim_decoder->name = FIM_MOD;
    fim_decoder->type = OSSEC_RL;
    fim_decoder->fts = 0;

    os_calloc(Config.decoder_order_size, sizeof(char *), fim_decoder->fields);
    fim_decoder->fields[FIM_FILE] = "file";
    fim_decoder->fields[FIM_HARD_LINKS] = "hard_links";
    fim_decoder->fields[FIM_MODE] = "mode";
    fim_decoder->fields[FIM_SIZE] = "size";
    fim_decoder->fields[FIM_SIZE_BEFORE] = "size_before";
    fim_decoder->fields[FIM_PERM] = "perm";
    fim_decoder->fields[FIM_PERM_BEFORE] = "perm_before";
    fim_decoder->fields[FIM_UID] = "uid";
    fim_decoder->fields[FIM_UID_BEFORE] = "uid_before";
    fim_decoder->fields[FIM_GID] = "gid";
    fim_decoder->fields[FIM_GID_BEFORE] = "gid_before";
    fim_decoder->fields[FIM_MD5] = "md5";
    fim_decoder->fields[FIM_MD5_BEFORE] = "md5_before";
    fim_decoder->fields[FIM_SHA1] = "sha1";
    fim_decoder->fields[FIM_SHA1_BEFORE] = "sha1_before";
    fim_decoder->fields[FIM_UNAME] = "uname";
    fim_decoder->fields[FIM_UNAME_BEFORE] = "uname_before";
    fim_decoder->fields[FIM_GNAME] = "gname";
    fim_decoder->fields[FIM_GNAME_BEFORE] = "gname_before";
    fim_decoder->fields[FIM_MTIME] = "mtime";
    fim_decoder->fields[FIM_MTIME_BEFORE] = "mtime_before";
    fim_decoder->fields[FIM_INODE] = "inode";
    fim_decoder->fields[FIM_INODE_BEFORE] = "inode_before";
    fim_decoder->fields[FIM_SHA256] = "sha256";
    fim_decoder->fields[FIM_SHA256_BEFORE] = "sha256_before";
    fim_decoder->fields[FIM_DIFF] = "changed_content";
    fim_decoder->fields[FIM_ATTRS] = "win_attributes";
    fim_decoder->fields[FIM_ATTRS_BEFORE] = "win_attributes_before";
    fim_decoder->fields[FIM_CHFIELDS] = "changed_fields";
    fim_decoder->fields[FIM_USER_ID] = "user_id";
    fim_decoder->fields[FIM_USER_NAME] = "user_name";
    fim_decoder->fields[FIM_GROUP_ID] = "group_id";
    fim_decoder->fields[FIM_GROUP_NAME] = "group_name";
    fim_decoder->fields[FIM_PROC_NAME] = "process_name";
    fim_decoder->fields[FIM_PROC_PNAME] = "parent_name";
    fim_decoder->fields[FIM_AUDIT_CWD] = "cwd";
    fim_decoder->fields[FIM_AUDIT_PCWD] = "parent_cwd";
    fim_decoder->fields[FIM_AUDIT_ID] = "audit_uid";
    fim_decoder->fields[FIM_AUDIT_NAME] = "audit_name";
    fim_decoder->fields[FIM_EFFECTIVE_UID] = "effective_uid";
    fim_decoder->fields[FIM_EFFECTIVE_NAME] = "effective_name";
    fim_decoder->fields[FIM_PPID] = "ppid";
    fim_decoder->fields[FIM_PROC_ID] = "process_id";
    fim_decoder->fields[FIM_TAG] = "tag";
    fim_decoder->fields[FIM_SYM_PATH] = "symbolic_path";
    fim_decoder->fields[FIM_REGISTRY_ARCH] = "arch";
    fim_decoder->fields[FIM_REGISTRY_VALUE_NAME] = "value_name";
    fim_decoder->fields[FIM_REGISTRY_VALUE_TYPE] = "value_type";
    fim_decoder->fields[FIM_REGISTRY_HASH] = "hash_full_path";
    fim_decoder->fields[FIM_ENTRY_TYPE] = "entry_type";
    fim_decoder->fields[FIM_EVENT_TYPE] = "event_type";
}

// Initialize the necessary information to process the syscheck information
void sdb_clean(_sdb *localsdb) {
    *localsdb->comment = '\0';
    *localsdb->size = '\0';
    *localsdb->perm = '\0';
    *localsdb->attrs = '\0';
    *localsdb->sym_path = '\0';
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

    /* Every syscheck message must be in the following format (OSSEC - Wazuh v3.10):
     * 'checksum' 'filename'
     * or
     * 'checksum'!'extradata' 'filename'
     * or
     *                                             |v2.1       |v3.4  |v3.4         |v3.6  |v3.9               |v1.0
     *                                             |->         |->    |->           |->   |->                  |->
     * "size:permision:uid:gid:md5:sha1:uname:gname:mtime:inode:sha256!w:h:o:d:a:t:a:tags:symbolic_path:silent filename\nreportdiff"
     *  ^^^^^^^^^^^^^^^^^^^^^^^^^^^checksum^^^^^^^^^^^^^^^^^^^^^^^^^^^!^^^^^^^^^^^^^^extradata^^^^^^^^^^^^^^^^ filename\n^^^diff^^^
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
            merror(FIM_INVALID_MESSAGE);
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
    char *diff = strchr(f_name, '\n');
    if (diff) {
        *(diff++) = '\0';
        os_strdup(diff, lf->fields[FIM_DIFF].value);
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
    char *sym_path = NULL;
    sk_sum_t oldsum = { .size = NULL };
    sk_sum_t newsum = { .size = NULL };
    time_t *end_first_scan = NULL;
    time_t end_scan = 0;
    syscheck_event_t event_type;

    memset(&oldsum, 0, sizeof(sk_sum_t));
    memset(&newsum, 0, sizeof(sk_sum_t));

    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);
    os_strdup(c_sum, new_check_sum);

    snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck load %s", lf->agent_id, f_name);

    os_calloc(OS_SIZE_6144, sizeof(char), response);
    db_result = wdbc_query_ex(&sdb->socket, wazuhdb_query, response, OS_SIZE_6144);

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

    if (strcmp(response, "ok") != 0) {
        goto exit_fail;
    }

    //extract changes and date_alert fields only available from wazuh_db
    sk_decode_extradata(&oldsum, check_sum);

    os_strdup(check_sum, old_check_sum);
    mdebug2("Agent '%s' File '%s'", lf->agent_id, f_name);
    mdebug2("Agent '%s' Old checksum '%s'", lf->agent_id, old_check_sum);
    mdebug2("Agent '%s' New checksum '%s'", lf->agent_id, new_check_sum);

    if (decode_newsum = sk_decode_sum(&newsum, c_sum, w_sum), decode_newsum != -1) {
        InsertWhodata(&newsum, sdb);
    }

    fim_adjust_checksum(&newsum, &new_check_sum);

    // Checksum match, we can just return and keep going
    if (SumCompare(old_check_sum, new_check_sum) == 0) {
        mdebug1("Agent '%s' Alert discarded '%s' same check_sum", lf->agent_id, f_name);
        fim_update_date (f_name, lf, sdb);
        goto exit_ok;
    }

    wazuhdb_query[0] = '\0';
    switch (decode_newsum) {
        case 1: // File deleted
            os_strdup(SYSCHECK_EVENT_STRINGS[FIM_DELETED], lf->fields[FIM_EVENT_TYPE].value);
            event_type = FIM_DELETED;

            if(!*old_check_sum){
                mdebug2("Agent '%s' Alert already reported (double delete alert)", lf->agent_id);
                goto exit_ok;
            }

            snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck delete %s",
                    lf->agent_id,
                    f_name
            );

            db_result = wdbc_query_ex(&sdb->socket, wazuhdb_query, response, OS_SIZE_6144);

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
                os_strdup(SYSCHECK_EVENT_STRINGS[FIM_MODIFIED], lf->fields[FIM_EVENT_TYPE].value);
                event_type = FIM_MODIFIED;
                changes = fim_check_changes(oldsum.changes, oldsum.date_alert, lf);
                sk_decode_sum(&oldsum, old_check_sum, NULL);

                // Alert discarded, frequency exceeded
                if (changes == -1) {
                    mdebug1("Agent '%s' Alert discarded '%s' frequency exceeded", lf->agent_id, f_name);
                    goto exit_ok;
                }
            } else {
                // File added
                os_strdup(SYSCHECK_EVENT_STRINGS[FIM_ADDED], lf->fields[FIM_EVENT_TYPE].value);
                event_type = FIM_ADDED;
            }

            if (strstr(lf->location, "syscheck-registry")) {
                *ttype = "registry";
            } else {
                *ttype = "file";
            }

            if (newsum.symbolic_path) {
                sym_path = escape_syscheck_field(newsum.symbolic_path);
            }

            // We need to escape the checksum because it will have
            // spaces if the event comes from Windows
            char *checksum_esc = wstr_replace(new_check_sum, " ", "\\ ");
            snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck save %s %s!%d:%ld:%s %s",
                    lf->agent_id,
                    *ttype,
                    checksum_esc,
                    changes,
                    lf->time.tv_sec,
                    sym_path ? sym_path : "",
                    f_name
            );
            os_free(sym_path);
            os_free(checksum_esc);
            db_result = wdbc_query_ex(&sdb->socket, wazuhdb_query, response, OS_SIZE_6144);

            switch (db_result) {
            case -2:
                merror("FIM decoder: Bad save/update query: '%s'.", wazuhdb_query);
                // Fallthrough
            case -1:
                goto exit_fail;
            }

            mdebug2("Agent '%s' File %s saved/updated in FIM DDBB", lf->agent_id, f_name);

            if (end_first_scan = (time_t *)OSHash_Get_ex(fim_agentinfo, lf->agent_id), end_first_scan == NULL) {
                fim_get_scantime(&end_scan, lf, sdb, "end_scan");
                os_calloc(1, sizeof(time_t), end_first_scan);
                *end_first_scan = end_scan;
                int res;
                if (res = OSHash_Add_ex(fim_agentinfo, lf->agent_id, end_first_scan), res != 2) {
                    os_free(end_first_scan);
                    if (res == 0) {
                        merror("Unable to add scan_info to hash table for agent: %s", lf->agent_id);
                    }
                }
            } else {
                end_scan = *end_first_scan;
            }

            if (event_type == FIM_ADDED) {
                if (end_scan == 0) {
                    mdebug2("Agent '%s' Alert discarded, first scan. File '%s'", lf->agent_id, f_name);
                    goto exit_ok;
                } else if (lf->time.tv_sec < end_scan) {
                    mdebug2("Agent '%s' Alert discarded, first scan (delayed event). File '%s'", lf->agent_id, f_name);
                    goto exit_ok;
                } else if (Config.syscheck_alert_new == 0) {
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

    if (!newsum.silent) {
        sk_fill_event(lf, f_name, &newsum);

        /* Dyanmic Fields */
        lf->nfields = FIM_NFIELDS;
        for (i = 0; i < FIM_NFIELDS; i++) {
            os_strdup(lf->decoder_info->fields[i], lf->fields[i].key);
        }

        if(fim_alert(f_name, &oldsum, &newsum, lf, sdb, event_type) == -1) {
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
    } else {
        mdebug2("Ignoring FIM event on '%s'.", f_name);
    }

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

int fim_alert (char *f_name, sk_sum_t *oldsum, sk_sum_t *newsum, Eventinfo *lf, _sdb *localsdb, syscheck_event_t event_type) {
    int changes = 0;
    char msg_type[OS_FLSIZE];
    char buf_ptr[26];

    if (event_type == FIM_DELETED) {
        snprintf(msg_type, sizeof(msg_type), "was deleted.");
        lf->decoder_info->id = fim_decoders[FILE_DECODER]->delete_id;
        lf->decoder_syscheck_id = lf->decoder_info->id;
        lf->decoder_info->name = fim_decoders[FILE_DECODER]->delete_name;
        changes = 1;
    } else if (event_type == FIM_ADDED) {
        snprintf(msg_type, sizeof(msg_type), "was added.");
        lf->decoder_info->id = fim_decoders[FILE_DECODER]->add_id;
        lf->decoder_syscheck_id = lf->decoder_info->id;
        lf->decoder_info->name = fim_decoders[FILE_DECODER]->add_name;
        changes = 1;
    } else if (event_type == FIM_MODIFIED) {
        snprintf(msg_type, sizeof(msg_type), "checksum changed.");
        lf->decoder_info->id = fim_decoders[FILE_DECODER]->modify_id;
        lf->decoder_syscheck_id = lf->decoder_info->id;
        lf->decoder_info->name = fim_decoders[FILE_DECODER]->modify_name;
        if (oldsum->size && newsum->size) {
            if (strcmp(oldsum->size, newsum->size) == 0) {
                localsdb->size[0] = '\0';
            } else {
                changes = 1;
                wm_strcat(&lf->fields[FIM_CHFIELDS].value, "size", ',');
                snprintf(localsdb->size, OS_FLSIZE,
                            "Size changed from '%s' to '%s'\n",
                            oldsum->size, newsum->size);

                os_strdup(oldsum->size, lf->fields[FIM_SIZE_BEFORE].value);
            }
        }

        /* Permission message */
        if (oldsum->perm && newsum->perm) {
            if (oldsum->perm == newsum->perm) {
                localsdb->perm[0] = '\0';
            } else if (oldsum->perm > 0 && newsum->perm > 0) {
                changes = 1;
                wm_strcat(&lf->fields[FIM_CHFIELDS].value, "perm", ',');
                char opstr[10];
                char npstr[10];
                lf->fields[FIM_PERM_BEFORE].value = agent_file_perm(oldsum->perm);
                char *new_perm = agent_file_perm(newsum->perm);

                strncpy(opstr, lf->fields[FIM_PERM_BEFORE].value, sizeof(opstr) - 1);
                strncpy(npstr, new_perm, sizeof(npstr) - 1);
                free(new_perm);

                opstr[9] = npstr[9] = '\0';
                snprintf(localsdb->perm, OS_FLSIZE, "Permissions changed from "
                            "'%9.9s' to '%9.9s'\n", opstr, npstr);
            }
        } else if (oldsum->win_perm && newsum->win_perm) { // Check for Windows permissions
            // We need to unescape the old permissions at this point
            char *unesc_perms = wstr_replace(oldsum->win_perm, "\\:", ":");
            free(oldsum->win_perm);
            oldsum->win_perm = unesc_perms;
            if (strcmp(oldsum->win_perm, newsum->win_perm) == 0) {
                localsdb->perm[0] = '\0';
            } else if (*oldsum->win_perm != '\0' && *newsum->win_perm != '\0') {
                changes = 1;
                wm_strcat(&lf->fields[FIM_CHFIELDS].value, "perm", ',');
                snprintf(localsdb->perm, OS_FLSIZE, "Permissions changed.\n");
                os_strdup(oldsum->win_perm, lf->fields[FIM_PERM_BEFORE].value);
            }
        }

        /* Ownership message */
        if (newsum->uid && oldsum->uid) {
            if (strcmp(newsum->uid, oldsum->uid) == 0) {
                localsdb->owner[0] = '\0';
            } else {
                changes = 1;
                wm_strcat(&lf->fields[FIM_CHFIELDS].value, "uid", ',');
                if (oldsum->uname && newsum->uname) {
                    snprintf(localsdb->owner, OS_FLSIZE, "Ownership was '%s (%s)', now it is '%s (%s)'\n", oldsum->uname, oldsum->uid, newsum->uname, newsum->uid);
                    os_strdup(oldsum->uname, lf->fields[FIM_UNAME_BEFORE].value);
                } else {
                    snprintf(localsdb->owner, OS_FLSIZE, "Ownership was '%s', now it is '%s'\n", oldsum->uid, newsum->uid);
                }
                os_strdup(oldsum->uid, lf->fields[FIM_UID_BEFORE].value);
            }
        }

        /* Group ownership message */
        if (newsum->gid && oldsum->gid) {
            if (strcmp(newsum->gid, oldsum->gid) == 0) {
                localsdb->gowner[0] = '\0';
            } else {
                changes = 1;
                wm_strcat(&lf->fields[FIM_CHFIELDS].value, "gid", ',');
                if (oldsum->gname && newsum->gname) {
                    snprintf(localsdb->gowner, OS_FLSIZE, "Group ownership was '%s (%s)', now it is '%s (%s)'\n", oldsum->gname, oldsum->gid, newsum->gname, newsum->gid);
                    os_strdup(oldsum->gname, lf->fields[FIM_GNAME_BEFORE].value);
                } else {
                    snprintf(localsdb->gowner, OS_FLSIZE, "Group ownership was '%s', now it is '%s'\n", oldsum->gid, newsum->gid);
                }
                os_strdup(oldsum->gid, lf->fields[FIM_GID_BEFORE].value);
            }
        }
        /* MD5 message */
        if (!*newsum->md5 || !*oldsum->md5 || strcmp(newsum->md5, oldsum->md5) == 0) {
            localsdb->md5[0] = '\0';
        } else {
            changes = 1;
            wm_strcat(&lf->fields[FIM_CHFIELDS].value, "md5", ',');
            snprintf(localsdb->md5, OS_FLSIZE, "Old md5sum was: '%s'\nNew md5sum is : '%s'\n",
                        oldsum->md5, newsum->md5);
            os_strdup(oldsum->md5, lf->fields[FIM_MD5_BEFORE].value);
        }

        /* SHA-1 message */
        if (!*newsum->sha1 || !*oldsum->sha1 || strcmp(newsum->sha1, oldsum->sha1) == 0) {
            localsdb->sha1[0] = '\0';
        } else {
            changes = 1;
            wm_strcat(&lf->fields[FIM_CHFIELDS].value, "sha1", ',');
            snprintf(localsdb->sha1, OS_FLSIZE, "Old sha1sum was: '%s'\nNew sha1sum is : '%s'\n",
                        oldsum->sha1, newsum->sha1);
            os_strdup(oldsum->sha1, lf->fields[FIM_SHA1_BEFORE].value);
        }

        /* SHA-256 message */
        if(newsum->sha256 && newsum->sha256[0] != '\0') {
            if(oldsum->sha256) {
                if (strcmp(newsum->sha256, oldsum->sha256) == 0) {
                    localsdb->sha256[0] = '\0';
                } else {
                    changes = 1;
                    wm_strcat(&lf->fields[FIM_CHFIELDS].value, "sha256", ',');
                    snprintf(localsdb->sha256, OS_FLSIZE, "Old sha256sum was: '%s'\nNew sha256sum is : '%s'\n",
                            oldsum->sha256, newsum->sha256);
                    os_strdup(oldsum->sha256, lf->fields[FIM_SHA256_BEFORE].value);
                }
            } else {
                changes = 1;
                wm_strcat(&lf->fields[FIM_CHFIELDS].value, "sha256", ',');
                snprintf(localsdb->sha256, OS_FLSIZE, "New sha256sum is : '%s'\n", newsum->sha256);
            }
        } else {
            localsdb->sha256[0] = '\0';
        }

        /* Modification time message */
        if (oldsum->mtime && newsum->mtime && oldsum->mtime != newsum->mtime) {
            changes = 1;
            wm_strcat(&lf->fields[FIM_CHFIELDS].value, "mtime", ',');
            char *old_ctime = strdup(ctime_r(&oldsum->mtime, buf_ptr));
            char *new_ctime = strdup(ctime_r(&newsum->mtime, buf_ptr));
            old_ctime[strlen(old_ctime) - 1] = '\0';
            new_ctime[strlen(new_ctime) - 1] = '\0';

            snprintf(localsdb->mtime, OS_FLSIZE, "Old modification time was: '%s', now it is '%s'\n", old_ctime, new_ctime);
            lf->fields[FIM_MTIME_BEFORE].value = w_long_str(oldsum->mtime);
            os_free(old_ctime);
            os_free(new_ctime);
        } else {
            localsdb->mtime[0] = '\0';
        }

        /* Inode message */
        if (oldsum->inode && newsum->inode && oldsum->inode != newsum->inode) {
            changes = 1;
            wm_strcat(&lf->fields[FIM_CHFIELDS].value, "inode", ',');
            snprintf(localsdb->inode, OS_FLSIZE, "Old inode was: '%ld', now it is '%ld'\n", oldsum->inode, newsum->inode);
            lf->fields[FIM_INODE_BEFORE].value = w_long_str(oldsum->inode);
        } else {
            localsdb->inode[0] = '\0';
        }

        /* Attributes message */
        if (oldsum->attributes && newsum->attributes
            && strcmp(oldsum->attributes, newsum->attributes)) {
            changes = 1;
            wm_strcat(&lf->fields[FIM_CHFIELDS].value, "attributes", ',');
            snprintf(localsdb->attrs, OS_SIZE_1024, "Old attributes were: '%s'\nNow they are '%s'\n", oldsum->attributes, newsum->attributes);
            os_strdup(oldsum->attributes, lf->fields[FIM_ATTRS_BEFORE].value);
        } else {
            localsdb->attrs[0] = '\0';
        }
    } else {
        return (-1);
    }

    /* Symbolic path message */
    if (newsum->symbolic_path && *newsum->symbolic_path) {
        snprintf(localsdb->sym_path, OS_FLSIZE, "Symbolic path: '%s'.\n", newsum->symbolic_path);
    } else {
        *localsdb->sym_path = '\0';
    }

    // Provide information about the file
    snprintf(localsdb->comment, OS_MAXSTR, "File"
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
            "%s",
            f_name,
            msg_type,
            localsdb->sym_path,
            localsdb->size,
            localsdb->perm,
            localsdb->owner,
            localsdb->gowner,
            localsdb->md5,
            localsdb->sha1,
            localsdb->sha256,
            localsdb->attrs,
            localsdb->mtime,
            localsdb->inode
    );
    if(!changes) {
        os_free(lf->data);
        return(-1);
    } else if (lf->fields[FIM_CHFIELDS].value != NULL) {
        wm_strcat(&lf->fields[FIM_CHFIELDS].value, ",", '\0');
    }

    // Create a new log message
    free(lf->full_log);
    os_strdup(localsdb->comment, lf->full_log);
    lf->log = lf->full_log;
    // Force clean event
    lf->program_name = NULL;
    lf->dec_timestamp = NULL;

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
    time_t ts_start;

    os_calloc(OS_SIZE_128, sizeof(char), msg);

    // If we don't have a valid syscheck message, it may be a scan control message
    if(strcmp(key, HC_FIM_DB_SFS) == 0) {
        snprintf(msg, OS_SIZE_128, "first_start");
    }
    if(strcmp(key, HC_FIM_DB_EFS) == 0) {
        if (fim_get_scantime(&ts_start, lf, sdb, "start_scan") == 1) {
            if (ts_start == 0) {
                free(msg);
                return (-1);
            }
        }
        snprintf(msg, OS_SIZE_128, "first_end");
    }
    if(strcmp(key, HC_FIM_DB_SS) == 0) {
        snprintf(msg, OS_SIZE_128, "start_scan");
    }
    if(strcmp(key, HC_FIM_DB_ES) == 0) {
        if (fim_get_scantime(&ts_start, lf, sdb, "start_scan") == 1) {
            if (ts_start == 0) {
                free(msg);
                return (-1);
            }
        }
        snprintf(msg, OS_SIZE_128, "end_scan");
    }
    if(strcmp(key, HC_SK_DB_COMPLETED) == 0) {
        snprintf(msg, OS_SIZE_128, "end_scan");
    }

    if (*msg != '\0') {
        os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);

        snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck scan_info_update %s %ld",
                lf->agent_id,
                msg,
                (long int)value
        );

        os_calloc(OS_SIZE_6144, sizeof(char), response);
        db_result = wdbc_query_ex(&sdb->socket, wazuhdb_query, response, OS_SIZE_6144);

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

            db_result = wdbc_query_ex(&sdb->socket, wazuhdb_query, response, OS_SIZE_6144);

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

    os_calloc(OS_SIZE_6144, sizeof(char), response);
    db_result = wdbc_query_ex(&sdb->socket, wazuhdb_query, response, OS_SIZE_6144);

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

    os_calloc(OS_SIZE_6144, sizeof(char), response);
    db_result = wdbc_query_ex(&sdb->socket, wazuhdb_query, response, OS_SIZE_6144);

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

int fim_get_scantime (long *ts, Eventinfo *lf, _sdb *sdb, const char* param) {
    char *wazuhdb_query = NULL;
    char *response = NULL;
    char *output;
    int db_result;

    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);

    snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s syscheck scan_info_get %s",
            lf->agent_id, param
    );

    os_calloc(OS_SIZE_6144, sizeof(char), response);
    db_result = wdbc_query_ex(&sdb->socket, wazuhdb_query, response, OS_SIZE_6144);

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

    if (!output) {
        merror("FIM decoder: Bad formatted response '%s'", response);
        os_free(wazuhdb_query);
        os_free(response);
        return (-1);
    }

    *(output++) = '\0';
    *ts = atol(output);

    mdebug2("Agent '%s' FIM %s '%ld'", lf->agent_id, param, *ts);

    os_free(wazuhdb_query);
    os_free(response);
    return (1);
}
// LCOV_EXCL_STOP

int decode_fim_event(_sdb *sdb, Eventinfo *lf) {
    /* Every syscheck message must be in the following JSON format, as of agent version v3.11
     * {
     *   type:                  "event"
     *   data: {
     *     path:                string
     *     hard_links:          array
     *     mode:                "scheduled"|"realtime"|"whodata"
     *     type:                "added"|"deleted"|"modified"
     *     timestamp:           number
     *     changed_attributes: [
     *       "size"
     *       "permission"
     *       "uid"
     *       "user_name"
     *       "gid"
     *       "group_name"
     *       "mtime"
     *       "inode"
     *       "md5"
     *       "sha1"
     *       "sha256"
     *     ]
     *     tags:                string
     *     content_changes:     string
     *     old_attributes: {
     *       type:              "file"|"registry"
     *       size:              number
     *       perm:              string
     *       user_name:         string
     *       group_name:        string
     *       uid:               string
     *       gid:               string
     *       inode:             number
     *       mtime:             number
     *       hash_md5:          string
     *       hash_sha1:         string
     *       hash_sha256:       string
     *       win_attributes:    string
     *       symlink_path:      string
     *       checksum:          string
     *     }
     *     attributes: {
     *       type:              "file"|"registry"
     *       size:              number
     *       perm:              string
     *       user_name:         string
     *       group_name:        string
     *       uid:               string
     *       gid:               string
     *       inode:             number
     *       mtime:             number
     *       hash_md5:          string
     *       hash_sha1:         string
     *       hash_sha256:       string
     *       win_attributes:    string
     *       symlink_path:      string
     *       checksum:          string
     *     }
     *     audit: {
     *       user_id:           string
     *       user_name:         string
     *       group_id:          string
     *       group_name:        string
     *       process_name:      string
     *       cwd:               string
     *       audit_uid:         string
     *       audit_name:        string
     *       effective_uid:     string
     *       effective_name:    string
     *       parent_name:       string
     *       parent_cwd:        string
     *       ppid:              number
     *       process_id:        number
     *     }
     *   }
     * }
     *
     * Scan info events:
     * {
     *   type:                  "scan_start"|"scan_end"
     *   data: {
     *     timestamp:           number
     *   }
     * }
     */

    cJSON *root_json = NULL;
    int retval = 0;

    assert(sdb != NULL);
    assert(lf != NULL);

    if (root_json = cJSON_Parse(lf->log), !root_json) {
        merror("Malformed FIM JSON event");
        return retval;
    }

    char * type = cJSON_GetStringValue(cJSON_GetObjectItem(root_json, "type"));
    cJSON * data = cJSON_GetObjectItem(root_json, "data");

    if (type != NULL && data != NULL) {
        if (strcmp(type, "event") == 0) {
            if (fim_process_alert(sdb, lf, data) == -1) {
                merror("Can't generate fim alert for event: '%s'", lf->log);
                cJSON_Delete(root_json);
                return retval;
            }

            retval = 1;
        } else if (strcmp(type, "scan_start") == 0) {
            fim_process_scan_info(sdb, lf->agent_id, FIM_SCAN_START, data);
        } else if (strcmp(type, "scan_end") == 0) {
            fim_process_scan_info(sdb, lf->agent_id, FIM_SCAN_END, data);
        }
    } else {
        merror("Invalid FIM event");
        cJSON_Delete(root_json);
        return retval;
    }

    cJSON_Delete(root_json);
    return retval;
}


static int fim_process_alert(_sdb * sdb, Eventinfo *lf, cJSON * event) {
    cJSON *attributes = NULL;
    cJSON *old_attributes = NULL;
    cJSON *audit = NULL;
    cJSON *object = NULL;
    int version = 0;
    char *entry_type = NULL;
    fim_decoders_t *decoder = NULL;
    syscheck_event_t event_type;

    cJSON_ArrayForEach(object, event) {
        if (object->string == NULL) {
            mdebug1("FIM event contains an item with no key.");
            return -1;
        }

        switch (object->type) {
        case cJSON_String:
            if (strcmp(object->string, "path") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_FILE].value);
            } else if (strcmp(object->string, "mode") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_MODE].value);
            } else if (strcmp(object->string, "type") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_EVENT_TYPE].value);
            } else if (strcmp(object->string, "tags") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_TAG].value);
            } else if (strcmp(object->string, "content_changes") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_DIFF].value);
            } else if (strcmp(object->string, "arch") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_REGISTRY_ARCH].value);
            } else if (strcmp(object->string, "value_name") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_REGISTRY_VALUE_NAME].value);
            } else if (strcmp(object->string, "index") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_REGISTRY_HASH].value);
            }

            break;

        case cJSON_Array:
            if (strcmp(object->string, "changed_attributes") == 0) {
                cJSON *item;

                cJSON_ArrayForEach(item, object) {
                    wm_strcat(&lf->fields[FIM_CHFIELDS].value, item->valuestring, ',');
                }
            } else if (strcmp(object->string, "hard_links") == 0) {
                lf->fields[FIM_HARD_LINKS].value = cJSON_PrintUnformatted(object);
            }

            break;

        case cJSON_Object:
            if (strcmp(object->string, "attributes") == 0) {
                attributes = object;
            } else if (strcmp(object->string, "old_attributes") == 0) {
                old_attributes = object;
            } else if (strcmp(object->string, "audit") == 0) {
                audit = object;
            }

            break;

        case cJSON_Number:
            if (strcmp(object->string, "version") == 0) {
                version = object->valueint;
            }

            break;
        }
    }

    entry_type = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type"));
    if (entry_type == NULL) {
        mdebug1("No member 'type' in Syscheck attributes JSON payload");
        return -1;
    }

    if (((strcmp("registry_key", entry_type) == 0) || (strcmp("registry_value", entry_type) == 0)) && version >= 3) {
        if (lf->fields[FIM_REGISTRY_HASH].value == NULL) {
            mdebug1("No member 'index' in Syscheck JSON payload");
            return -1;
        }
    }

    if (lf->fields[FIM_EVENT_TYPE].value == NULL) {
        mdebug1("No member 'type' in Syscheck JSON payload");
        return -1;
    }

    if (lf->fields[FIM_FILE].value == NULL) {
        mdebug1("No member 'path' in Syscheck JSON payload");
        return -1;
    }

    if (strcmp("file", entry_type) == 0 || strcmp("registry", entry_type) == 0) {
        decoder = fim_decoders[FILE_DECODER];
    } else if (strcmp("registry_key", entry_type) == 0) {
        decoder = fim_decoders[REGISTRY_KEY_DECODER];
    } else if (strcmp("registry_value", entry_type) == 0) {
        decoder = fim_decoders[REGISTRY_VALUE_DECODER];
    } else {
        mdebug1("Invalid member 'type' in Syscheck attributes JSON payload");
        return -1;
    }
    os_strdup(entry_type, lf->fields[FIM_ENTRY_TYPE].value);

    if (strcmp(SYSCHECK_EVENT_STRINGS[FIM_ADDED], lf->fields[FIM_EVENT_TYPE].value) == 0) {
        event_type = FIM_ADDED;
        lf->decoder_info->name = decoder->add_name;
        lf->decoder_info->id = decoder->add_id;
    } else if (strcmp(SYSCHECK_EVENT_STRINGS[FIM_MODIFIED], lf->fields[FIM_EVENT_TYPE].value) == 0) {
        event_type = FIM_MODIFIED;
        lf->decoder_info->name = decoder->modify_name;
        lf->decoder_info->id = decoder->modify_id;
    } else if (strcmp(SYSCHECK_EVENT_STRINGS[FIM_DELETED], lf->fields[FIM_EVENT_TYPE].value) == 0) {
        event_type = FIM_DELETED;
        lf->decoder_info->name = decoder->delete_name;
        lf->decoder_info->id =  decoder->delete_id;
    } else {
        mdebug1("Invalid 'type' value '%s' in JSON payload.", lf->fields[FIM_EVENT_TYPE].value);
        return -1;
    }

    lf->decoder_syscheck_id = lf->decoder_info->id;

    fim_generate_alert(lf, event_type, attributes, old_attributes, audit);

    if (event_type == FIM_ADDED || event_type == FIM_MODIFIED) {
        fim_send_db_save(sdb, lf->agent_id, event);
    } else if (event_type == FIM_DELETED) {
        if (strcmp("file", entry_type) == 0) {
            fim_send_db_delete(sdb, lf->agent_id, lf->fields[FIM_FILE].value);
        } else {
            fim_send_db_delete(sdb, lf->agent_id, lf->fields[FIM_REGISTRY_HASH].value);
        }
    }

    return 0;
}

void fim_send_db_save(_sdb * sdb, const char * agent_id, cJSON * data) {
    cJSON_DeleteItemFromObject(data, "mode");
    cJSON_DeleteItemFromObject(data, "type");
    cJSON_DeleteItemFromObject(data, "tags");
    cJSON_DeleteItemFromObject(data, "content_changes");
    cJSON_DeleteItemFromObject(data, "changed_attributes");
    cJSON_DeleteItemFromObject(data, "hard_links");
    cJSON_DeleteItemFromObject(data, "old_attributes");
    cJSON_DeleteItemFromObject(data, "audit");

    char * data_plain = cJSON_PrintUnformatted(data);
    char * query;

    os_malloc(OS_MAXSTR, query);

    if (snprintf(query, OS_MAXSTR, "agent %s syscheck save2 %s", agent_id, data_plain) >= OS_MAXSTR) {
        merror("FIM decoder: Cannot build save2 query: input is too long.");
        goto end;
    }

    fim_send_db_query(&sdb->socket, query);

end:
    free(data_plain);
    free(query);
}

void fim_send_db_delete(_sdb * sdb, const char * agent_id, const char * path) {
    char query[OS_SIZE_6144];

    if (snprintf(query, sizeof(query), "agent %s syscheck delete %s", agent_id, path) >= OS_SIZE_6144) {
        merror("FIM decoder: Cannot build delete query: input is too long.");
        return;
    }

    fim_send_db_query(&sdb->socket, query);
}

void fim_send_db_query(int * sock, const char * query) {
    char * response;
    char * arg;

    os_malloc(OS_MAXSTR, response);

    switch (wdbc_query_ex(sock, query, response, OS_MAXSTR)) {
    case -2:
        merror("FIM decoder: Cannot communicate with database.");
        goto end;
    case -1:
        merror("FIM decoder: Cannot get response from database.");
        goto end;
    }

    switch (wdbc_parse_result(response, &arg)) {
    case WDBC_OK:
        break;
    case WDBC_ERROR:
        if (strcmp(arg, "Agent not found") != 0) {
            merror("FIM decoder: Bad response from database: %s", arg);
        }
        // Fallthrough
    default:
        goto end;
    }

end:
    free(response);
}


static int fim_generate_alert(Eventinfo *lf, syscheck_event_t event_type, cJSON *attributes, cJSON *old_attributes, cJSON *audit) {
    static const char *ENTRY_TYPE_FILE = "File";
    static const char *ENTRY_TYPE_REGISTRY_KEY = "Registry Key";
    static const char *ENTRY_TYPE_REGISTRY_VALUE = "Registry Value";

    cJSON *object = NULL;
    char change_size[OS_FLSIZE + 1] = {'\0'};
    char change_perm[OS_FLSIZE + 1] = {'\0'};
    char change_owner[OS_FLSIZE + 1] = {'\0'};
    char change_user[OS_FLSIZE + 1] = {'\0'};
    char change_gowner[OS_FLSIZE + 1] = {'\0'};
    char change_group[OS_FLSIZE + 1] = {'\0'};
    char change_md5[OS_FLSIZE + 1] = {'\0'};
    char change_sha1[OS_FLSIZE + 1] = {'\0'};
    char change_sha256[OS_FLSIZE + 1] = {'\0'};
    char change_mtime[OS_FLSIZE + 1] = {'\0'};
    char change_inode[OS_FLSIZE + 1] = {'\0'};
    char change_win_attributes[OS_SIZE_256 + 1] = {'\0'};
    const char *entry_type = NULL;
    int it;
    int path_len = 0;
    char path_buffer[757] = "";
    char *path = path_buffer;

    /* Dynamic Fields */
    lf->nfields = FIM_NFIELDS;
    for (it = 0; it < FIM_NFIELDS; it++) {
        os_strdup(lf->decoder_info->fields[it], lf->fields[it].key);
    }

    if (fim_fetch_attributes(attributes, old_attributes, lf)) {
        return -1;
    }

    cJSON_ArrayForEach(object, audit) {
        if (object->string == NULL) {
            mdebug1("FIM audit set contains an item with no key.");
            return -1;
        }

        switch (object->type) {
        case cJSON_Number:
            if (strcmp(object->string, "ppid") == 0) {
                os_calloc(OS_SIZE_32, sizeof(char), lf->fields[FIM_PPID].value);
                snprintf(lf->fields[FIM_PPID].value, OS_SIZE_32, "%ld", (long)object->valuedouble);
            } else if (strcmp(object->string, "process_id") == 0) {
                os_calloc(OS_SIZE_32, sizeof(char), lf->fields[FIM_PROC_ID].value);
                snprintf(lf->fields[FIM_PROC_ID].value, OS_SIZE_32, "%ld", (long)object->valuedouble);
            }

            break;

        case cJSON_String:
            if (strcmp(object->string, "user_id") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_USER_ID].value);
            } else if (strcmp(object->string, "user_name") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_USER_NAME].value);
            } else if (strcmp(object->string, "group_id") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_GROUP_ID].value);
            } else if (strcmp(object->string, "group_name") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_GROUP_NAME].value);
            } else if (strcmp(object->string, "process_name") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_PROC_NAME].value);
            } else if (strcmp(object->string, "parent_name") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_PROC_PNAME].value);
            } else if (strcmp(object->string, "cwd") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_AUDIT_CWD].value);
            } else if (strcmp(object->string, "parent_cwd") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_AUDIT_PCWD].value);
            }else if (strcmp(object->string, "audit_uid") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_AUDIT_ID].value);
            } else if (strcmp(object->string, "audit_name") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_AUDIT_NAME].value);
            } else if (strcmp(object->string, "effective_uid") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_EFFECTIVE_UID].value);
            } else if (strcmp(object->string, "effective_name") == 0) {
                os_strdup(object->valuestring, lf->fields[FIM_EFFECTIVE_NAME].value);
            }
        }
    }

    // Format comment
    if (event_type == FIM_MODIFIED) {
        fim_generate_comment(change_size, sizeof(change_size), "Size changed from '%s' to '%s'\n", lf->fields[FIM_SIZE_BEFORE].value, lf->fields[FIM_SIZE].value);
        size_t size = fim_generate_comment(change_perm, sizeof(change_perm), "Permissions changed from '%s' to '%s'\n", lf->fields[FIM_PERM_BEFORE].value, lf->fields[FIM_PERM].value);
        if (size >= sizeof(change_perm)) {
            snprintf(change_perm, sizeof(change_perm), "Permissions changed.\n"); //LCOV_EXCL_LINE
        }
        fim_generate_comment(change_owner, sizeof(change_owner), "Ownership was '%s', now it is '%s'\n", lf->fields[FIM_UID_BEFORE].value, lf->fields[FIM_UID].value);
        fim_generate_comment(change_user, sizeof(change_owner), "User name was '%s', now it is '%s'\n", lf->fields[FIM_UNAME_BEFORE].value, lf->fields[FIM_UNAME].value);
        fim_generate_comment(change_gowner, sizeof(change_gowner), "Group ownership was '%s', now it is '%s'\n", lf->fields[FIM_GID_BEFORE].value, lf->fields[FIM_GID].value);
        fim_generate_comment(change_group, sizeof(change_gowner), "Group name was '%s', now it is '%s'\n", lf->fields[FIM_GNAME_BEFORE].value, lf->fields[FIM_GNAME].value);
        fim_generate_comment(change_mtime, sizeof(change_mtime), "Old modification time was: '%s', now it is '%s'\n", lf->fields[FIM_MTIME_BEFORE].value, lf->fields[FIM_MTIME].value);
        fim_generate_comment(change_inode, sizeof(change_inode), "Old inode was: '%s', now it is '%s'\n", lf->fields[FIM_INODE_BEFORE].value, lf->fields[FIM_INODE].value);
        fim_generate_comment(change_md5, sizeof(change_md5), "Old md5sum was: '%s'\nNew md5sum is : '%s'\n", lf->fields[FIM_MD5_BEFORE].value, lf->fields[FIM_MD5].value);
        fim_generate_comment(change_sha1, sizeof(change_sha1), "Old sha1sum was: '%s'\nNew sha1sum is : '%s'\n", lf->fields[FIM_SHA1_BEFORE].value, lf->fields[FIM_SHA1].value);
        fim_generate_comment(change_sha256, sizeof(change_sha256), "Old sha256sum was: '%s'\nNew sha256sum is : '%s'\n", lf->fields[FIM_SHA256_BEFORE].value, lf->fields[FIM_SHA256].value);
        fim_generate_comment(change_win_attributes, sizeof(change_win_attributes), "Old attributes were: '%s'\nNow they are '%s'\n", lf->fields[FIM_ATTRS_BEFORE].value, lf->fields[FIM_ATTRS].value);
    }

    // Provide information about the file
    char changed_attributes[OS_SIZE_256];
    snprintf(changed_attributes, OS_SIZE_256, "Changed attributes: %s\n", lf->fields[FIM_CHFIELDS].value);

    char hard_links[OS_SIZE_256];
    cJSON *tmp = cJSON_Parse(lf->fields[FIM_HARD_LINKS].value);
    if (lf->fields[FIM_HARD_LINKS].value) {
        cJSON *item;
        char * hard_links_tmp = NULL;
        cJSON_ArrayForEach(item, tmp) {
            wm_strcat(&hard_links_tmp, item->valuestring, ',');
        }

        snprintf(hard_links, OS_SIZE_256, "Hard links: %s\n", hard_links_tmp);
        os_free(hard_links_tmp);
    }

    if (strcmp("file", lf->fields[FIM_ENTRY_TYPE].value) == 0 ||
        strcmp("registry", lf->fields[FIM_ENTRY_TYPE].value) == 0) {
        entry_type = ENTRY_TYPE_FILE;
        path_len = strlen(lf->fields[FIM_FILE].value);

        if (path_len > 756) {
            char *aux = lf->fields[FIM_FILE].value + path_len - 30;
            snprintf(path_buffer, 757, "%.719s [...] %s", lf->fields[FIM_FILE].value, aux);
        } else {
            path = lf->fields[FIM_FILE].value;
        }
    } else if (strcmp("registry_key", lf->fields[FIM_ENTRY_TYPE].value) == 0) {
        entry_type = ENTRY_TYPE_REGISTRY_KEY;

        path_len = 6 + strlen(lf->fields[FIM_FILE].value);
        if (path_len > 756) {
            char *aux = lf->fields[FIM_FILE].value + path_len - 30;
            snprintf(path_buffer, 757, "%s %.713s [...] %s", lf->fields[FIM_REGISTRY_ARCH].value,
                     lf->fields[FIM_FILE].value, aux);
        } else {
            snprintf(path_buffer, 757, "%s %s", lf->fields[FIM_REGISTRY_ARCH].value, lf->fields[FIM_FILE].value);
        }
    } else if (strcmp("registry_value", lf->fields[FIM_ENTRY_TYPE].value) == 0) {
        int value_len = strlen(lf->fields[FIM_REGISTRY_VALUE_NAME].value);
        entry_type = ENTRY_TYPE_REGISTRY_VALUE;

        path_len = 6 + strlen(lf->fields[FIM_FILE].value) + value_len;
        if (path_len > 756) {
            snprintf(path_buffer, 757, "%s %.*s [...] \\%s", lf->fields[FIM_REGISTRY_ARCH].value,
                     751 - value_len < 0 ? 0 : 751 - value_len, lf->fields[FIM_FILE].value,
                     lf->fields[FIM_REGISTRY_VALUE_NAME].value);
        } else {
            snprintf(path_buffer, 757, "%s %s\\%s", lf->fields[FIM_REGISTRY_ARCH].value, lf->fields[FIM_FILE].value,
                     lf->fields[FIM_REGISTRY_VALUE_NAME].value);
        }
    }

    snprintf(lf->full_log, OS_MAXSTR,
            "%s '%s' %s\n"
            "%s"
            "Mode: %s\n"
            "%s"
            "%s%s%s%s%s%s%s%s%s%s%s%s",
            entry_type, path, lf->fields[FIM_EVENT_TYPE].value,
            lf->fields[FIM_HARD_LINKS].value ? hard_links : "",
            lf->fields[FIM_MODE].value,
            lf->fields[FIM_CHFIELDS].value ? changed_attributes : "",
            change_size,
            change_perm,
            change_owner,
            change_user,
            change_gowner,
            change_group,
            change_mtime,
            change_inode,
            change_md5,
            change_sha1,
            change_sha256,
            change_win_attributes
            //lf->fields[FIM_SYM_PATH].value
    );

    cJSON_Delete(tmp);

    return 0;
}

// Build change comment

size_t fim_generate_comment(char * str, long size, const char * format, const char * a1, const char * a2) {
    a1 = a1 != NULL ? a1 : "";
    a2 = a2 != NULL ? a2 : "";

    size_t str_size = 0;
    if (strcmp(a1, a2) != 0) {
        str_size = snprintf(str, size, format, a1, a2);
    }

    return str_size;
}

// Process scan info event

void fim_process_scan_info(_sdb * sdb, const char * agent_id, fim_scan_event event, cJSON * data) {
    cJSON * timestamp = cJSON_GetObjectItem(data, "timestamp");

    if (!cJSON_IsNumber(timestamp)) {
        mdebug1("No such member \"timestamp\" in FIM scan info event.");
        return;
    }

    char query[OS_SIZE_6144];

    if (snprintf(query, sizeof(query), "agent %s syscheck scan_info_update %s %ld", agent_id, event == FIM_SCAN_START ? "start_scan" : "end_scan", (long)timestamp->valuedouble) >= OS_SIZE_6144) {
        merror("FIM decoder: Cannot build save query: input is too long.");
        return;
    }

    fim_send_db_query(&sdb->socket, query);
}

int fim_fetch_attributes(cJSON *new_attrs, cJSON *old_attrs, Eventinfo *lf) {
    if (fim_fetch_attributes_state(new_attrs, lf, 1) ||
        fim_fetch_attributes_state(old_attrs, lf, 0)) {
        return -1;
    }

    return 0;
}

int fim_fetch_attributes_state(cJSON *attr, Eventinfo *lf, char new_state) {
    cJSON *attr_it;
    long aux_time;
    char *time_string = NULL;
    char buf_ptr[26];

    assert(lf != NULL);
    assert(lf->fields != NULL);

    cJSON_ArrayForEach(attr_it, attr) {
        if (!attr_it->string) {
            mdebug1("FIM attribute set contains an item with no key.");
            return -1;
        }

        if (attr_it->type == cJSON_Number) {
            assert(lf->fields != NULL);
            if (strcmp(attr_it->string, "size") == 0) {
                if (new_state) {
                    lf->fields[FIM_SIZE].value = w_long_str((long) attr_it->valuedouble);
                } else {
                    lf->fields[FIM_SIZE_BEFORE].value = w_long_str((long) attr_it->valuedouble);
                }
            } else if (strcmp(attr_it->string, "inode") == 0) {
                if (new_state) {
                    lf->fields[FIM_INODE].value = w_long_str((long) attr_it->valuedouble);
                } else {
                    lf->fields[FIM_INODE_BEFORE].value = w_long_str((long) attr_it->valuedouble);;
                }
            } else if (strcmp(attr_it->string, "mtime") == 0) {
                aux_time = (long) attr_it->valuedouble;
                time_string = ctime_r(&aux_time, buf_ptr);
                time_string[strlen(time_string) - 1] = '\0';
                if (new_state) {
                    lf->fields[FIM_MTIME].value = w_long_str((long) attr_it->valuedouble);
                } else {
                    lf->fields[FIM_MTIME_BEFORE].value = w_long_str((long) attr_it->valuedouble);
                }
            }
        } else if (attr_it->type == cJSON_String) {
            char **dst_data = NULL;

            if (strcmp(attr_it->string, "perm") == 0) {
                dst_data = new_state ? &lf->fields[FIM_PERM].value : &lf->fields[FIM_PERM_BEFORE].value;
            } else if (strcmp(attr_it->string, "user_name") == 0) {
                dst_data = new_state ? &lf->fields[FIM_UNAME].value : &lf->fields[FIM_UNAME_BEFORE].value;
            } else if (strcmp(attr_it->string, "group_name") == 0) {
                dst_data = new_state ? &lf->fields[FIM_GNAME].value : &lf->fields[FIM_GNAME_BEFORE].value;
            } else if (strcmp(attr_it->string, "uid") == 0) {
                dst_data = new_state ? &lf->fields[FIM_UID].value : &lf->fields[FIM_UID_BEFORE].value;
            } else if (strcmp(attr_it->string, "gid") == 0) {
                dst_data = new_state ? &lf->fields[FIM_GID].value : &lf->fields[FIM_GID_BEFORE].value;
            } else if (strcmp(attr_it->string, "hash_md5") == 0) {
                dst_data = new_state ? &lf->fields[FIM_MD5].value : &lf->fields[FIM_MD5_BEFORE].value;
            } else if (strcmp(attr_it->string, "hash_sha1") == 0) {
                dst_data = new_state ? &lf->fields[FIM_SHA1].value : &lf->fields[FIM_SHA1_BEFORE].value;
            } else if (strcmp(attr_it->string, "hash_sha256") == 0) {
                dst_data = new_state ? &lf->fields[FIM_SHA256].value : &lf->fields[FIM_SHA256_BEFORE].value;
            } else if (strcmp(attr_it->string, "attributes") == 0) {
                dst_data = new_state ? &lf->fields[FIM_ATTRS].value : &lf->fields[FIM_ATTRS_BEFORE].value; //LCOV_EXCL_LINE
            } else if (new_state && strcmp(attr_it->string, "symlink_path") == 0) {
                dst_data = &lf->fields[FIM_SYM_PATH].value;
            } else if (strcmp(attr_it->string, "value_type") == 0) {
                dst_data = &lf->fields[FIM_REGISTRY_VALUE_TYPE].value;
            }

            if (dst_data) {
                os_strdup(attr_it->valuestring, *dst_data);
            }
        } else if (attr_it->type == cJSON_Object) {
            if (strcmp(attr_it->string, "perm") == 0) {
                if (new_state) {
                    lf->fields[FIM_PERM].value = perm_json_to_old_format(attr_it);
                } else {
                    lf->fields[FIM_PERM_BEFORE].value = perm_json_to_old_format(attr_it);
                }
            }
        } else {
            mdebug1("Unknown FIM data type.");
        }
    }

    return 0;
}

char *decode_ace_json(const cJSON *const perm_array, const char *const account_name, const char *const ace_type) {
    cJSON *it;
    char *output = NULL;
    char *perms = NULL;
    int length;

    if (perm_array == NULL) {
        return NULL;
    }

    length = snprintf(NULL, 0, "%s (%s): ", account_name, ace_type);

    if (length <= 0) {
        return NULL; // LCOV_EXCL_LINE
    }

    os_malloc(length + 1, output);

    snprintf(output, length + 1, "%s (%s): ", account_name, ace_type);

    cJSON_ArrayForEach(it, perm_array) {
        wm_strcat(&perms, cJSON_GetStringValue(it), '|');
    }

    if (perms) {
        str_uppercase(perms);
        wm_strcat(&output, perms, '\0');
        free(perms);
    }

    wm_strcat(&output, ", ", '\0');

    return output;
}

char *perm_json_to_old_format(cJSON *perm_json) {
    char *account_name;
    char *output = NULL;
    int length;
    cJSON *json_it;

    assert(perm_json != NULL);

    cJSON_ArrayForEach(json_it, perm_json) {
        char *ace;
        account_name = cJSON_GetStringValue(cJSON_GetObjectItem(json_it, "name"));
        if (account_name == NULL) {
            account_name = json_it->string;
        }

        ace = decode_ace_json(cJSON_GetObjectItem(json_it, "allowed"), account_name, "allowed");
        if (ace) {
            wm_strcat(&output, ace, '\0');
            free(ace);
        }

        ace = decode_ace_json(cJSON_GetObjectItem(json_it, "denied"), account_name, "denied");
        if (ace) {
            wm_strcat(&output, ace, '\0');
            free(ace);
        }
    }

    if (output == NULL) {
        return NULL;
    }

    length = strlen(output);

    if (length > 2 && output[strlen(output) - 2] == ',') {
        output[length - 2] = '\0';
    }

    return output;
}

void fim_adjust_checksum(sk_sum_t *newsum, char **checksum) {
    // Adjust attributes
    if (newsum->attributes) {
        os_realloc(*checksum,
                strlen(*checksum) + strlen(newsum->attributes) + 2,
                *checksum);
        char *found = strrchr(*checksum, ':');
        if (found) {
            snprintf(found + 1, strlen(newsum->attributes) + 1, "%s", newsum->attributes);
        }
    }

    // Adjust permissions
    if (newsum->win_perm && *newsum->win_perm) {
        char *first_part = strchr(*checksum, ':');
        if (!first_part) return;
        first_part++;
        *(first_part++) = '\0';
        char *second_part = strchr(first_part, ':');
        if (!second_part) return;
        os_strdup(second_part, second_part);

        // We need to escape the character ':' from the permissions
        //because we are going to compare against escaped permissions
        // sent by wazuh-db
        char *esc_perms = wstr_replace(newsum->win_perm, ":", "\\:");
        wm_strcat(checksum, esc_perms, 0);
        free(esc_perms);

        wm_strcat(checksum, second_part, 0);
        free(second_part);
    }
}
