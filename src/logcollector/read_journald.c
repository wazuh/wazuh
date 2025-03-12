/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifdef __linux__

#include "shared.h"
#include "logcollector.h"
#include "journal_log.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#define INLINE
// Ajust the buffer size for testing
#undef OS_MAXSTR
#define OS_MAXSTR 16
#undef OS_LOG_HEADER
#define OS_LOG_HEADER 0
#else
#define STATIC static
#define INLINE inline
#endif

/* Constants */
#define OFE_TIMESTAMP "timestamp"

/**
 * @brief Configuration and status of the journal log
 * @note not thread safe, only accessible from Inputs threads
 */
typedef struct {
    unsigned long owner_id;            ///< Owner ID of the journal log
    bool is_disabled;                  ///< Flag to disable the journal log, error on initialization
    w_journal_context_t* journal_ctx;  ///< Journal log context
} w_journald_global_t;                 ///< Current configuration and status of the journal log

STATIC w_journald_global_t gs_journald_global = {
    .owner_id = 0,
    .is_disabled = false,
    .journal_ctx = NULL,
}; ///< Current configuration and status of the journal log

/**
 * @brief Only future events configuration and status
 * @note Only accessible from Input Owner Thread and Deamon Thread (main thread)
 */
typedef struct {
    bool exist_journal;           ///< Flag to indicate if the journal log exists
    bool only_future_events;      ///< Flag to indicate if only future events are read
    uint64_t last_read_timestamp; ///< Last read timestamp from the journal log
    pthread_mutex_t mutex;        ///< Mutex to protect the timestamp, only resource shared with the Input Owner Thread
} w_journald_ofe_t;

STATIC w_journald_ofe_t gs_journald_ofe = {
    .exist_journal = false,
    .only_future_events = true,
    .last_read_timestamp = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
}; ///< Only future events configuration and status

#ifdef WAZUH_UNIT_TESTING
void set_gs_journald_ofe(bool exist, bool ofe, uint64_t timestamp) {
    gs_journald_ofe.exist_journal = exist;
    gs_journald_ofe.only_future_events = ofe;
    gs_journald_ofe.last_read_timestamp = timestamp;
}

void set_gs_journald_global(unsigned long owner_id, bool is_disabled, void* journal_ctx)
{
    gs_journald_global.owner_id = owner_id;
    gs_journald_global.is_disabled = is_disabled;
    gs_journald_global.journal_ctx = journal_ctx;
}

bool journald_isDisabled() {
    return gs_journald_global.is_disabled;
}
#endif


bool w_journald_can_read(unsigned long owner_id) {

    if (gs_journald_global.is_disabled) {
        return false;
    }

    if (gs_journald_global.owner_id == 0) {

        gs_journald_global.owner_id = owner_id;

        if (gs_journald_global.journal_ctx == NULL && w_journal_context_create(&gs_journald_global.journal_ctx) != 0) {
            merror(LOGCOLLECTOR_JOURNAL_LOG_DISABLING);
            gs_journald_global.is_disabled = true;
            return false;
        }

        if (seek_and_refresh_timestamp() < 0)
        {
            return false;
        }

        minfo(LOGCOLLECTOR_JOURNALD_MONITORING);

    } else if (gs_journald_global.owner_id != owner_id) {
        return false;
    }

    if (w_journal_rotation_detected(gs_journald_global.journal_ctx)) {

        if (seek_and_refresh_timestamp() < 0)
        {
            return false;
        }

        minfo(LOGCOLLECTOR_TIMESTAMP_REFRESHED);
    }

    return true;
}

void * read_journald(logreader * lf, int * rc, __attribute__((unused)) int drop_it) {
    const unsigned long MAX_LINE_LEN = OS_MAXSTR - OS_LOG_HEADER;
    char read_buffer[OS_MAXSTR + 1];
    read_buffer[OS_MAXSTR] = '\0';
    int count_logs = 0;
    *rc = 0;
    w_journal_filters_list_t filters = lf->journal_log->disable_filters ? NULL : lf->journal_log->filters;

    while ((maximum_lines == 0 || count_logs < maximum_lines) && can_read()) {
        // Get the next entry
        int result_get_next = w_journal_context_next_newest_filtered(gs_journald_global.journal_ctx, filters);
        if (result_get_next < 0) {
            merror(LOGCOLLECTOR_JOURNAL_LOG_FAIL_NEXT, strerror(-result_get_next));
            gs_journald_global.is_disabled = true;
            break;
        } else if (result_get_next == 0) {
            mdebug2(LOGCOLLECTOR_JOURNAL_LOG_NO_NEW);
            break;
        }

        // Get the message
        w_journal_entry_t * entry =
            w_journal_entry_dump(gs_journald_global.journal_ctx, W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG);
        char * entry_str = w_journal_entry_to_string(entry);
        w_journal_entry_free(entry);

        if (entry_str == NULL) {
            mdebug1(LOGCOLLECTOR_JOURNAL_LOG_FAIL_GET);
            break;
        }

        // Copy the message to the buffer
        unsigned long entry_str_len = strlen(entry_str);
        if (entry_str_len > MAX_LINE_LEN) {
            mdebug1(LOGCOLLECTOR_JOURNAL_LOG_TRUNCATED);
            entry_str_len = MAX_LINE_LEN;
        }
        strncpy(read_buffer, entry_str, entry_str_len);
        read_buffer[entry_str_len] = '\0';
        os_free(entry_str);

        if (isDebug()) {
            mdebug2(LOGCOLLECTOR_JOURNAL_LOG_READING, read_buffer);
        }

        // Send the message to the manager
        w_msg_hash_queues_push(read_buffer, JOURNALD_LOG, entry_str_len + 1, lf->log_target, LOCALFILE_MQ);
        count_logs++;
    }

    // Update timestamp
    w_mutex_lock(&gs_journald_ofe.mutex);
    gs_journald_ofe.last_read_timestamp = gs_journald_global.journal_ctx->timestamp;
    w_mutex_unlock(&gs_journald_ofe.mutex);

    return NULL;
}

/** ONLY FUTURE EVENTS configuration */

void w_journald_set_ofe(bool ofe) {
    gs_journald_ofe.only_future_events = ofe;
    gs_journald_ofe.exist_journal = true;
}

cJSON * w_journald_get_status_as_JSON() {

    // Maybe journal log is not initialized yet
    if (!gs_journald_ofe.exist_journal) {
        return NULL;
    }

    w_mutex_lock(&gs_journald_ofe.mutex);
    uint64_t timestamp = gs_journald_ofe.last_read_timestamp;
    w_mutex_unlock(&gs_journald_ofe.mutex);

    // Convert the timestamp uint64_t to a string
    char timestamp_str[OS_SIZE_256] = {0};
    snprintf(timestamp_str, OS_SIZE_256 - 1, "%" PRIu64, timestamp);
    cJSON * journald_log = cJSON_CreateObject();
    cJSON_AddStringToObject(journald_log, OFE_TIMESTAMP, timestamp_str);

    return journald_log;
}

void w_journald_set_status_from_JSON(cJSON * global_json) {

    if (global_json == NULL) {
        return;
    }

    cJSON * jurnald_log = cJSON_GetObjectItem(global_json, JOURNALD_LOG);
    char * timestamp = cJSON_GetStringValue(cJSON_GetObjectItem(jurnald_log, OFE_TIMESTAMP));

    if (timestamp == NULL) {
        return;
    }

    // Convert the timestamp to a uint64_t
    uint64_t timestamp_uint = strtoull(timestamp, NULL, 10);
    if (timestamp_uint == 0 || timestamp_uint == ULLONG_MAX) {
        return;
    }

    // Set the timestamp
    w_mutex_lock(&gs_journald_ofe.mutex);
    gs_journald_ofe.last_read_timestamp = timestamp_uint;
    w_mutex_unlock(&gs_journald_ofe.mutex);

    mdebug2(LOGCOLLECTOR_JOURNAL_LOG_SET_LAST, timestamp_uint);
}

int seek_and_refresh_timestamp()
{
    // Set the pointer to the journal log
    w_mutex_lock(&gs_journald_ofe.mutex);
    uint64_t lr_ts = gs_journald_ofe.last_read_timestamp;
    w_mutex_unlock(&gs_journald_ofe.mutex);

    int ret = gs_journald_ofe.only_future_events
                  ? w_journal_context_seek_most_recent(gs_journald_global.journal_ctx)
                  : w_journal_context_seek_timestamp(gs_journald_global.journal_ctx, lr_ts);

    if (ret < 0)
    {
        merror(LOGCOLLECTOR_JOURNAL_LOG_FAIL_SEEK, strerror(-ret));
        gs_journald_global.is_disabled = true;
    }

    return ret;
}

#endif
