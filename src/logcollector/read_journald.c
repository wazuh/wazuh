/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifdef __linux__

#include <stdatomic.h>

#include "shared.h"
#include "logcollector.h"
#include "journal_log.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#define INLINE
#else
#define STATIC static
#define INLINE inline
#endif

STATIC unsigned long gs_owner_id = 0;               ///< Owner ID of the journal log
STATIC bool gs_is_disabled = false;                 ///< Flag to disable the journal log, error on initialization
STATIC w_journal_context_t * gs_journal_ctx = NULL; ///< Journal log context
STATIC atomic_int gs_close_journal = 0;             ///< Flag to close the journal log

void w_journald_release_ctx() { atomic_store(&gs_close_journal, 1); }

bool w_journald_can_read(unsigned long owner_id) {

    if (gs_is_disabled) {
        return false;
    }

    if (gs_owner_id == 0) {
        gs_owner_id = owner_id;
        if (gs_journal_ctx == NULL && w_journal_context_create(&gs_journal_ctx) != 0) {
            gs_is_disabled = true;
            return false;
        }

        // move to the end of the journal
        int ret = w_journal_context_seek_most_recent(gs_journal_ctx);
        if (ret < 0) {
            mwarn("Failed to move to the end of the journal, disabling journal log: %s", strerror(-ret));
            gs_is_disabled = true;
            return false;
        }

    } else if (gs_owner_id != owner_id) {
        return false;
    }

    if (atomic_load(&gs_close_journal) == 1) {
        w_journal_context_free(gs_journal_ctx);
        gs_is_disabled = true;
        return false;
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
        int result_get_next = w_journal_context_next_newest_filtered(gs_journal_ctx, filters);
        if (result_get_next < 0) {
            merror("Failed to get next entry, disabling journal log: %s", strerror(-result_get_next));
            gs_is_disabled = true;
            break;
        } else if (result_get_next == 0) {
            mdebug2("No new entries in the journal");
            break;
        }

        // Get the message
        w_journal_entry_t * entry = w_journal_entry_dump(gs_journal_ctx, W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG);
        char * entry_str = w_journal_entry_to_string(entry);
        w_journal_entry_free(entry);

        if (entry_str == NULL) {
            merror("Failed to get the message from the journal");
            break;
        }

        // Copy the message to the buffer
        unsigned long entry_str_len = strlen(entry_str);
        if (entry_str_len > MAX_LINE_LEN) {
            mdebug1("Message size > maximum allowed, The message will be truncated");
            entry_str_len = MAX_LINE_LEN;
        }
        strncpy(read_buffer, entry_str, entry_str_len);
        read_buffer[entry_str_len] = '\0';
        os_free(entry_str);

        if (isDebug()) {
            mdebug2("Reading from journal: %s", read_buffer);
        }

        // Send the message to the manager
        w_msg_hash_queues_push(read_buffer, JOURNALD_LOG, entry_str_len + 1, lf->log_target, LOCALFILE_MQ);
        count_logs++;
    }

    return NULL;
}

#endif
