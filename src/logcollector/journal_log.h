#ifndef w_journal_H
#define w_journal_H

#include <shared.h>
#include "../config/localfile-config.h"

#include "cJSON.h"
#include "expression.h"

/*******************************************************************************
 * NOTE: This module is not thread-safe.
 *
 * This library is used to interact with the journal log through the sd_journal
 * library.
 * All functions listed here are thread-agnostic and only a single specific
 * thread may operate on a given object during its entire lifetime.
 * It's safe to allocate multiple independent objects and use each from a
 * specific thread in parallel.
 * However, it's not safe to allocate such an object in one thread, and operate
 * or free it from any other, even if locking is used to ensure these threads
 * don't operate on it at the very same time.
 * The library tries to dinamically load the sd_journal library, so it's not
 * necessary to link it at compile time.
 * All functions are added in version 187 unless otherwise noted.
 *******************************************************************************/

/**********************************************************
 *               Journald library related
 ***********************************************************/
typedef struct sd_journal sd_journal;           ///< sd_journal type
typedef struct w_journal_lib_t w_journal_lib_t; ///< Journal library functions

/**********************************************************
 *                    Context related
 ***********************************************************/

/**
 * @brief Journal log context
 */
typedef struct {
    w_journal_lib_t * lib; ///< Journal functions
    sd_journal * journal;  ///< Journal context
    uint64_t timestamp;    ///< Last timestamp processed (__REALTIME_TIMESTAMP)
} w_journal_context_t;

/**
 * @brief Get a new journal log context
 *
 * The caller is responsible for freeing the returned context.
 * @param ctx Journal log context
 * @return int 0 on success or -1 on error
 * @note The context should be created and used by a single thread only.
 */
int w_journal_context_create(w_journal_context_t ** ctx);

/**
 * @brief Free the journal log context and all its resources
 *
 * The context pointer is invalid after the call.
 * @param ctx Journal log context
 */
void w_journal_context_free(w_journal_context_t * ctx);

/**
 * @brief Try update the timestamp in the journal log context with the timestamp of the current entry
 *
 * If failed to get the timestamp, the timestamp updated with the current time.
 * @param ctx Journal log context
 */
void w_journal_context_update_timestamp(w_journal_context_t * ctx);

/**
 * @brief Move the cursor to the most recent entry
 *
 * @param ctx Journal log context
 * @return int 0 on success or a negative errno-style error code.
 * @note This function is not thread-safe.
 *
 */
int w_journal_context_seek_most_recent(w_journal_context_t * ctx);

/**
 * @brief Move the cursor to the entry with the specified timestamp or the next newer entry available.
 *
 * If the timestamp is in the future or 0, the cursor is moved most recent entry.
 * If the timestamp is older than the oldest available entry, the cursor is moved to the oldest entry.
 * @param ctx Journal log context
 * @param timestamp The timestamp to seek
 * @return int 0 on success or a negative errno-style error code.
 */
int w_journal_context_seek_timestamp(w_journal_context_t * ctx, uint64_t timestamp);

/**
 * @brief Move the cursor to the next newest entry
 *
 * @param ctx Journal log context
 * @return int 0 no more entries or a negative errno-style error code.
 * @note This function is not thread-safe.
 */
int w_journal_context_next_newest(w_journal_context_t * ctx);

/**
 * @brief Move the cursor to the next newest entry that matches the filters
 *
 * If filters is NULL, the function will return the next newest entry.
 * If filters is not NULL, the function will return the next newest entry that matches the filters.
 * If no entry matches the filters, the function will return 0, but the cursor will be moved to the next newest entry.
 * @param ctx Journal log context
 * @param filters The filters to match
 * @return int 0 no more entries or a negative errno-style error code.
 */
int w_journal_context_next_newest_filtered(w_journal_context_t * ctx, w_journal_filters_list_t filters);

/**
 * @brief Get the oldest accessible timestamp in the journal (__REALTIME_TIMESTAMP)
 *
 * @param ctx Journal log context
 * @param timestamp The oldest timestamp
 * @return int 0 on success or a negative errno-style error code.
 * @note This function is not thread-safe.
 */
int w_journal_context_get_oldest_timestamp(w_journal_context_t * ctx, uint64_t * timestamp);

/**
 * @brief Closes and reopens the context
 *
 * The caller is responsible for freeing the returned context.
 * @param ctx Journal log context
 * @return int 0 on success or -1 on error
 * @note The context should be created and used by a single thread only.
 */
int w_journal_context_recreate(w_journal_context_t** ctx);
/**********************************************************
 *                   Entry related
 **********************************************************/
/**
 * @brief Determine the types of dump of a journal log entry
 */
typedef enum {
    W_JOURNAL_ENTRY_DUMP_TYPE_INVALID = -1, ///< Invalid dump type
    W_JOURNAL_ENTRY_DUMP_TYPE_JSON,         ///< JSON dump
    W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG,       ///< Syslog dump
} w_journal_entry_dump_type_t;

/**
 * @brief Represents a dump of a journal log entry
 */
typedef struct {
    w_journal_entry_dump_type_t type; ///< Dump type
    union {
        cJSON * json;   ///< JSON dump
        char * syslog;  ///< Syslog dump
    } data;             ///< Dump data
    uint64_t timestamp; ///< Indexing timestamp (__REALTIME_TIMESTAMP)
} w_journal_entry_t;

/**
 * @brief Create the entry from the current entry in the journal log context
 *
 * The caller is responsible for freeing the returned entry.
 * @param ctx Journal log context
 * @param type The type of dump
 * @return w_journal_entry_t* The current entry or NULL on error
 * @note This function is not thread-safe.
 */
w_journal_entry_t * w_journal_entry_dump(w_journal_context_t * ctx, w_journal_entry_dump_type_t type);

/**
 * @brief Free the entry and all its resources,
 *
 * The entry pointer is invalid after the call.
 * @param entry Journal log entry
 */
void w_journal_entry_free(w_journal_entry_t * entry);

/**
 * @brief Dump the current entry to a string representation
 *
 * The caller is responsible for freeing the returned string.
 * @param entry Journal log entry
 * @return char*  The string representation of the entry or NULL on error
 */
char * w_journal_entry_to_string(w_journal_entry_t * entry);

/**********************************************************
 *                   Filter related
 **********************************************************/

/**
 * @brief Apply the filter to the journal log context
 *
 * The filter will be applied to the journal log context.
 * @param ctx Journal log context
 * @param filter Journal log filter
 * @return int positive number of entries matched, 0 if no entries matched, or a negative errno-style error code.
 */
int w_journal_filter_apply(w_journal_context_t * ctx, w_journal_filter_t * filter);

/**
 * @brief Detects changes on the journald files
 *
 * The context pointer is invalid after the call.
 * @param ctx Journal log context
*/
bool w_journal_rotation_detected(w_journal_context_t *ctx);

#endif // w_journal_H
