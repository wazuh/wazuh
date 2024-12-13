#if defined(__linux__)

#include "journal_log.h"

#include <dlfcn.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "debug_op.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#define INLINE
#else
#define STATIC static
#define INLINE inline
#endif

STATIC const int W_SD_JOURNAL_LOCAL_ONLY = 1 << 0;     ///< Open the journal log for the local machine
STATIC const char * W_LIB_SYSTEMD = "libsystemd.so.0"; ///< Name of the systemd library

// Function added on version 187 of systemd
typedef int (*w_journal_open)(sd_journal ** ret, int flags);            ///< sd_journal_open
typedef void (*w_journal_close)(sd_journal * j);                        ///< sd_journal_close
typedef int (*w_journal_previous)(sd_journal * j);                      ///< sd_journal_previous
typedef int (*w_journal_next)(sd_journal * j);                          ///< sd_journal_next
typedef int (*w_journal_seek_tail)(sd_journal * j);                     ///< sd_journal_seek_tail
typedef int (*w_journal_seek_timestamp)(sd_journal * j, uint64_t usec); ///< sd_journal_seek_realtime_usec
typedef int (*w_journal_get_cutoff_timestamp)(sd_journal * j,
                                              uint64_t * from,
                                              uint64_t * to);           ///< sd_journal_get_cutoff_realtime_usec
typedef int (*w_journal_get_timestamp)(sd_journal * j, uint64_t * ret); ///< sd_journal_get_realtime_usec
typedef int (*w_journal_get_data)(sd_journal * j,
                                  const char * field,
                                  const void ** data,
                                  size_t * l);                                           ///< sd_journal_get_data
typedef void (*w_journal_restart_data)(sd_journal * j);                                  ///< sd_journal_restart_data
typedef int (*w_journal_enumerate_date)(sd_journal * j, const void ** data, size_t * l); ///< sd_journal_enumerate_data

/**
 * @brief Journal log library
 *
 * This structure is used to store the functions of the journal log library.
 * The functions are used to interact with the journal log.
 */
struct w_journal_lib_t {
    // Open and close functions
    w_journal_open open;   ///< Open the journal log
    w_journal_close close; ///< Close the journal log
    // Cursor functions
    w_journal_previous previous;             ///< Move the cursor to the previous entry
    w_journal_next next;                     ///< Move the cursor to the next entry
    w_journal_seek_tail seek_tail;           ///< Move the cursor to the end of the journal log
    w_journal_seek_timestamp seek_timestamp; ///< Move the cursor to the entry with the specified timestamp
    // Timestamp functions
    w_journal_get_cutoff_timestamp get_cutoff_timestamp; ///< Get the oldest timestamps in the journal
    w_journal_get_timestamp get_timestamp;               ///< Get the current time of the journal log
    // Data functions
    w_journal_get_data get_data;             ///< Get the data of the specified field in the current entry
    w_journal_restart_data restart_data;     ///< Restart the enumeration of the available data
    w_journal_enumerate_date enumerate_date; ///< Enumerate the available data in the current entry
    void * handle;                           ///< Handle of the library
};

/**********************************************************
 *                    Auxiliar functions
 ***********************************************************/

/**
 * @brief Return the epoch time in microseconds
 *
 * @return int64_t
 */
STATIC INLINE uint64_t w_get_epoch_time() {
    struct timeval tv = {0};
    gettimeofday(&tv, NULL);
    return (uint64_t) tv.tv_sec * 1000000 + tv.tv_usec;
}

/**
 * @brief Convert the epoch time to a human-readable string (ISO 8601)
 * 2022-12-19T15:02:53.288+00:00 hostnameTest processName[123]: Message Test >> Wazuh no extra el hostname
 * The caller is responsible for freeing the returned string.
 * @param timestamp The epoch time
 * @return char* The human-readable string or NULL on error
 */
STATIC INLINE char * w_timestamp_to_string(uint64_t timestamp) {
    struct tm tm;
    time_t time = timestamp / 1000000;
    if (gmtime_r(&time, &tm) == NULL) {
        return NULL;
    }

    char * str;
    os_calloc(sizeof("Mar 01 12:39:34") + 1, sizeof(char), str);
    strftime(str, sizeof("Mar 01 12:39:34"), "%b %d %T", &tm);
    return str;
}

/**
 * @brief Convert the epoch time to a journal --since time format %Y-%m-%d %H:%M:%S
 * i.e. 2024-03-14 14:08:52
 * The caller is responsible for freeing the returned string.
 * @param timestamp The epoch time
 * @return char* The human-readable string or NULL on error
 */
STATIC INLINE char * w_timestamp_to_journalctl_since(uint64_t timestamp) {
    struct tm tm;
    time_t time = timestamp / 1000000;
    if (gmtime_r(&time, &tm) == NULL) {
        return NULL;
    }

    char * str;
    os_calloc(sizeof("2024-03-14 14:08:52") + 1, sizeof(char), str);
    strftime(str, sizeof("2024-03-14 14:08:52"), "%Y-%m-%d %T", &tm);
    return str;
}

/**********************************************************
 *                    Load library related
 ***********************************************************/
/**
 * @brief Finds the path of a library in the process memory maps.
 *
 * This function searches for the specified library name in the process memory maps
 * and returns the path of the library if found.
 *
 * @param library_name The name of the library to search for.
 * @return The path of the library if found, or NULL if not found or an error occurred.
 */
STATIC INLINE char * find_library_path(const char * library_name) {
    FILE * maps_file = fopen("/proc/self/maps", "r");
    if (maps_file == NULL) {
        return NULL;
    }

    char * line = NULL;
    size_t len = 0;
    char * path = NULL;

    while (getline(&line, &len, maps_file) != -1) {
        if (strstr(line, library_name) != NULL) {
            char * path_start = strchr(line, '/');
            if (path_start == NULL) {
                break; // Never happens
            }
            char * path_end = strchr(path_start, '\n');
            if (path_end == NULL) {
                break; // Never happens
            }
            *path_end = '\0';
            path = strndup(path_start, path_end - path_start);
            break;
        }
    }

    os_free(line);
    fclose(maps_file);
    return path;
}

/**
 * @brief Checks if a file is owned by the root user.
 *
 * This function checks the ownership of a file by retrieving the file's
 * stat structure and comparing the user ID (UID) with the root user's UID (0).
 *
 * @param library_path The path to the file to be checked.
 * @return true if the file is owned by the root user, false otherwise.
 */
STATIC INLINE bool is_owned_by_root(const char * library_path) {
    struct stat file_stat;
    if (stat(library_path, &file_stat) != 0) {
        return false;
    }

    return file_stat.st_uid == 0;
}

/**
 * @brief Load and validate a function from a library.
 *
 * @param handle Library handle
 * @param name Function name
 * @param func Function pointer
 * @return true if the function was loaded and validated successfully, false otherwise.
 */
STATIC INLINE bool load_and_validate_function(void * handle, const char * name, void ** func) {
    *func = dlsym(handle, name);
    if (*func == NULL) {
        mwarn(LOGCOLLECTOR_JOURNAL_LOG_LIB_FAIL_LOAD, name, dlerror());
        return false;
    }
    return true;
}

/**
 * @brief Initialize the journal library functions
 *
 * The caller is responsible for freeing the returned library.
 * @return w_journal_lib_t* The library or NULL on error
 */
STATIC INLINE w_journal_lib_t * w_journal_lib_init() {
    w_journal_lib_t * lib = NULL;
    os_calloc(1, sizeof(w_journal_lib_t), lib);

    // Load the library
    lib->handle = dlopen(W_LIB_SYSTEMD, RTLD_LAZY);
    if (lib->handle == NULL) {
        char * err = dlerror();
        mwarn(LOGCOLLECTOR_JOURNAL_LOG_LIB_FAIL_LOAD, W_LIB_SYSTEMD, err == NULL ? "Unknown error" : err);
        os_free(lib);
        return NULL;
    }

    // Verify the ownership of the library
    char * library_path = find_library_path(W_LIB_SYSTEMD);
    if (library_path == NULL || !is_owned_by_root(library_path)) {
        mwarn(LOGCOLLECTOR_JOURNAL_LOG_LIB_FAIL_OWN, W_LIB_SYSTEMD);
        os_free(library_path);
        dlclose(lib->handle);
        os_free(lib);
        return NULL;
    }
    os_free(library_path);

    // Load and verify the functions
    bool ok =
        load_and_validate_function(lib->handle, "sd_journal_open", (void **) &lib->open)
        && load_and_validate_function(lib->handle, "sd_journal_close", (void **) &lib->close)
        && load_and_validate_function(lib->handle, "sd_journal_previous", (void **) &lib->previous)
        && load_and_validate_function(lib->handle, "sd_journal_next", (void **) &lib->next)
        && load_and_validate_function(lib->handle, "sd_journal_seek_tail", (void **) &lib->seek_tail)
        && load_and_validate_function(lib->handle, "sd_journal_seek_realtime_usec", (void **) &lib->seek_timestamp)
        && load_and_validate_function(lib->handle, "sd_journal_get_realtime_usec", (void **) &lib->get_timestamp)
        && load_and_validate_function(lib->handle, "sd_journal_get_data", (void **) &lib->get_data)
        && load_and_validate_function(lib->handle, "sd_journal_restart_data", (void **) &lib->restart_data)
        && load_and_validate_function(lib->handle, "sd_journal_enumerate_data", (void **) &lib->enumerate_date)
        && load_and_validate_function(
            lib->handle, "sd_journal_get_cutoff_realtime_usec", (void **) &lib->get_cutoff_timestamp);

    if (!ok) {
        dlclose(lib->handle);
        os_free(lib);
        return NULL;
    }

    return lib;
}

/**********************************************************
 *                    Context related
 ***********************************************************/

int w_journal_context_create(w_journal_context_t ** ctx) {
    int ret = -1; // Return error by default

    if (ctx == NULL) {
        return ret;
    }
    os_calloc(1, sizeof(w_journal_context_t), (*ctx));

    (*ctx)->lib = w_journal_lib_init();
    if ((*ctx)->lib == NULL) {
        os_free(*ctx);
        return ret;
    }

    ret = (*ctx)->lib->open(&((*ctx)->journal), W_SD_JOURNAL_LOCAL_ONLY);
    if (ret < 0) {
        mwarn(LOGCOLLECTOR_JOURNAL_LOG_FAIL_OPEN, strerror(-ret));
        dlclose((*ctx)->lib->handle);
        os_free((*ctx)->lib);
        os_free(*ctx);
    }
    return ret;
}

void w_journal_context_free(w_journal_context_t * ctx) {
    if (ctx == NULL) {
        return;
    }

    ctx->lib->close(ctx->journal);
    dlclose(ctx->lib->handle);
    os_free(ctx->lib);
    os_free(ctx);
}

void w_journal_context_update_timestamp(w_journal_context_t * ctx) {
    static bool failed_logged = false;
    if (ctx == NULL) {
        return;
    }

    int err = ctx->lib->get_timestamp(ctx->journal, &(ctx->timestamp));
    if (err < 0) {
        ctx->timestamp = w_get_epoch_time();
        if (!failed_logged) {
            failed_logged = true;
            mwarn(LOGCOLLECTOR_JOURNAL_LOG_FAIL_READ_TS, strerror(-err));
        }
    }
}

int w_journal_context_seek_most_recent(w_journal_context_t * ctx) {

    if (ctx == NULL) {
        return -1;
    }

    int err = ctx->lib->seek_tail(ctx->journal);
    if (err < 0) {
        return err;
    }

    err = ctx->lib->previous(ctx->journal);
    // if change cursor, update timestamp
    if (err > 0) {
        w_journal_context_update_timestamp(ctx);
    }
    return err;
}

int w_journal_context_seek_timestamp(w_journal_context_t * ctx, uint64_t timestamp) {

    if (ctx == NULL) {
        return -1;
    }

    // If the timestamp is in the future or invalid, seek the most recent entry
    if (timestamp == 0 || timestamp > w_get_epoch_time()) {
        mwarn(LOGCOLLECTOR_JOURNAL_LOG_FUTURE_TS, timestamp);
        return w_journal_context_seek_most_recent(ctx);
    }

    // Check if the timestamp is older than the oldest available
    uint64_t oldest;
    int err = w_journal_context_get_oldest_timestamp(ctx, &oldest);

    if (err < 0) {
        mwarn(LOGCOLLECTOR_JOURNAL_LOG_FAIL_READ_OLD_TS, strerror(-err));
    } else if (timestamp < oldest) {
        mwarn(LOGCOLLECTOR_JOURNAL_LOG_CHANGE_TS, timestamp);
        timestamp = oldest;
    }

    err = ctx->lib->seek_timestamp(ctx->journal, timestamp);
    if (err < 0) {
        return err;
    }

    err = ctx->lib->next(ctx->journal);
    if (err > 0) // if the cursor change, update timestamp
    {
        w_journal_context_update_timestamp(ctx);
    }
    return err;
}

int w_journal_context_next_newest(w_journal_context_t * ctx) {

    if (ctx == NULL) {
        return -1;
    }

    int ret = ctx->lib->next(ctx->journal);

    // if change cursor, update timestamp
    if (ret > 0) {
        w_journal_context_update_timestamp(ctx);
    }

    return ret;
}

int w_journal_context_next_newest_filtered(w_journal_context_t * ctx, w_journal_filters_list_t filters) {

    if (filters == NULL) {
        return w_journal_context_next_newest(ctx);
    }

    int ret = 0;
    while ((ret = w_journal_context_next_newest(ctx)) > 0) {
        if (isDebug()) {
            char * ts = w_timestamp_to_journalctl_since(ctx->timestamp);
            mdebug2(LOGCOLLECTOR_JOURNAL_LOG_CHECK_FILTER, ts == NULL ? "unknown" : ts);
            os_free(ts);
        }

        for (size_t i = 0; filters[i] != NULL; i++) {
            if (w_journal_filter_apply(ctx, filters[i]) > 0) {
                return 1;
            }
        }
    };

    return ret;
}

// Check return value on value un error
int w_journal_context_get_oldest_timestamp(w_journal_context_t * ctx, uint64_t * timestamp) {
    return ctx->lib->get_cutoff_timestamp(ctx->journal, timestamp, NULL);
}

/**********************************************************
 *                   Entry related
 **********************************************************/
/**
 * @brief Create a JSON object with the available data in the journal log context
 *
 * The caller is responsible for freeing the returned cJSON object.
 * @param ctx Journal log context
 * @return cJSON* JSON object with the available data or NULL on error
 */
STATIC INLINE cJSON * entry_as_json(w_journal_context_t * ctx) {
    cJSON * dump = cJSON_CreateObject();
    int isEmpty = 1; // Flag to check if the entry is empty

    // Iterate through the available data
    const void * data;
    size_t length;
    ctx->lib->restart_data(ctx->journal);
    while (ctx->lib->enumerate_date(ctx->journal, &data, &length) > 0) {
        // Value is a string "key=value" without null-terminator
        const char * equal_sign = memchr(data, '=', length);
        if (!equal_sign) {
            continue;
        }

        size_t key_len = equal_sign - (const char *) data;
        size_t value_len = length - key_len - 1;

        char * key = strndup(data, key_len);
        char * value = strndup(equal_sign + 1, value_len);

        // Add the key and value to the JSON object
        cJSON_AddStringToObject(dump, key, value);
        isEmpty = 0;

        os_free(key);
        os_free(value);
    }

    // Error or no data
    if (isEmpty) {
        cJSON_Delete(dump);
        return NULL;
    }
    return dump;
}

/**
 * @brief Get the field pointer from the current entry in the journal log context
 *
 * @param ctx Journal log context
 * @param field Field to get
 * @param value
 * @return int
 */
STATIC INLINE char * get_field_ptr(w_journal_context_t * ctx, const char * field) {
    const void * data;
    size_t length;

    int err = ctx->lib->get_data(ctx->journal, field, &data, &length);
    if (err < 0) {
        return NULL;
    }

    // Assume that the value is a string "key=value"
    const char * equal_sign = memchr(data, '=', length);
    if (!equal_sign) {
        return NULL; // Invalid value
    }

    // Copy the value
    size_t key_len = equal_sign - (const char *) data;
    size_t value_len = length - key_len - 1;

    return strndup(equal_sign + 1, value_len);
}

/**
 * @brief Create a syslog plaain text message from the basic fields
 *
 * The syslog format is: $TIMESTAMP $HOSTNAME $SYSLOG_IDENTIFIER[$PID]: $MESSAGE
 *
 *  * The caller is responsible for freeing the returned string.
 * @param timestamp  The timestamp
 * @param hostname
 * @param syslog_identifier
 * @param pid
 * @param message
 * @return char*
 * @warning The arguments must be valid strings (except pid)
 */
STATIC INLINE char * create_plain_syslog(const char * timestamp,
                                         const char * hostname,
                                         const char * syslog_identifier,
                                         const char * pid,
                                         const char * message) {
    static const char * syslog_format = "%s %s %s%s%s%s: %s";

    size_t size = snprintf(NULL,
                           0,
                           syslog_format,
                           timestamp,
                           hostname,
                           syslog_identifier,
                           pid ? "[" : "",
                           pid ? pid : "",
                           pid ? "]" : "",
                           message)
                  + 1;

    char * syslog_msg;
    os_calloc(size, sizeof(char), syslog_msg);
    snprintf(syslog_msg,
             size,
             syslog_format,
             timestamp,
             hostname,
             syslog_identifier,
             pid ? "[" : "",
             pid ? pid : "",
             pid ? "]" : "",
             message);
    return syslog_msg;
}

/**
 * @brief Create the entry from the current entry in the journal log context
 *
 * @param ctx
 * @param type
 * @return w_journal_entry_t*
 */
STATIC INLINE char * entry_as_syslog(w_journal_context_t * ctx) {

    char * hostname = get_field_ptr(ctx, "_HOSTNAME");
    char * syslog_identifier = get_field_ptr(ctx, "SYSLOG_IDENTIFIER");
    char * message = get_field_ptr(ctx, "MESSAGE");
    char * pid = get_field_ptr(ctx, "SYSLOG_PID");
    if (pid == NULL) {
        pid = get_field_ptr(ctx, "_PID");
    }
    char * timestamp = w_timestamp_to_string(ctx->timestamp);

    if (!hostname || !message || !timestamp) {
        mdebug2(LOGCOLLECTOR_JOURNAL_LOG_NOT_SYSLOG, ctx->timestamp);
        os_free(hostname);
        os_free(syslog_identifier);
        os_free(message);
        os_free(pid);
        os_free(timestamp);
        return NULL;
    }

    if (syslog_identifier == NULL) {
        syslog_identifier = strdup("unknown");
    }

    char * syslog_msg = create_plain_syslog(timestamp, hostname, syslog_identifier, pid, message);

    // Free the memory
    os_free(hostname);
    os_free(syslog_identifier);
    os_free(message);
    os_free(pid);
    os_free(timestamp);

    return syslog_msg;
}

w_journal_entry_t * w_journal_entry_dump(w_journal_context_t * ctx, w_journal_entry_dump_type_t type) {

    if (ctx == NULL || ctx->journal == NULL) {
        return NULL;
    }

    w_journal_entry_t * entry = NULL;
    os_calloc(1, sizeof(w_journal_entry_t), entry);
    entry->type = W_JOURNAL_ENTRY_DUMP_TYPE_INVALID;
    entry->timestamp = ctx->timestamp;

    // Create the dump
    switch (type) {
    case W_JOURNAL_ENTRY_DUMP_TYPE_JSON:
        entry->data.json = entry_as_json(ctx);
        if (entry->data.json != NULL) {
            entry->type = W_JOURNAL_ENTRY_DUMP_TYPE_JSON;
        }
        break;
    case W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG:
        entry->data.syslog = entry_as_syslog(ctx);
        if (entry->data.syslog != NULL) {
            entry->type = W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG;
        }
        break;
    default:
        break;
    }

    if (entry->type == W_JOURNAL_ENTRY_DUMP_TYPE_INVALID) {
        os_free(entry);
        return NULL;
    }
    return entry;
}

void w_journal_entry_free(w_journal_entry_t * entry) {

    if (entry == NULL) {
        return;
    }

    switch (entry->type) {
    case W_JOURNAL_ENTRY_DUMP_TYPE_JSON:
        cJSON_Delete(entry->data.json);
        break;
    case W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG:
        os_free(entry->data.syslog);
        break;
    default:
        break;
    }
    os_free(entry);
}

char * w_journal_entry_to_string(w_journal_entry_t * entry) {

    if (entry == NULL) {
        return NULL;
    }

    char * str = NULL;
    switch (entry->type) {
    case W_JOURNAL_ENTRY_DUMP_TYPE_JSON:
        str = cJSON_PrintUnformatted(entry->data.json);
        break;
    case W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG:
        str = strdup(entry->data.syslog);
        break;
    default:
        break;
    }
    return str;
}

/**********************************************************
 *                   Filter related
 **********************************************************/

/**
 * @brief Apply the filter to the current entry of the journal log context.
 *
 * @param ctx Journal log context
 * @param filter Journal log filter
 * @return int 1 if the entry matches the filter, 0 if it does not match, -1 on error
 */
int w_journal_filter_apply(w_journal_context_t * ctx, w_journal_filter_t * filter) {

    if (ctx == NULL || filter == NULL) {
        return -1;
    }

    for (size_t i = 0; i < filter->units_size; i++) {
        _w_journal_filter_unit_t * unit = filter->units[i];

        // Get the data
        const char * data;
        size_t length;

        int err = ctx->lib->get_data(ctx->journal, unit->field, (const void **) &data, &length);
        if (err < 0) {
            if (unit->ignore_if_missing) {
                continue;
            } else {
                mdebug2(LOGCOLLECTOR_JOURNAL_LOG_FIELD_ERROR, unit->field, ctx->timestamp, strerror(-err));
                return err;
            }
        }

        // Extract the value (data: key=value)
        size_t keyPart_len = strnlen(unit->field, length) + 1;
        if (keyPart_len > length) {
            return -1; // invalid value
        }
        size_t value_len = length - keyPart_len;
        char * value_str = strndup(data + keyPart_len, value_len);
        const char * end_match;

        bool match = w_expression_match(unit->exp, value_str, &end_match, NULL);

        os_free(value_str);
        if (!match) {
            return 0; // No match
        }
    }

    return 1; // Match
}

#endif
