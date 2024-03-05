#if defined(__linux__)

#include "journal_log.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "debug_op.h"
#include "string_op.h"
#include "sym_load.h"

// TODO: Review de error handling
static const int W_SD_JOURNAL_LOCAL_ONLY = 1 << 0;
static const char* W_LIB_SYSTEMD = "systemd";

/**********************************************************
 *                    Auxiliar functions
 ***********************************************************/

/**
 * @brief Return the epoch time in microseconds
 *
 * @return int64_t
 */
static inline uint64_t w_get_epoch_time()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/**
 * @brief Convert the epoch time to a human-readable string (ISO 8601)
 * 2022-12-19T15:02:53.288+00:00 hostnameTest processName[123]: Message Test >> Wazuh no extra el hostname
 * The caller is responsible for freeing the returned string.
 * @param timestamp The epoch time
 * @return char* The human-readable string or NULL on error
 */
static inline char* w_timestamp_to_string(uint64_t timestamp)
{
    struct tm tm;
    time_t time = timestamp / 1000000;
    if (gmtime_r(&time, &tm) == NULL)
    {
        return NULL;
    }

    char* str;
    os_calloc(sizeof("Mar 01 12:39:34") + 1, sizeof(char), str);
    strftime(str, sizeof("Mar 01 12:39:34"), "%b %d %T", &tm);
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
char* find_library_path(const char* library_name)
{
    FILE* maps_file = fopen("/proc/self/maps", "r");
    if (maps_file == NULL)
    {
        return NULL;
    }

    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    char* path = NULL;

    while ((read = getline(&line, &len, maps_file)) != -1)
    {
        if (strstr(line, library_name) != NULL)
        {
            char* path_start = strchr(line, '/');
            char* path_end = strchr(path_start, '\n');
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
bool is_owned_by_root(const char* library_path)
{
    struct stat file_stat;
    if (stat(library_path, &file_stat) != 0)
    {
        return false;
    }

    return file_stat.st_uid == 0;
}

/**
 * @brief Initialize the journal library functions
 * 
 * The caller is responsible for freeing the returned library.
 * @param char** Returns the error message if the library could not be loaded, NULL otherwise. // TODO
 * @return w_journal_lib_t* The library or NULL on error
 */
static inline w_journal_lib_t* w_journal_lib_init()
{
    w_journal_lib_t* lib = NULL;
    os_calloc(1, sizeof(w_journal_lib_t), lib);

    // Load the library
    lib->handle = so_get_module_handle(W_LIB_SYSTEMD);
    if (lib->handle == NULL)
    {
        os_free(lib);
        return NULL;
    }

    // Verify the ownership of the library
    char* library_path = find_library_path(W_LIB_SYSTEMD);
    if (library_path == NULL || !is_owned_by_root(library_path))
    {
        // mwarn("[journal_log] The library '%s' is not owned by the root user", W_LIB_SYSTEMD);
        os_free(library_path);
        so_free_library(lib->handle);
        os_free(lib);
        return NULL;
    }
    os_free(library_path);

    // Load and verify the functions
    lib->open = (w_journal_open)so_get_function_sym(lib->handle, "sd_journal_open");
    lib->close = (w_journal_close)so_get_function_sym(lib->handle, "sd_journal_close");
    lib->get_timestamp = (w_journal_get_timestamp)so_get_function_sym(lib->handle, "sd_journal_get_realtime_usec");
    lib->seek_tail = (w_journal_seek_tail)so_get_function_sym(lib->handle, "sd_journal_seek_tail");
    lib->previous = (w_journal_previous)so_get_function_sym(lib->handle, "sd_journal_previous");
    lib->seek_timestamp = (w_journal_seek_timestamp)so_get_function_sym(lib->handle, "sd_journal_seek_realtime_usec");
    lib->next = (w_journal_next)so_get_function_sym(lib->handle, "sd_journal_next");
    lib->get_cutoff_timestamp =
        (w_journal_get_cutoff_timestamp)so_get_function_sym(lib->handle, "sd_journal_get_cutoff_realtime_usec");
    lib->enumerate_available_data =
        (w_journal_enumerate_available_data)so_get_function_sym(lib->handle, "sd_journal_enumerate_available_data");
    lib->get_data = (w_journal_get_data)so_get_function_sym(lib->handle, "sd_journal_get_data");

    if (lib->open == NULL || lib->close == NULL || lib->get_timestamp == NULL || lib->seek_tail == NULL
        || lib->previous == NULL || lib->seek_timestamp == NULL || lib->next == NULL
        || lib->get_cutoff_timestamp == NULL || lib->enumerate_available_data == NULL || lib->get_data == NULL)
    {
        so_free_library(lib->handle);
        os_free(lib);
        return NULL;
    }

    return lib;
}

/**********************************************************
 *                    Context related
 ***********************************************************/

int w_journal_context_create(w_journal_context_t** ctx)
{
    if (ctx == NULL)
    {
        return -1;
    }
    os_calloc(1, sizeof(w_journal_context_t), (*ctx));

    (*ctx)->lib = w_journal_lib_init();
    if ((*ctx)->lib == NULL)
    {
        os_free(*ctx);
        return -1;
    }

    return (*ctx)->lib->open(&((*ctx)->journal), W_SD_JOURNAL_LOCAL_ONLY);
}

void w_journal_context_free(w_journal_context_t* ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    ctx->lib->close(ctx->journal);
    so_free_library(ctx->lib->handle);
    os_free(ctx->lib);
    os_free(ctx);

}

void w_journal_context_update_timestamp(w_journal_context_t* ctx)
{
    static bool failed_logged = false;
    if (ctx == NULL)
    {
        return;
    }

    int err = ctx->lib->get_timestamp(ctx->journal, &(ctx->timestamp));
    if (err < 0)
    {
        ctx->timestamp = w_get_epoch_time();
        if (!failed_logged)
        {
            failed_logged = true;
            mwarn("[journal_log] Failed to get timestamp: '%s', using current time", strerror(-err));
        }
    }
}

int w_journal_context_seek_most_recent(w_journal_context_t* ctx)
{
    int err = ctx->lib->seek_tail(ctx->journal);
    if (err < 0)
    {
        return err;
    }

    err = ctx->lib->previous(ctx->journal);
    // if change cursor, update timestamp
    if (err > 0)
    {
        w_journal_context_update_timestamp(ctx);
    }
    return err;
}

int w_journal_context_seek_timestamp(w_journal_context_t* ctx, uint64_t timestamp)
{
    // If the timestamp is in the future or invalid, seek the most recent entry
    if (timestamp == 0 || timestamp > w_get_epoch_time())
    {
        mwarn("[journal_log] The timestamp '%" PRIu64 "' is in the future or invalid. Using the most recent entry",
              timestamp);
        // return w_journal_context_seek_most_recent(ctx);
        return ctx->lib->seek_tail(ctx->journal);
    }

    // Check if the timestamp is older than the oldest available
    uint64_t oldest;
    int err = w_journal_context_get_oldest_timestamp(ctx, &oldest);

    if (err < 0)
    {
        mwarn("[journal_log] Failed to get the oldest timestamp: '%s'", strerror(-err));
    }
    else if (timestamp < oldest)
    {
        mwarn("[journal_log] The timestamp '%" PRIu64
              "' is older than the oldest available in journal. Using the oldest entry",
              timestamp);
        timestamp = oldest;
    }

    err = ctx->lib->seek_timestamp(ctx->journal, timestamp);
    if (err < 0)
    {
        return err;
    }

    err = ctx->lib->next(ctx->journal);
    if (err > 0) // if the cursor change, update timestamp
    {
        w_journal_context_update_timestamp(ctx);
    }
    return err;
}

int w_journal_context_next_newest(w_journal_context_t* ctx)
{
    int ret = ctx->lib->next(ctx->journal);

    // if change cursor, update timestamp
    if (ret > 0)
    {
        w_journal_context_update_timestamp(ctx);
    }

    return ret;
}
// Check return value on value un error
int w_journal_context_get_oldest_timestamp(w_journal_context_t* ctx, uint64_t* timestamp)
{
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
static inline cJSON* entry_as_json(w_journal_context_t* ctx)
{
    cJSON* dump = cJSON_CreateObject();
    int isEmpty = 1; // Flag to check if the entry is empty

    // Iterate through the available data
    int result = 0;
    do
    {
        const char* data;
        size_t data_len;

        result = ctx->lib->enumerate_available_data(ctx->journal, (void const**)&data, &data_len);
        if (result < 0)
        {
            mwarn("[journal_log] Failed to enumerate data, discarted log: %s", strerror(-result));
            break;
        }
        else if (result == 0)
        {
            break;
        }

        // Parse the data, split it into key and value -> raw: key=value
        const char* separator = memchr(data, '=', data_len);
        if (separator == NULL || separator == data)
        {
            mwarn("[journal_log] Failed to find separator, key/value pair discarted");
            continue;
        }

        // Determine de key and value length
        size_t key_len = separator - data;
        size_t value_len = data_len - key_len - 1;

        // Allocate memory for the key and value (null terminated string)
        char* key;
        char* value;
        os_calloc(key_len + 1, sizeof(char), key);
        os_calloc(value_len + 1, sizeof(char), value);

        // Copy the key and value
        memcpy(key, data, key_len);
        memcpy(value, separator + 1, value_len);

        // Add the key and value to the entry
        cJSON_AddStringToObject(dump, key, value);
        isEmpty = 0;

        // Free the memory
       os_free(key);
       os_free(value);

    } while (result > 0);

    // Error or no data
    if (result < 0 || isEmpty)
    {
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
static inline char* get_field_ptr(w_journal_context_t* ctx, const char* field)
{
    const void* data;
    size_t length;

    int err = ctx->lib->get_data(ctx->journal, field, &data, &length);
    if (err < 0)
    {
        return NULL;
    }

    // Assume that the value is a string "key=value"
    const char* equal_sign = memchr(data, '=', length);
    if (!equal_sign)
    {
        return NULL; // Invalid value
    }

    // Copy the value
    size_t key_len = equal_sign - (const char*)data;
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
static inline char* create_plain_syslog(
    const char* timestamp, const char* hostname, const char* syslog_identifier, const char* pid, const char* message)
{
    static const char* syslog_format = "%s %s %s%s%s%s: %s";

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

    char* syslog_msg;
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
static inline char* entry_as_syslog(w_journal_context_t* ctx)
{
    char* hostname = get_field_ptr(ctx, "_HOSTNAME");
    char* syslog_identifier = get_field_ptr(ctx, "SYSLOG_IDENTIFIER");
    char* message = get_field_ptr(ctx, "MESSAGE");
    char* pid = get_field_ptr(ctx, "_PID");
    char* timestamp = w_timestamp_to_string(ctx->timestamp);

    if (!hostname || !syslog_identifier || !message || !timestamp)
    {
        mdebug2("[journal_log] Failed to get the required fields, discarted log with timestamp '%" PRIu64 "'",
                ctx->timestamp);
        os_free(hostname);
        os_free(syslog_identifier);
        os_free(message);
        os_free(pid);
        os_free(timestamp);
        return NULL;
    }

    char* syslog_msg = create_plain_syslog(timestamp, hostname, syslog_identifier, pid, message);

    // Free the memory
    os_free(hostname);
    os_free(syslog_identifier);
    os_free(message);
    os_free(pid);
    os_free(timestamp);

    return syslog_msg;
}

w_journal_entry_t* w_journal_entry_dump(w_journal_context_t* ctx, w_journal_entry_dump_type_t type)
{
    if (ctx == NULL || ctx->journal == NULL)
    {
        return NULL;
    }

    w_journal_entry_t* entry = calloc(1, sizeof(w_journal_entry_t));
    entry->type = W_JOURNAL_ENTRY_DUMP_TYPE_INVALID;
    entry->timestamp = ctx->timestamp;

    // Create the dump
    switch (type)
    {
        case W_JOURNAL_ENTRY_DUMP_TYPE_JSON:
            entry->data.json = entry_as_json(ctx);
            if (entry->data.json != NULL)
            {
                entry->type = W_JOURNAL_ENTRY_DUMP_TYPE_JSON;
            }
            break;
        case W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG:
            entry->data.syslog = entry_as_syslog(ctx);
            if (entry->data.syslog != NULL)
            {
                entry->type = W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG;
            }
            break;
        default: break;
    }

    if (entry->type == W_JOURNAL_ENTRY_DUMP_TYPE_INVALID)
    {
        os_free(entry);
        return NULL;
    }
    return entry;
}

void w_journal_entry_free(w_journal_entry_t* entry)
{
    if (entry == NULL)
    {
        return;
    }

    switch (entry->type)
    {
        case W_JOURNAL_ENTRY_DUMP_TYPE_JSON: cJSON_Delete(entry->data.json); break;
        case W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG: os_free(entry->data.syslog); break;
        default: break;
    }
    os_free(entry);
}

char* w_journal_entry_to_string(w_journal_entry_t* entry)
{
    if (entry == NULL)
    {
        return NULL;
    }

    char* str = NULL;
    switch (entry->type)
    {
        case W_JOURNAL_ENTRY_DUMP_TYPE_JSON: str = cJSON_PrintUnformatted(entry->data.json); break;
        case W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG: str = strdup(entry->data.syslog); break;
        default: break;
    }
    return str;
}

/**********************************************************
 *                   Filter related
 **********************************************************/

/**
 * @brief Free the unit filter and all its resources
 *
 * The unit pointer is invalid after the call.
 * @param unit Journal filter unit
 */
static void free_unit_filter(_w_journal_filter_unit_t* unit)
{
    if (unit == NULL)
    {
        return;
    }

   os_free(unit->field);
   w_free_expression_t(&(unit->exp));
   os_free(unit);
}

/**
 * @brief Create the filter unit
 * The caller is responsible for freeing the returned unit.
 *
 * @param field The field to filter
 * @param expression The expression to match
 * @param ignore_if_missing Ignore if the field is missing
 */
static _w_journal_filter_unit_t* create_unit_filter(const char* field, char* expression, int ignore_if_missing)
{
    if (field == NULL || expression == NULL)
    {
        return NULL;
    }

    _w_journal_filter_unit_t* unit = calloc(1, sizeof(_w_journal_filter_unit_t));

    w_calloc_expression_t(&(unit->exp), EXP_TYPE_PCRE2);

    if (!w_expression_compile(unit->exp, expression, 0))
    {
        free_unit_filter(unit);
        return NULL;
    }

    unit->field = strdup(field);
    unit->ignore_if_missing = ignore_if_missing;

    return unit;
}

void w_journal_filter_free(w_journal_filter_t* ptr_filter)
{
    if (ptr_filter == NULL)
    {
        return;
    }

    if (ptr_filter->units != NULL)
    {
        for (size_t i = 0; ptr_filter->units[i] != NULL; i++)
        {
            free_unit_filter(ptr_filter->units[i]);   
        }

       os_free(ptr_filter->units);
    }

   os_free(ptr_filter);
}

int w_journal_filter_add_condition(w_journal_filter_t** ptr_filter,
                                   char* field,
                                   char* expression,
                                   int ignore_if_missing)
{
    if (field == NULL || expression == NULL || ptr_filter == NULL)
    {
        return -1;
    }

    // Crete the unit filter
    _w_journal_filter_unit_t* unit = create_unit_filter(field, expression, ignore_if_missing);
    if (unit == NULL)
    {
        return -1;
    }

    // If the filter does not exist, create it
    if (*ptr_filter == NULL)
    {
        *ptr_filter = calloc(1, sizeof(w_journal_filter_t));
    }
    w_journal_filter_t* filter = *ptr_filter;

    // Allocate memory for the new unit
    filter->units = realloc(filter->units, (filter->units_size + 2) * sizeof(_w_journal_filter_unit_t*));

    // Add the new unit
    filter->units[filter->units_size] = unit;
    filter->units_size++;
    filter->units[filter->units_size] = NULL;

    return 0;
}

/**
 * @brief Apply the filter to the current entry of the journal log context.
 *
 * @param ctx Journal log context
 * @param filter Journal log filter
 * @return int 1 if the entry matches the filter, 0 if it does not match, -1 on error
 */
int w_journal_filter_apply(w_journal_context_t* ctx, w_journal_filter_t* filter)
{
    if (ctx == NULL || filter == NULL)
    {
        return -1;
    }

    for (size_t i = 0; i < filter->units_size; i++)
    {
        _w_journal_filter_unit_t* unit = filter->units[i];

        // Get the data
        const char* data;
        size_t length;

        int err = ctx->lib->get_data(ctx->journal, unit->field, (const void**)&data, &length);
        if (err < 0)
        {
            if (unit->ignore_if_missing)
            {
                continue;
            }
            else
            {
                fprintf(stderr, "Failed to get data: %s\n", strerror(-err));
                return err;
            }
        }

        // Extract the value (data: key=value)
        size_t keyPart_len = strnlen(unit->field, length) + 1; // TODO store the length of the key
        if (keyPart_len > length)
        {
            return -1; // invalid value
        }
        size_t value_len = length - keyPart_len;
        char* value_str = strndup(data + keyPart_len, value_len);
        const char* end_match;

        bool match = w_expression_match(unit->exp, value_str, &end_match, NULL);

        // Print the match Debug 2
        // printf("Match: %d , pattern: '%s', field: '%s', value: '%s'\n", match, unit->exp->pcre2->raw_pattern,
        // unit->field, value_str);

       os_free(value_str);
        if (!match)
        {
            return 0; // No match
        }
    }

    return 1; // Match
}

#endif
