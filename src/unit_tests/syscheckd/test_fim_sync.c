/*
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "../wrappers/common.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/queue_op_wrappers.h"
#include "../wrappers/wazuh/shared/integrity_op_wrappers.h"
#include "../wrappers/wazuh/syscheckd/create_db_wrappers.h"
#include "../wrappers/wazuh/syscheckd/fim_db_wrappers.h"
#include "../wrappers/wazuh/syscheckd/run_check_wrappers.h"

#include "../syscheckd/syscheck.h"
#include "../syscheckd/db/fim_db.h"

/* Globals */
extern long fim_sync_cur_id;
extern w_queue_t * fim_sync_queue;

fim_file_data DEFAULT_FILE_DATA = {
    // Checksum attributes
    .size = 0,
    .perm = "rw-rw-r--",
    .attributes = NULL,
    .uid = "1000",
    .gid = "1000",
    .user_name = "root",
    .group_name = "root",
    .mtime = 123456789,
    .inode = 1,
    .hash_md5 = "0123456789abcdef0123456789abcdef",
    .hash_sha1 = "0123456789abcdef0123456789abcdef01234567",
    .hash_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",

    // Options
    .mode = FIM_REALTIME,
    .last_event = 12345679,
    .dev = 100,
    .scanned = 0,
    .options = (CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_INODE | CHECK_MD5SUM |
                CHECK_SHA1SUM | CHECK_SHA256SUM),
    .checksum = "0123456789abcdef0123456789abcdef01234567",
};

#ifdef TEST_WINAGENT
const fim_registry_key DEFAULT_REGISTRY_KEY = {
    .id = 1,
    .path = "HKEY_LOCAL_MACHINE\\software\\some:\\key",
    .perm = "perm",
    .uid = "",
    .gid = "",
    .user_name = "",
    .group_name = "",
    .mtime = 12345678,
    .arch = ARCH_64BIT,
    .scanned = 1,
    .last_event = 12345679,
    .checksum = "0123456789abcdef0123456789abcdef01234567"
};

const fim_registry_value_data DEFAULT_REGISTRY_VALUE = {
    .id = 1,
    .name = "some:value",
    .type = REG_SZ,
    .size = 10,
    .hash_md5 = "0123456789abcdef0123456789abcdef",
    .hash_sha1 = "0123456789abcdef0123456789abcdef01234567",
    .hash_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    .scanned = 1,
    .last_event = 12345679,
    .checksum = "0123456789abcdef0123456789abcdef01234567",
    .mode = FIM_SCHEDULED
};

static registry REGISTRY_CONFIGURATION[] = {
    [0] = {
        .entry = "HKEY_LOCAL_MACHINE\\software",
        .arch = ARCH_64BIT,
        .opts = REGISTRY_CHECK_ALL,
        .recursion_level = 512,
        .diff_size_limit = 0,
        .restrict_key = NULL,
        .restrict_value = NULL,
        .tag = NULL
    },
    [1] = NULL };
#endif

/* Auxiliar structs */
typedef struct __json_payload_s {
    cJSON *payload;
    char *printed_payload;
} json_payload_t;

typedef struct __str_pair_s {
    char *first;
    char *last;
} str_pair_t;

/* redefinitons/wrapping */
#ifndef TEST_WINAGENT
int __wrap_time() {
    return 1572521857;
}
#endif

/* setup/teardown */
static int setup_group(void **state) {
#ifdef TEST_WINAGENT
    time_mock_value = 1572521857;

    syscheck.registry = REGISTRY_CONFIGURATION;
#endif
    syscheck.database = fim_db_init(FIM_DB_DISK);
    return 0;
}

static int teardown_group(void **state) {
    fim_db_close(syscheck.database);
    return 0;
}

static int setup_fim_sync_queue(void **state) {
    char *msg = (char *)malloc(sizeof(char) * 45);

    snprintf(msg, 45, "%s", "This is a mock message, it won't go anywhere");

    *state = msg;

    fim_sync_queue = queue_init(10);

    return 0;
}

static int teardown_fim_sync_queue(void **state) {
    char *msg = *state;

    free(msg);
    msg = NULL;

    char *copy = (char *)queue_pop(fim_sync_queue);

    if (copy) {
        free(copy);
        copy = NULL;
    }

    queue_free(fim_sync_queue);
    fim_sync_queue = NULL;

    return 0;
}

static int setup_json_payload(void **state) {
    json_payload_t *json_payload = calloc(1, sizeof(json_payload_t));
    const static char *text_payload =
        "{"
            "\"id\": 1234,"
            "\"begin\": \"start\","
            "\"end\": \"top\""
        "}";

    if(json_payload == NULL)
        return -1;

    json_payload->payload = cJSON_Parse(text_payload);

    if(json_payload->payload == NULL)
        return -1;

    json_payload->printed_payload = cJSON_PrintUnformatted(json_payload->payload);

    if(json_payload->printed_payload == NULL)
        return -1;

    *state = json_payload;
    return 0;
}

static int teardown_json_payload(void **state) {
    json_payload_t *json_payload = *state;

    cJSON_Delete(json_payload->payload);
    free(json_payload->printed_payload);
    free(json_payload);

    return 0;
}

static int setup_str_pair(void **state) {
    str_pair_t *new = malloc(sizeof(str_pair_t));
    if (new == NULL) {
        return -1;
    }

    new->first = strdup("first");
    new->last = strdup("last");

    *state = new;
    return new->first == NULL || new->last == NULL;
}


static int teardown_str_pair(void **state) {
    str_pair_t *new = *state;

    if(new->first)
        free(new->first);
    if(new->last)
        free(new->last);

    free(new);

    return 0;
}

static int teardown_str(void **state) {
    char *data = *state;
    free(data);

    return 0;
}

static int teardown_delete_json(void **state) {
    cJSON *json = *state;
    cJSON_Delete(json);
    return 0;
}

/* Auxiliar functions */

static void expect_fim_db_get_first_row_error(const fdb_t *db, int type, char *path, char *error_msg) {
    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_fim_db_get_first_path, fim_sql, db);
    expect_value(__wrap_fim_db_get_first_path, type, type);
    will_return(__wrap_fim_db_get_first_path, path);
    will_return(__wrap_fim_db_get_first_path, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, error_msg);
    expect_function_call(__wrap_pthread_mutex_unlock);
}

static void expect_fim_db_get_first_row_success(const fdb_t *db, int type, char *path) {
    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_fim_db_get_first_path, fim_sql, db);
    expect_value(__wrap_fim_db_get_first_path, type, type);
    will_return(__wrap_fim_db_get_first_path, path);
    will_return(__wrap_fim_db_get_first_path, FIMDB_OK);
}

static void expect_fim_db_get_last_row_success(const fdb_t *db, int type, char *path) {
    expect_value(__wrap_fim_db_get_last_path, fim_sql, db);
    expect_value(__wrap_fim_db_get_last_path, type, type);
    will_return(__wrap_fim_db_get_last_path, path);
    will_return(__wrap_fim_db_get_last_path, FIMDB_OK);
}

static void expect_fim_db_last_row_error(const fdb_t *db, int type, char *first_path, char *error_msg) {
    expect_fim_db_get_first_row_success(db, type, first_path);

    expect_value(__wrap_fim_db_get_last_path, fim_sql, db);
    expect_value(__wrap_fim_db_get_last_path, type, type);
    will_return(__wrap_fim_db_get_last_path, NULL);
    will_return(__wrap_fim_db_get_last_path, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, error_msg);
    expect_function_call(__wrap_pthread_mutex_unlock);
}

static void expect_fim_db_get_data_checksum_error(const fdb_t *db) {
    expect_fim_db_get_first_row_success(syscheck.database, FIM_TYPE_FILE, NULL);
    expect_fim_db_get_last_row_success(syscheck.database, FIM_TYPE_FILE, NULL);

    expect_value(__wrap_fim_db_get_data_checksum, fim_sql, db);
    will_return(__wrap_fim_db_get_data_checksum, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, FIM_DB_ERROR_CALC_CHECKSUM);
    expect_function_call(__wrap_pthread_mutex_unlock);
}

static void expect_fim_db_get_count_range_n(char *start, char *stop, int n) {
    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_fim_db_get_count_range, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_count_range, type, FIM_TYPE_FILE);
    expect_string(__wrap_fim_db_get_count_range, start, start);
    expect_string(__wrap_fim_db_get_count_range, top, stop);

    will_return(__wrap_fim_db_get_count_range, n);
    will_return(__wrap_fim_db_get_count_range, FIMDB_OK);

    expect_function_call(__wrap_pthread_mutex_unlock);
}

static void expect_fim_db_get_data_checksum_success(const fdb_t *db, char **first, char **last) {
    expect_fim_db_get_first_row_success(syscheck.database, FIM_TYPE_FILE, *first);
    expect_fim_db_get_last_row_success(syscheck.database, FIM_TYPE_FILE, *last);

    expect_value(__wrap_fim_db_get_data_checksum, fim_sql, db);
    will_return(__wrap_fim_db_get_data_checksum, FIMDB_OK);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_dbsync_check_msg_call("fim_file",INTEGRITY_CHECK_GLOBAL, 1572521857, *first, *last, NULL,
                                 strdup("A mock message"));

    expect_string(__wrap_fim_send_sync_msg, msg, "A mock message");
}

static void expect_fim_db_get_entry_from_sync_msg(char *path, int type, fim_entry *mock_entry) {
    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_fim_db_get_entry_from_sync_msg, fim_sql, syscheck.database);
#ifdef TEST_WINAGENT
    expect_value(__wrap_fim_db_get_entry_from_sync_msg, type, type);
#endif
    expect_value(__wrap_fim_db_get_entry_from_sync_msg, path, path);
    will_return(__wrap_fim_db_get_entry_from_sync_msg, mock_entry);

    expect_function_call(__wrap_pthread_mutex_unlock);
}

static void expect_fim_db_get_path_range(fdb_t *db,
                                        fim_type type,
                                        char *start,
                                        char *top,
                                        int storage,
                                        fim_tmp_file *file,
                                        int ret) {

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_fim_db_get_path_range, fim_sql, db);
    expect_value(__wrap_fim_db_get_path_range, type, type);
    expect_string(__wrap_fim_db_get_path_range, start, start);
    expect_string(__wrap_fim_db_get_path_range, top, top);
    expect_value(__wrap_fim_db_get_path_range, storage, storage);
    will_return(__wrap_fim_db_get_path_range, file);
    will_return(__wrap_fim_db_get_path_range, ret);

    expect_function_call(__wrap_pthread_mutex_unlock);
}

static void expect_fim_db_read_line_from_file(fim_tmp_file *file, int storage, int it, char *buffer, int ret) {
    expect_value(__wrap_fim_db_read_line_from_file, file, file);
    expect_value(__wrap_fim_db_read_line_from_file, storage, storage);
    expect_value(__wrap_fim_db_read_line_from_file, it, it);

    will_return(__wrap_fim_db_read_line_from_file, buffer);
    will_return(__wrap_fim_db_read_line_from_file, ret);
}

static void expect_read_line(fim_tmp_file *file, char *line, fim_entry *entry, int storage) {

    expect_fim_db_read_line_from_file (file, FIM_DB_DISK, 0, line, FIMDB_OK);
    expect_fim_db_get_entry_from_sync_msg(line, FIM_TYPE_FILE, entry);

    expect_any(__wrap_dbsync_state_msg, data);
    expect_string(__wrap_dbsync_state_msg, component, "fim_file");
    will_return(__wrap_dbsync_state_msg, strdup("msg"));

    expect_any(__wrap_fim_send_sync_msg, msg);
    expect_fim_db_read_line_from_file(file, storage, 1, NULL, 1);

    expect_any(__wrap_fim_db_clean_file, file);
    expect_value(__wrap_fim_db_clean_file, storage, storage);
}

/* tests */
/* fim_sync_push_msg */
static void test_fim_sync_push_msg_success(void **state) {
    char *msg = *state;

    expect_value(__wrap_queue_push_ex, queue, fim_sync_queue);
    expect_string(__wrap_queue_push_ex, data, msg);
    will_return(__wrap_queue_push_ex, 0);

    fim_sync_push_msg(msg);
}

static void test_fim_sync_push_msg_queue_full(void **state) {
    char *msg = *state;

    expect_value(__wrap_queue_push_ex, queue, fim_sync_queue);
    expect_string(__wrap_queue_push_ex, data, msg);
    will_return(__wrap_queue_push_ex, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Cannot push a data synchronization message: queue is full.");

    fim_sync_push_msg(msg);
}

static void test_fim_sync_push_msg_no_response(void **state) {
    expect_string(__wrap__mwarn, formatted_msg,
        "A data synchronization response was received before sending the first message.");

    fim_sync_push_msg("test");
}

/* fim_sync_checksum */
static void test_fim_sync_checksum_first_row_error(void **state) {
    pthread_mutex_t *mutex = NULL;
    char buffer[60];
    snprintf(buffer, 60, FIM_DB_ERROR_GET_ROW_PATH, "FIRST", "FILE");

    expect_fim_db_get_first_row_error(syscheck.database, FIM_TYPE_FILE, NULL, buffer);

    fim_sync_checksum(FIM_TYPE_FILE, mutex);
}

static void test_fim_sync_checksum_last_row_error(void **state) {
    pthread_mutex_t *mutex = NULL;
    char buffer[60];
    snprintf(buffer, 60, FIM_DB_ERROR_GET_ROW_PATH, "LAST","FILE");

    expect_fim_db_last_row_error(syscheck.database, FIM_TYPE_FILE, NULL, buffer);

    fim_sync_checksum(FIM_TYPE_FILE, mutex);
}

static void test_fim_sync_checksum_checksum_error(void **state) {
    pthread_mutex_t *mutex = NULL;

    expect_fim_db_get_data_checksum_error(syscheck.database);

    fim_sync_checksum(FIM_TYPE_FILE, mutex);
}

static void test_fim_sync_checksum_empty_db(void **state) {
    pthread_mutex_t *mutex = NULL;

    expect_fim_db_get_first_row_success(syscheck.database, FIM_TYPE_FILE, NULL);
    expect_fim_db_get_last_row_success(syscheck.database, FIM_TYPE_FILE, NULL);

    expect_value(__wrap_fim_db_get_data_checksum, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_get_data_checksum, FIMDB_OK);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_dbsync_check_msg_call("fim_file", INTEGRITY_CLEAR, 1572521857, NULL, NULL, NULL, strdup("A mock message"));

    expect_string(__wrap_fim_send_sync_msg, msg, "A mock message");
    fim_sync_checksum(FIM_TYPE_FILE, mutex);
}
static void test_fim_sync_checksum_success(void **state) {
    pthread_mutex_t *mutex = NULL;
    str_pair_t *pair = *state;

    char *first = pair->first;
    char *last = pair->last;

    expect_fim_db_get_data_checksum_success(syscheck.database, &first, &last);
    fim_sync_checksum(FIM_TYPE_FILE, mutex);
    pair->first = NULL;
    pair->last = NULL;
}

/* fim_sync_checksum_split */
static void test_fim_sync_checksum_split_get_count_range_error(void **state) {
    pthread_mutex_t *mutex = NULL;
    str_pair_t *pair = *state;

    char *first = pair->first;
    char *last = pair->last;
    char buffer[256];

    snprintf(buffer, 256, FIM_DB_ERROR_COUNT_RANGE, first, last);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_value(__wrap_fim_db_get_count_range, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_count_range, type, FIM_TYPE_FILE);
    expect_string(__wrap_fim_db_get_count_range, start, first);
    expect_string(__wrap_fim_db_get_count_range, top, last);
    will_return(__wrap_fim_db_get_count_range, 0);
    will_return(__wrap_fim_db_get_count_range, FIMDB_ERR);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__merror, formatted_msg, buffer);

    fim_sync_checksum_split(first, last, 1234);
}

static void test_fim_sync_checksum_split_range_size_0(void **state) {
    expect_fim_db_get_count_range_n("start", "top", 0);
    fim_sync_checksum_split("start", "top", 1234);
}

static void test_fim_sync_checksum_split_range_size_1(void **state) {
    fim_entry entry;
    entry.type = FIM_TYPE_FILE;
    entry.file_entry.path = "/some/path";
    entry.file_entry.data = &DEFAULT_FILE_DATA;

    char *str = strdup("some message");

    expect_fim_db_get_count_range_n("start", "top", 1);

    expect_fim_db_get_entry_from_sync_msg("start", FIM_TYPE_FILE, &entry);

    expect_any(__wrap_dbsync_state_msg, data);
    expect_string(__wrap_dbsync_state_msg, component, "fim_file");
    will_return(__wrap_dbsync_state_msg, str);

    expect_any(__wrap_fim_send_sync_msg, msg);

    fim_sync_checksum_split("start", "top", 1234);
    // str is freed at this point.
}

static void test_fim_sync_checksum_split_range_size_1_get_path_error(void **state) {
    char buffer[38];
    snprintf(buffer, 38, FIM_DB_ERROR_GET_PATH, "start");

    expect_fim_db_get_count_range_n("start", "top", 1);
    expect_fim_db_get_entry_from_sync_msg("start", FIM_TYPE_FILE, NULL);

    expect_string(__wrap__merror, formatted_msg, buffer);

    fim_sync_checksum_split("start", "top", 1234);
}

static void test_fim_sync_checksum_split_range_size_default(void **state) {
    expect_fim_db_get_count_range_n("start", "top", 2);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_fim_db_get_checksum_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_checksum_range, start, "start");
    expect_string(__wrap_fim_db_get_checksum_range, top, "top");
    expect_value(__wrap_fim_db_get_checksum_range, n, 2);

    will_return(__wrap_fim_db_get_checksum_range, strdup("path1"));
    will_return(__wrap_fim_db_get_checksum_range, strdup("path2"));
    will_return(__wrap_fim_db_get_checksum_range, FIMDB_OK);

    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_dbsync_check_msg_call("fim_file", INTEGRITY_CHECK_LEFT, 1234, "start", "path1", "path2",
                                 strdup("plain_text"));

    expect_string(__wrap_fim_send_sync_msg, msg, "plain_text");

    expect_dbsync_check_msg_call("fim_file", INTEGRITY_CHECK_RIGHT, 1234, "path2", "top", "", strdup("plain_text"));

    expect_string(__wrap_fim_send_sync_msg, msg, "plain_text");

    fim_sync_checksum_split("start", "top", 1234);
}

/* fim_sync_send_list */
static void test_fim_sync_send_list_sync_path_range_error(void **state) {
    str_pair_t *pair = *state;
    char *start = pair->first;
    char *top = pair->last;

    expect_fim_db_get_path_range(syscheck.database, FIM_TYPE_FILE, start, top, FIM_DB_DISK, NULL, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, FIM_DB_ERROR_SYNC_DB);

    fim_sync_send_list(start, top);
}

static void test_fim_sync_send_list_success(void **state) {
    fim_tmp_file file;
    file.elements = 1;

    fim_entry entry;
    entry.type = FIM_TYPE_FILE;
    entry.file_entry.path = "/some/path";
    entry.file_entry.data = &DEFAULT_FILE_DATA;

    expect_read_line(&file, strdup("/some/path"), &entry, FIM_DB_DISK);

    expect_fim_db_get_path_range(syscheck.database, FIM_TYPE_FILE, "start", "top", FIM_DB_DISK, &file, FIMDB_OK);

    fim_sync_send_list("start", "top");
}

/* fim_sync_dispatch */
static void test_fim_sync_dispatch_null_payload(void **state) {
    expect_assert_failure(fim_sync_dispatch(NULL));
}

static void test_fim_sync_dispatch_no_argument(void **state) {
    expect_string(__wrap__mdebug1, formatted_msg, "(6312): Data synchronization command 'no_argument' with no argument.");

    fim_sync_dispatch("no_argument");
}

static void test_fim_sync_dispatch_invalid_argument(void **state) {
    json_payload_t *json_payload = *state;
    char payload[OS_MAXSTR];

    snprintf(payload, OS_MAXSTR, "invalid_json %.3s", json_payload->printed_payload);

    expect_string(__wrap__mdebug1, formatted_msg, "(6314): Invalid data synchronization argument: '{\"i'");

    fim_sync_dispatch(payload);
}

static void test_fim_sync_dispatch_id_not_number(void **state) {
    json_payload_t *json_payload = *state;
    char payload[OS_MAXSTR];

    cJSON_DeleteItemFromObject(json_payload->payload, "id");
    cJSON_AddStringToObject(json_payload->payload, "id", "invalid");

    free(json_payload->printed_payload);

    json_payload->printed_payload = cJSON_PrintUnformatted(json_payload->payload);

    if(json_payload->printed_payload == NULL)
        fail();

    snprintf(payload, OS_MAXSTR, "invalid_id %s", json_payload->printed_payload);

    expect_string(__wrap__mdebug1, formatted_msg, "(6314): Invalid data synchronization argument: '{\"begin\":\"start\",\"end\":\"top\",\"id\":\"invalid\"}'");

    fim_sync_dispatch(payload);
}

static void test_fim_sync_dispatch_drop_message(void **state) {
    json_payload_t *json_payload = *state;
    char payload[OS_MAXSTR];

    snprintf(payload, OS_MAXSTR, "drop_message %s", json_payload->printed_payload);

    fim_sync_cur_id = 0;

    expect_string(__wrap__mdebug1, formatted_msg, "(6316): Dropping message with id (1234) greater than global id (0)");

    fim_sync_dispatch(payload);
}

static void test_fim_sync_dispatch_no_begin_object(void **state) {
    json_payload_t *json_payload = *state;
    char payload[OS_MAXSTR];

    cJSON_DeleteItemFromObject(json_payload->payload, "begin");

    free(json_payload->printed_payload);

    json_payload->printed_payload = cJSON_PrintUnformatted(json_payload->payload);

    if(json_payload->printed_payload == NULL)
        fail();

    snprintf(payload, OS_MAXSTR, "no_begin %s", json_payload->printed_payload);

    fim_sync_cur_id = 1235;

    expect_string(__wrap__mdebug1, formatted_msg, "(6315): Setting global ID back to lower message ID (1234)");
    expect_string(__wrap__mdebug1, formatted_msg, "(6314): Invalid data synchronization argument: '{\"id\":1234,\"end\":\"top\"}'");

    fim_sync_dispatch(payload);
}

static void test_fim_sync_dispatch_checksum_fail(void **state) {
    json_payload_t *json_payload = *state;
    char payload[OS_MAXSTR];

    snprintf(payload, OS_MAXSTR, "checksum_fail %s", json_payload->printed_payload);

    fim_sync_cur_id = 1234;

    // Inside fim_sync_checksum_split
    expect_fim_db_get_count_range_n("start", "top", 0);

    fim_sync_dispatch(payload);
}

static void test_fim_sync_dispatch_no_data(void **state) {
    int i;
    char payload[OS_MAXSTR];
    char *line = strdup("entry from file");


    fim_entry entry;
    entry.type = FIM_TYPE_FILE;
    entry.file_entry.path = "/some/path";
    entry.file_entry.data = &DEFAULT_FILE_DATA;

    json_payload_t *json_payload = *state;
    fim_tmp_file file;

    snprintf(payload, OS_MAXSTR, "no_data %s", json_payload->printed_payload);
    fim_sync_cur_id = 1234;

    // Inside fim_sync_send_list
    file.elements = 1;
    expect_fim_db_get_path_range(syscheck.database, FIM_TYPE_FILE, "start", "top", FIM_DB_DISK, &file, FIMDB_OK);
    expect_read_line(&file, line, &entry, FIM_DB_DISK);

    fim_sync_dispatch(payload);
}

static void test_fim_sync_dispatch_unwknown_command(void **state) {
    json_payload_t *json_payload = *state;
    char payload[OS_MAXSTR];

    snprintf(payload, OS_MAXSTR, "unknown %s", json_payload->printed_payload);

    fim_sync_cur_id = 1234;

    // Inside fim_sync_send_list
    expect_string(__wrap__mdebug1, formatted_msg, "(6313): Unknown data synchronization command: 'unknown'");

    fim_sync_dispatch(payload);
}


static void test_fim_entry_json_file_entry(void **state) {
    char *f_path = "/dir/test";
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = f_path, .file_entry.data = &DEFAULT_FILE_DATA };
    cJSON *event;

    event = fim_entry_json(f_path, &entry);

    assert_non_null(event);

    *state = event;

    cJSON *path = cJSON_GetObjectItem(event, "path");
    assert_non_null(path);
    assert_string_equal(path->valuestring, f_path);

    cJSON *timestamp = cJSON_GetObjectItem(event, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 12345679);
}

#ifdef TEST_WINAGENT
static void test_fim_entry_json_registry_key_entry(void **state) {
    const char *input_path = DEFAULT_REGISTRY_KEY.path;
    fim_registry_key key = DEFAULT_REGISTRY_KEY;
    fim_entry entry = {
        .type = FIM_TYPE_REGISTRY,
        .registry_entry.key = &key,
        .registry_entry.value = NULL
    };
    cJSON *event;

    event = fim_entry_json(input_path, &entry);

    assert_non_null(event);

    *state = event;

    cJSON *path = cJSON_GetObjectItem(event, "path");
    assert_non_null(path);
    assert_string_equal(path->valuestring, input_path);

    cJSON *timestamp = cJSON_GetObjectItem(event, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 12345679);

    cJSON *arch = cJSON_GetObjectItem(event, "arch");
    assert_non_null(arch);
    assert_string_equal(arch->valuestring, "[x64]");

    assert_null(cJSON_GetObjectItem(event, "value_name"));
}

static void test_fim_entry_json_registry_value_entry(void **state) {
    const char *input_path = DEFAULT_REGISTRY_KEY.path;
    fim_registry_key key = DEFAULT_REGISTRY_KEY;
    fim_registry_value_data value = DEFAULT_REGISTRY_VALUE;
    fim_entry entry = {
        .type = FIM_TYPE_REGISTRY,
        .registry_entry.key = &key,
        .registry_entry.value = &value
    };
    cJSON *event;

    event = fim_entry_json(input_path, &entry);

    assert_non_null(event);

    *state = event;

    cJSON *path = cJSON_GetObjectItem(event, "path");
    assert_non_null(path);
    assert_string_equal(path->valuestring, input_path);

    cJSON *timestamp = cJSON_GetObjectItem(event, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 12345679);

    cJSON *arch = cJSON_GetObjectItem(event, "arch");
    assert_non_null(arch);
    assert_string_equal(arch->valuestring, "[x64]");

    cJSON *value_name = cJSON_GetObjectItem(event, "value_name");
    assert_non_null(value_name);
    assert_string_equal(value_name->valuestring, "some:value");
}
#endif

static void test_fim_entry_json_null_path(void **state) {
    char *f_path = "/dir/test";
    fim_entry entry = { .type = FIM_TYPE_FILE, .file_entry.path = f_path, .file_entry.data = &DEFAULT_FILE_DATA };
    cJSON *event;

    expect_assert_failure(fim_entry_json(NULL, &entry));
}

static void test_fim_entry_json_null_data(void **state) {
    expect_assert_failure(fim_entry_json("/a/path", NULL));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* fim_sync_push */
        cmocka_unit_test_setup_teardown(test_fim_sync_push_msg_success, setup_fim_sync_queue, teardown_fim_sync_queue),
        cmocka_unit_test_setup_teardown(test_fim_sync_push_msg_queue_full, setup_fim_sync_queue, teardown_fim_sync_queue),
        cmocka_unit_test(test_fim_sync_push_msg_no_response),

        /* fim_sync_checksum */
        cmocka_unit_test(test_fim_sync_checksum_first_row_error),
        cmocka_unit_test(test_fim_sync_checksum_last_row_error),
        cmocka_unit_test(test_fim_sync_checksum_checksum_error),
        cmocka_unit_test(test_fim_sync_checksum_empty_db),
        cmocka_unit_test_setup_teardown(test_fim_sync_checksum_success, setup_str_pair, teardown_str_pair),

        /* fim_sync_checksum_split */
        cmocka_unit_test_setup_teardown(test_fim_sync_checksum_split_get_count_range_error, setup_str_pair, teardown_str_pair),
        cmocka_unit_test(test_fim_sync_checksum_split_range_size_0),
        cmocka_unit_test(test_fim_sync_checksum_split_range_size_1),
        cmocka_unit_test(test_fim_sync_checksum_split_range_size_1_get_path_error),
        cmocka_unit_test(test_fim_sync_checksum_split_range_size_default),

        /* fim_sync_send_list */
        cmocka_unit_test_setup_teardown(test_fim_sync_send_list_sync_path_range_error, setup_str_pair, teardown_str_pair),
        cmocka_unit_test(test_fim_sync_send_list_success),

        /* fim_sync_dispatch */
        cmocka_unit_test(test_fim_sync_dispatch_null_payload),
        cmocka_unit_test(test_fim_sync_dispatch_no_argument),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_invalid_argument, setup_json_payload, teardown_json_payload),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_id_not_number, setup_json_payload, teardown_json_payload),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_drop_message, setup_json_payload, teardown_json_payload),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_no_begin_object, setup_json_payload, teardown_json_payload),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_checksum_fail, setup_json_payload, teardown_json_payload),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_no_data, setup_json_payload, teardown_json_payload),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_unwknown_command, setup_json_payload, teardown_json_payload),

        /* fim_entry_json */
        cmocka_unit_test_teardown(test_fim_entry_json_file_entry, teardown_delete_json),
#ifdef TEST_WINAGENT
        cmocka_unit_test_teardown(test_fim_entry_json_registry_key_entry, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_entry_json_registry_value_entry, teardown_delete_json),
#endif
        cmocka_unit_test(test_fim_entry_json_null_path),
        cmocka_unit_test(test_fim_entry_json_null_data),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
