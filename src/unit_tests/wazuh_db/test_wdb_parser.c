#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"


#include "os_err.h"
#include "../wazuh_db/wdb.h"

typedef struct test_struct {
    wdb_t *wdb;
    wdb_t *wdb_global;
    char *output;
} test_struct_t;

static int test_teardown(void **state){
    test_struct_t *data  = (test_struct_t *)*state;

    free(data->output);
    free(data->wdb->id);
    free(data->wdb);
    free(data->wdb_global);
    free(data);

    return 0;
}

static int test_setup_global(void **state) {
    test_struct_t *init_data;

    init_data = malloc(sizeof(test_struct_t));
    init_data->wdb = malloc(sizeof(wdb_t));
    init_data->wdb_global = malloc(sizeof(wdb_t));
    init_data->wdb->id = strdup("global");
    init_data->output = calloc(256, sizeof(char));
    init_data->wdb->peer = 1234;
    init_data->wdb->enabled = true;

    *state = init_data;

    return 0;
}

/* wdb_parse_global_backup */

void test_wdb_parse_global_backup_invalid_syntax(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global backup", query);
    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: backup");

    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for backup.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: backup");

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'backup'");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_global_backup_missing_action(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("", query);

    result = wdb_parse_global_backup(NULL, query, data->output);

    assert_string_equal(data->output, "err Missing backup action");
    assert_int_equal(result, OS_INVALID);
    os_free(query);
}

void test_wdb_parse_global_backup_invalid_action(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("invalid", query);

    result = wdb_parse_global_backup(NULL, query, data->output);

    assert_string_equal(data->output, "err Invalid backup action: invalid");
    assert_int_equal(result, OS_INVALID);
    os_free(query);
}

void test_wdb_parse_global_backup_create_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global backup create", query);
    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: backup create");

    will_return(__wrap_wdb_global_create_backup, "ERROR MESSAGE");
    will_return(__wrap_wdb_global_create_backup, OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Creating Global DB snapshot on demand failed: ERROR MESSAGE");

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ERROR MESSAGE");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_global_backup_create_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global backup create", query);
    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: backup create");

    will_return(__wrap_wdb_global_create_backup, "ok SNAPSHOT");
    will_return(__wrap_wdb_global_create_backup, OS_SUCCESS);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok SNAPSHOT");
    assert_int_equal(result, OS_SUCCESS);

    os_free(query);
}

int main()
{
    const struct CMUnitTest tests[] = {
        /* wdb_parse_global_backup */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_backup_invalid_syntax, test_setup_global, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_backup_missing_action, test_setup_global, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_backup_invalid_action, test_setup_global, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_backup_create_failed, test_setup_global, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_backup_create_success, test_setup_global, test_teardown),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
