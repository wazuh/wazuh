
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "../wazuh_db/wdb.h"
#include "../headers/shared.h"

#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"


/********** setup/teardown *********************/
int setup_wdb(void **state) {
    wdb_t *wdb = NULL;
    os_calloc(1,sizeof(wdb_t),wdb);
    os_strdup("000",wdb->id);
    os_calloc(1,sizeof(sqlite3 *),wdb->db);
    *state = wdb;
    return 0;
}

int teardown_wdb(void **state) {
    wdb_t *wdb  = (wdb_t *)*state;
    os_free(wdb->id);
    os_free(wdb->db);
    os_free(wdb);
    return 0;
}
/***********  tests  *********************/
void test_wdb_rootcheck_insert_cache_error(void **state) {
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__merror, formatted_msg, "DB(000) Cannot cache statement");

    wdb_t *wdb  = (wdb_t *)*state;
    rk_event_t event;
    event.date_last = time(0);
    event.date_first = event.date_last;
    event.log = "Test log";
    int ret = wdb_rootcheck_insert(wdb, &event);
    assert_int_equal(ret, -1);
}

void test_wdb_rootcheck_insert_success(void **state) {
    wdb_t *wdb  = (wdb_t *)*state;
    rk_event_t event;
    event.date_last = time(0);
    event.date_first = event.date_last;
    event.log = "Test log";

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, event.date_first);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, event.date_last);
    will_return_always(__wrap_sqlite3_bind_int, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "Test log");
    will_return(__wrap_sqlite3_bind_text, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    will_return(__wrap_sqlite3_bind_text, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    will_return(__wrap_sqlite3_bind_text, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_last_insert_rowid, 10);
    int ret = wdb_rootcheck_insert(wdb, &event);

    assert_int_equal(ret, 10);
}


void test_wdb_rootcheck_update_cache_error(void **state) {
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__merror, formatted_msg, "DB(000) Cannot cache statement");

    wdb_t *wdb  = (wdb_t *)*state;
    rk_event_t event;
    event.date_last = time(0);
    event.date_first = event.date_last;
    event.log = "Test log";
    int ret = wdb_rootcheck_update(wdb, &event);
    assert_int_equal(ret, -1);
}

void test_wdb_rootcheck_update_succcess(void **state) {
    wdb_t *wdb  = (wdb_t *)*state;
    rk_event_t event;
    event.date_first = time(0);
    event.date_last = event.date_first + 1;
    event.log = "Test log";

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, event.date_last);
    will_return_always(__wrap_sqlite3_bind_int, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "Test log");
    will_return(__wrap_sqlite3_bind_text, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 10);
    int ret = wdb_rootcheck_update(wdb, &event);
    assert_int_equal(ret, 10);
}

void test_wdb_rootcheck_delete_cache_error(void **state) {
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__merror, formatted_msg, "DB(000) Cannot cache statement");

    wdb_t *wdb  = (wdb_t *)*state;
    int ret = wdb_rootcheck_delete(wdb);
    assert_int_equal(ret, -1);
}

void test_wdb_rootcheck_delete_success(void **state) {
    wdb_t *wdb  = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 10);
    int ret = wdb_rootcheck_delete(wdb);
    assert_int_equal(ret, 10);
}
/***********************************************/

int main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_wdb_rootcheck_insert_cache_error, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_rootcheck_insert_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_rootcheck_update_cache_error, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_rootcheck_update_succcess, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_rootcheck_delete_cache_error, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_rootcheck_delete_success, setup_wdb, teardown_wdb)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
