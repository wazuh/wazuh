
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"

#include "os_err.h"
#include "wazuh_db/wdb.h"

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data;

    init_data = malloc(sizeof(test_struct_t));
    init_data->wdb = malloc(sizeof(wdb_t));
    init_data->wdb->id = strdup("000");
    init_data->output = malloc(256*sizeof(char));

    *state = init_data;

    return 0;
}

static int test_teardown(void **state){
    test_struct_t *data  = (test_struct_t *)*state;

    free(data->output);
    free(data->wdb->id);
    free(data->wdb);
    free(data);

    return 0;
}

void test_wdb_parse_syscheck_no_space(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) Invalid FIM query syntax: badquery_nospace");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, "badquery_nospace", data->output);

    assert_string_equal(data->output, "err Invalid FIM query syntax, near \'badquery_nospace\'");
    assert_int_equal(ret, -1);
}

void test_scan_info_error(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("scan_info_get ");

    will_return(__wrap_wdb_scan_info_get, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot get FIM scan info.");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Cannot get fim scan info.");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_scan_info_ok(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("scan_info_get ");


    will_return(__wrap_wdb_scan_info_get, 1);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok 0");
    assert_int_equal(ret, 1);

    os_free(query);
}


void test_update_info_error(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("updatedate ");

    will_return(__wrap_wdb_fim_update_date_entry, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot update fim date field.");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Cannot update fim date field.");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_update_info_ok(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("updatedate ");

    will_return(__wrap_wdb_fim_update_date_entry, 1);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}


void test_clean_old_entries_error(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("cleandb ");

    will_return(__wrap_wdb_fim_clean_old_entries, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot clean fim database.");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Cannot clean fim database.");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_clean_old_entries_ok(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("cleandb ");

    will_return(__wrap_wdb_fim_clean_old_entries, 1);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_scan_info_update_noarg(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("scan_info_update ");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid scan_info fim query syntax.");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near \'\'");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_scan_info_update_error(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("scan_info_update \"191919\" ");

    will_return(__wrap_wdb_scan_info_update, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot save fim control message.");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Cannot save fim control message");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_scan_info_update_ok(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("scan_info_update \"191919\" ");

    will_return(__wrap_wdb_scan_info_update, 1);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_scan_info_fim_check_control_error(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("control ");

    will_return(__wrap_wdb_scan_info_fim_checks_control, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot save fim check_control message.");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Cannot save fim control message");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_scan_info_fim_check_control_ok(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("control ");

    will_return(__wrap_wdb_scan_info_fim_checks_control, 1);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_syscheck_load_error(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("load ");

    will_return(__wrap_wdb_syscheck_load, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot load FIM.");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Cannot load Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_load_ok(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("load ");

    will_return(__wrap_wdb_syscheck_load, 1);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok TEST STRING");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_fim_delete_error(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("delete ");

    will_return(__wrap_wdb_fim_delete, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot delete FIM entry.");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Cannot delete Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_fim_delete_ok(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("delete ");

    will_return(__wrap_wdb_fim_delete, 1);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_syscheck_save_noarg(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save ");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid FIM query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) FIM query: ");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near \'\'");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_invalid_type(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save invalid_type ");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid FIM query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) FIM query: invalid_type");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near \'invalid_type\'");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_file_type_error(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save file 1212121 ");

    will_return(__wrap_wdb_syscheck_save, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot save FIM.");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Cannot save Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_file_nospace(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save file ");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid FIM query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "FIM query: ");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near \'\'");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_file_type_ok(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save file !1212121 ");

    will_return(__wrap_wdb_syscheck_save, 1);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_syscheck_save_registry_type_error(void **state) {
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save registry 1212121 ");

    will_return(__wrap_wdb_syscheck_save, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot save FIM.");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Cannot save Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_registry_type_ok(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save registry !1212121 ");

    will_return(__wrap_wdb_syscheck_save, 1);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_syscheck_save2_error(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save2 ");

    will_return(__wrap_wdb_syscheck_save2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot save FIM.");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Cannot save Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save2_ok(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save2 ");

    will_return(__wrap_wdb_syscheck_save2, 1);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_integrity_check_error(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_check_ ");

    will_return(__wrap_wdbi_query_checksum, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot query FIM range checksum.");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Cannot perform range checksum");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_integrity_check_no_data(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_check_ ");

    will_return(__wrap_wdbi_query_checksum, 0);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok no_data");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_integrity_check_checksum_fail(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_check_ ");

    will_return(__wrap_wdbi_query_checksum, 1);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok checksum_fail");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_integrity_check_ok(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_check_ ");

    will_return(__wrap_wdbi_query_checksum, 2);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_integrity_clear_error(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_clear ");

    will_return(__wrap_wdbi_query_clear, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot query FIM range checksum.");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Cannot perform range checksum");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_integrity_clear_ok(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_clear ");

    will_return(__wrap_wdbi_query_clear, 2);

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, 0);

    os_free(query);
}


void test_invalid_command(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("wrong_command ");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid FIM query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB query error near: wrong_command");

    ret = wdb_parse_syscheck(data->wdb, WDB_FIM_FILE, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near 'wrong_command'");
    assert_int_equal(ret, -1);

    os_free(query);
}


void test_wdb_parse_rootcheck_badquery(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("badquery ");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) Invalid rootcheck query syntax: badquery");
    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid rootcheck query syntax, near 'badquery'");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_delete_error(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("delete");
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__merror, formatted_msg, "DB(000) Cannot cache statement");

    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Error deleting rootcheck PM tuple");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_delete_ok(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("delete");
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 10);

    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok 0");
    assert_int_equal(ret, 0);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_invalid_no_next(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) Invalid rootcheck query syntax: save");
    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid rootcheck query syntax, near 'save'");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_no_ptr(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save ");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) Invalid rootcheck query syntax: save");
    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid rootcheck query syntax, near 'save'");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_date_max_long(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save 9223372036854775807 asdasd");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) Invalid rootcheck date timestamp: 9223372036854775807");
    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid rootcheck query syntax, near 'save'");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_update_cache_error(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save 123456789 Test");

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__merror, formatted_msg, "DB(000) Cannot cache statement");

    expect_string(__wrap__merror, formatted_msg, "DB(000) Error updating rootcheck PM tuple on SQLite database");

    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Error updating rootcheck PM tuple");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_update_success(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save 123456789 Test");

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 123456789);
    will_return_always(__wrap_sqlite3_bind_int, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "Test");
    will_return(__wrap_sqlite3_bind_text, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 10);

    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok 1");
    assert_int_equal(ret, 0);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_update_insert_cache_error(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save 123456789 Test");

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 123456789);
    will_return_always(__wrap_sqlite3_bind_int, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "Test");
    will_return(__wrap_sqlite3_bind_text, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 0);

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__merror, formatted_msg, "DB(000) Cannot cache statement");

    expect_string(__wrap__merror, formatted_msg, "DB(000) Error inserting rootcheck PM tuple on SQLite database for agent");

    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Error updating rootcheck PM tuple");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_update_insert_success(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save 123456789 Test");

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 123456789);
    will_return_always(__wrap_sqlite3_bind_int, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "Test");
    will_return(__wrap_sqlite3_bind_text, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 123456789);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 123456789);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "Test");
    will_return(__wrap_sqlite3_bind_text, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    will_return(__wrap_sqlite3_bind_text, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    will_return(__wrap_sqlite3_bind_text, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_last_insert_rowid, 10);

    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok 2");
    assert_int_equal(ret, 0);
    os_free(query);
}

/* vuln_cves Tests */

void test_vuln_cves_syntax_error(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("agent 000 vuln_cves", query);

    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, (wdb_t*)1); // Returning any value
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: vuln_cves");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid vuln_cves query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) vuln_cves query error near: vuln_cves");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid vuln_cves query syntax, near 'vuln_cves'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cves_invalid_action(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("agent 000 vuln_cves invalid", query);
    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, (wdb_t*)1); // Returning any value
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: vuln_cves invalid");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid vuln_cves action: invalid");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cves_missing_action(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("", query);

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Missing vuln_cves action");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cves_insert_syntax_error(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("insert {\"name\":\"package\",\"version\":}", query);

    // wdb_parse_agents_insert_vuln_cves
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid vuln_cves JSON syntax when inserting vulnerable package.");
    expect_string(__wrap__mdebug2, formatted_msg, "JSON error near: }");

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{\"name\":\"package\",\"version\":}'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cves_insert_constraint_error(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("insert {\"name\":\"package\",\"version\":\"2.2\",\"architecture\":\"x86\"}", query);

    // wdb_parse_agents_insert_vuln_cves
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid vuln_cves JSON data when inserting vulnerable package."
    " Not compliant with constraints defined in the database.");

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid JSON data, missing required fields");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cves_insert_command_error(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("insert {\"name\":\"package\",\"version\":\"2.2\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1500\",\"reference\":\"8549fd9faf9b124635298e9311ccf672c2ad05d1\",\"type\":\"PACKAGE\",\"status\":\"VALID\",\"check_pkg_existance\":true}", query);

    // wdb_parse_agents_insert_vuln_cves
    expect_string(__wrap_wdb_agents_insert_vuln_cves, name, "package");
    expect_string(__wrap_wdb_agents_insert_vuln_cves, version, "2.2");
    expect_string(__wrap_wdb_agents_insert_vuln_cves, architecture, "x86");
    expect_string(__wrap_wdb_agents_insert_vuln_cves, cve, "CVE-2021-1500");
    expect_string(__wrap_wdb_agents_insert_vuln_cves, reference, "8549fd9faf9b124635298e9311ccf672c2ad05d1");
    expect_string(__wrap_wdb_agents_insert_vuln_cves, type, "PACKAGE");
    expect_string(__wrap_wdb_agents_insert_vuln_cves, status, "VALID");
    expect_value(__wrap_wdb_agents_insert_vuln_cves, check_pkg_existance, true);
    will_return(__wrap_wdb_agents_insert_vuln_cves, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error inserting vulnerability in vuln_cves.");

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Error inserting vulnerability in vuln_cves.");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cves_insert_command_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;
    os_strdup("insert {\"name\":\"package\",\"version\":\"2.2\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1500\",\"reference\":\"8549fd9faf9b124635298e9311ccf672c2ad05d1\",\"type\":\"PACKAGE\",\"status\":\"VALID\",\"check_pkg_existance\":true}", query);
    char *result = NULL;
    os_strdup("[{\"test\":\"TEST\"}]", result);

    cJSON *test =  cJSON_CreateObject();

    // wdb_parse_agents_insert_vuln_cves
    expect_string(__wrap_wdb_agents_insert_vuln_cves, name, "package");
    expect_string(__wrap_wdb_agents_insert_vuln_cves, version, "2.2");
    expect_string(__wrap_wdb_agents_insert_vuln_cves, architecture, "x86");
    expect_string(__wrap_wdb_agents_insert_vuln_cves, cve, "CVE-2021-1500");
    expect_string(__wrap_wdb_agents_insert_vuln_cves, reference, "8549fd9faf9b124635298e9311ccf672c2ad05d1");
    expect_string(__wrap_wdb_agents_insert_vuln_cves, type, "PACKAGE");
    expect_string(__wrap_wdb_agents_insert_vuln_cves, status, "VALID");
    expect_value(__wrap_wdb_agents_insert_vuln_cves, check_pkg_existance, true);
    will_return(__wrap_wdb_agents_insert_vuln_cves, test);
    will_return(__wrap_cJSON_PrintUnformatted, result);

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok [{\"test\":\"TEST\"}]");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_vuln_cves_update_status_syntax_error(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("update_status {\"old_status\",\"new_status\"}", query);

    // wdb_parse_agents_update_status_vuln_cves
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid vuln_cves JSON syntax when updating status value.");
    expect_string(__wrap__mdebug2, formatted_msg, "JSON error near: ,\"new_status\"}");

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{\"old_status\",\"new_status\"}'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cves_update_status_constraint_error(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("update_status {\"old_status\":\"new_status\"}", query);

    // wdb_parse_agents_update_status_vuln_cves
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid vuln_cves JSON data when updating status value."
    " Not compliant with constraints defined in the database.");

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid JSON data, missing required fields");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cves_update_status_command_error(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}", query);

    // wdb_parse_agents_update_status_vuln_cves
    will_return(__wrap_wdb_agents_update_status_vuln_cves, OS_INVALID);
    expect_string(__wrap_wdb_agents_update_status_vuln_cves, old_status, "valid");
    expect_string(__wrap_wdb_agents_update_status_vuln_cves, new_status, "obsolete");
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot execute vuln_cves update_status command; SQL err: ERROR MESSAGE");

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot execute vuln_cves update_status command; SQL err: ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cves_update_status_command_success(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("update_status {\"old_status\":\"valid\",\"new_status\":\"obsolete\"}", query);

    // wdb_parse_agents_update_status_vuln_cves
    will_return(__wrap_wdb_agents_update_status_vuln_cves, OS_SUCCESS);
    expect_string(__wrap_wdb_agents_update_status_vuln_cves, old_status, "valid");
    expect_string(__wrap_wdb_agents_update_status_vuln_cves, new_status, "obsolete");

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_vuln_cves_remove_syntax_error(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("remove {\"status\"}", query);

    // wdb_parse_agents_update_status_vuln_cves
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid vuln_cves JSON syntax when removing vulnerabilities.");
    expect_string(__wrap__mdebug2, formatted_msg, "JSON error near: }");

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{\"status\"}'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cves_remove_json_data_error(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("remove {}", query);

    // wdb_parse_agents_update_status_vuln_cves
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid vuln_cves JSON data to remove vulnerabilities.");

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid JSON data");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cves_remove_by_status_success(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("remove {\"status\":\"OBSOLETE\"}", query);

    // wdb_agents_remove_by_status_vuln_cves
    expect_string(__wrap_wdb_agents_remove_by_status_vuln_cves, status, "OBSOLETE");
    will_return(__wrap_wdb_agents_remove_by_status_vuln_cves, "{\"cve\":\"cve-xxxx-yyyy\"}");
    will_return(__wrap_wdb_agents_remove_by_status_vuln_cves, WDBC_OK);

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok {\"cve\":\"cve-xxxx-yyyy\"}");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_vuln_cves_remove_entry_error(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("remove {\"cve\":\"cve-xxxx-yyyy\",\"reference\":\"ref-cve-xxxx-yyyy\"}", query);

    // wdb_agents_remove_vuln_cves
    expect_string(__wrap_wdb_agents_remove_vuln_cves, cve, "cve-xxxx-yyyy");
    expect_string(__wrap_wdb_agents_remove_vuln_cves, reference, "ref-cve-xxxx-yyyy");
    will_return(__wrap_wdb_agents_remove_vuln_cves, OS_INVALID);

    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot execute vuln_cves remove command; SQL err: ERROR MESSAGE");

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot execute vuln_cves remove command; SQL err: ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cves_remove_entry_success(void **state){
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("remove {\"cve\":\"cve-xxxx-yyyy\",\"reference\":\"ref-cve-xxxx-yyyy\"}", query);

    // wdb_agents_remove_vuln_cves
    expect_string(__wrap_wdb_agents_remove_vuln_cves, cve, "cve-xxxx-yyyy");
    expect_string(__wrap_wdb_agents_remove_vuln_cves, reference, "ref-cve-xxxx-yyyy");
    will_return(__wrap_wdb_agents_remove_vuln_cves, OS_SUCCESS);

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_vuln_cves_clear_command_error(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("clear", query);

    // wdb_parse_agents_clear_vuln_cves
    will_return(__wrap_wdb_agents_clear_vuln_cves, OS_INVALID);
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot execute vuln_cves clear command; SQL err: ERROR MESSAGE");

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot execute vuln_cves clear command; SQL err: ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cves_clear_command_success(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("clear", query);

    // wdb_parse_agents_clear_vuln_cves
    will_return(__wrap_wdb_agents_clear_vuln_cves, OS_SUCCESS);

    ret = wdb_parse_vuln_cves(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

int main()
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test_setup_teardown(test_wdb_parse_syscheck_no_space, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_update_info_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_update_info_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_clean_old_entries_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_clean_old_entries_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_update_noarg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_update_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_update_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_fim_check_control_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_fim_check_control_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_load_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_load_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_fim_delete_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_fim_delete_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_noarg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_invalid_type, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_file_type_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_file_nospace, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_file_type_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_registry_type_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_registry_type_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save2_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save2_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_check_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_check_no_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_check_checksum_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_check_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_clear_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_clear_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_command, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_badquery, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_delete_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_delete_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_invalid_no_next, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_no_ptr, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_date_max_long, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_update_cache_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_update_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_update_insert_cache_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_update_insert_success, test_setup, test_teardown),
        /* Tests vuln_cves */
        cmocka_unit_test_setup_teardown(test_vuln_cves_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cves_invalid_action, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cves_missing_action, test_setup, test_teardown),
        // wdb_parse_agents_insert_vuln_cves
        cmocka_unit_test_setup_teardown(test_vuln_cves_insert_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cves_insert_constraint_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cves_insert_command_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cves_insert_command_success, test_setup, test_teardown),
        // wdb_parse_agents_vuln_cves_update_status
        cmocka_unit_test_setup_teardown(test_vuln_cves_update_status_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cves_update_status_constraint_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cves_update_status_command_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cves_update_status_command_success, test_setup, test_teardown),
        // wdb_parse_agents_remove_vuln_cves
        cmocka_unit_test_setup_teardown(test_vuln_cves_remove_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cves_remove_json_data_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cves_remove_by_status_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cves_remove_entry_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cves_remove_entry_success, test_setup, test_teardown),
        // wdb_parse_agents_clear_vuln_cves
        cmocka_unit_test_setup_teardown(test_vuln_cves_clear_command_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cves_clear_command_success, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);

}
