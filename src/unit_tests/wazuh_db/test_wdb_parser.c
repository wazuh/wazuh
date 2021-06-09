
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
    wdb_t *wdb_global;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data;

    init_data = malloc(sizeof(test_struct_t));
    init_data->wdb = malloc(sizeof(wdb_t));
    init_data->wdb_global = malloc(sizeof(wdb_t));
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
    free(data->wdb_global);
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

/* vuln_cve Tests */

void test_vuln_cve_syntax_error(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("agent 000 vuln_cve", query);

    will_return(__wrap_wdb_open_global, data->wdb_global);

    expect_value(__wrap_wdb_global_agent_exists, wdb, data->wdb_global);
    expect_value(__wrap_wdb_global_agent_exists, agent_id, 0);
    will_return(__wrap_wdb_global_agent_exists, 1);

    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, (wdb_t*)1); // Returning any value
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: vuln_cve");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid vuln_cve query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) vuln_cve query error near: vuln_cve");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid vuln_cve query syntax, near 'vuln_cve'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cve_invalid_action(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("agent 000 vuln_cve invalid", query);
    will_return(__wrap_wdb_open_global, data->wdb_global);

    expect_value(__wrap_wdb_global_agent_exists, wdb, data->wdb_global);
    expect_value(__wrap_wdb_global_agent_exists, agent_id, 0);
    will_return(__wrap_wdb_global_agent_exists, 1);

    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, (wdb_t*)1); // Returning any value
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: vuln_cve invalid");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid vuln_cve action: invalid");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cve_missing_action(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("", query);

    ret = wdb_parse_vuln_cve(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Missing vuln_cve action");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cve_insert_syntax_error(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("insert {\"name\":\"package\",\"version\":}", query);

    // wdb_parse_agents_insert_vuln_cve
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid vuln_cve JSON syntax when inserting vulnerable package.");
    expect_string(__wrap__mdebug2, formatted_msg, "JSON error near: }");

    ret = wdb_parse_vuln_cve(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{\"name\":\"package\",\"version\":}'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cve_insert_constraint_error(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("insert {\"name\":\"package\",\"version\":\"2.2\",\"architecture\":\"x86\"}", query);

    // wdb_parse_agents_insert_vuln_cve
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid vuln_cve JSON data when inserting vulnerable package."
    " Not compliant with constraints defined in the database.");

    ret = wdb_parse_vuln_cve(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid JSON data, missing required fields");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cve_insert_command_error(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("insert {\"name\":\"package\",\"version\":\"2.2\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1500\"}", query);

    // wdb_parse_agents_insert_vuln_cve
    will_return(__wrap_wdb_agents_insert_vuln_cve, OS_INVALID);
    expect_string(__wrap_wdb_agents_insert_vuln_cve, name, "package");
    expect_string(__wrap_wdb_agents_insert_vuln_cve, version, "2.2");
    expect_string(__wrap_wdb_agents_insert_vuln_cve, architecture, "x86");
    expect_string(__wrap_wdb_agents_insert_vuln_cve, cve, "CVE-2021-1500");
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot execute vuln_cve insert command; SQL err: ERROR MESSAGE");

    ret = wdb_parse_vuln_cve(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot execute vuln_cve insert command; SQL err: ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cve_insert_command_success(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("insert {\"name\":\"package\",\"version\":\"2.2\",\"architecture\":\"x86\",\"cve\":\"CVE-2021-1500\"}", query);

    // wdb_parse_agents_insert_vuln_cve
    will_return(__wrap_wdb_agents_insert_vuln_cve, OS_SUCCESS);
    expect_string(__wrap_wdb_agents_insert_vuln_cve, name, "package");
    expect_string(__wrap_wdb_agents_insert_vuln_cve, version, "2.2");
    expect_string(__wrap_wdb_agents_insert_vuln_cve, architecture, "x86");
    expect_string(__wrap_wdb_agents_insert_vuln_cve, cve, "CVE-2021-1500");

    ret = wdb_parse_vuln_cve(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_vuln_cve_clear_command_error(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("clear", query);

    // wdb_parse_agents_clear_vuln_cve
    will_return(__wrap_wdb_agents_clear_vuln_cve, OS_INVALID);
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot execute vuln_cve clear command; SQL err: ERROR MESSAGE");

    ret = wdb_parse_vuln_cve(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot execute vuln_cve clear command; SQL err: ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_vuln_cve_clear_command_success(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("clear", query);

    // wdb_parse_agents_clear_vuln_cve
    will_return(__wrap_wdb_agents_clear_vuln_cve, OS_SUCCESS);

    ret = wdb_parse_vuln_cve(data->wdb, query, data->output);

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
        /* vuln_cve Tests */
        cmocka_unit_test_setup_teardown(test_vuln_cve_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cve_invalid_action, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cve_missing_action, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cve_insert_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cve_insert_constraint_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cve_insert_command_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cve_insert_command_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cve_clear_command_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_vuln_cve_clear_command_success, test_setup, test_teardown)

    };

    return cmocka_run_group_tests(tests, NULL, NULL);

}
