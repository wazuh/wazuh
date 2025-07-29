
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_syscollector_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_agents_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_delta_event_wrappers.h"


#include "os_err.h"
#include "../wazuh_db/wdb.h"

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
    init_data->output = calloc(256, sizeof(char));
    init_data->wdb->peer = 1234;
    init_data->wdb->enabled = true;

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

void test_wdb_parse_sca_no_space(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid Security Configuration Assessment query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "Security Configuration Assessment query: badquery_nospace");

    ret = wdb_parse_sca(data->wdb, "badquery_nospace", data->output);

    assert_string_equal(data->output, "err Invalid Security Configuration Assessment query syntax, near \'badquery_nospace\'");
    assert_int_equal(ret, -1);
}

void test_wdb_parse_sca_query_not_found(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char query [7] = "query ";

    will_return(__wrap_wdb_sca_find, 0);

    ret = wdb_parse_sca(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok not found");
    assert_int_equal(ret, 0);
}

void test_wdb_parse_sca_query_found(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char query [7] = "query ";

    will_return(__wrap_wdb_sca_find, 1);

    ret = wdb_parse_sca(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok found ");
    assert_int_equal(ret, 1);
}

void test_wdb_parse_sca_cannot_query(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char query [7] = "query ";

    will_return(__wrap_wdb_sca_find, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot query Security Configuration Assessment.");

    ret = wdb_parse_sca(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot query Security Configuration Assessment");
    assert_int_equal(ret, -1);
}

void test_wdb_parse_sca_invalid_insert(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char query [8] = "insert ";

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid Security Configuration Assessment query syntax. JSON object not found or invalid");

    ret = wdb_parse_sca(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid Security Configuration Assessment query syntax, near ''");
    assert_int_equal(ret, -1);
}

void test_wdb_parse_sca_invalid_insert_not_number_id(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char query [25] = "insert {\"id\":\"wazuh\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "Malformed JSON: field 'id' must be a number");

    ret = wdb_parse_sca(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid Security Configuration Assessment query syntax, near '{\"id\":\"wazuh\"}'");
    assert_int_equal(ret, -1);
}

void test_wdb_parse_sca_invalid_insert_negative_number_id(void **state) {
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char query [25] = "insert {\"id\":-1}";

    expect_string(__wrap__mdebug1, formatted_msg, "Malformed JSON: field 'id' cannot be negative");

    ret = wdb_parse_sca(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid Security Configuration Assessment query syntax, near '{\"id\":-1}'");
    assert_int_equal(ret, -1);
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

/* Tests osinfo */

void test_osinfo_syntax_error(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("agent 000 osinfo", query);

    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: osinfo");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) query error near: osinfo");
    expect_string(__wrap_w_is_file, file, "queue/db/000.db");
    will_return(__wrap_w_is_file, 1);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'osinfo'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_invalid_action(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("agent 000 osinfo invalid", query);
    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: osinfo invalid");
    expect_string(__wrap_w_is_file, file, "queue/db/000.db");
    will_return(__wrap_w_is_file, 1);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid osinfo action: invalid");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_missing_action(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("", query);

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Missing osinfo action");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_get_error(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("get", query);

    // wdb_agents_get_sys_osinfo
    will_return(__wrap_wdb_agents_get_sys_osinfo, NULL);
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot get sys_osinfo database table information; SQL err: ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_get_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;
    char *result = NULL;

    os_strdup("get", query);
    os_strdup("[]", result);
    cJSON *test =  cJSON_CreateObject();

    // wdb_agents_get_sys_osinfo
    will_return(__wrap_wdb_agents_get_sys_osinfo, test);
    will_return(__wrap_cJSON_PrintUnformatted, result);

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok []");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_osinfo_set_error(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_scan_id(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set ", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_scan_time(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_hostname(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_architecture(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_os_name(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|hostname|NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_os_version(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|hostname|architecture|NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_os_codename(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|hostname|architecture|os_name|NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_os_major(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|hostname|architecture|os_name|os_version|NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_os_minor(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|hostname|architecture|os_name|os_version|os_codename|NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_os_build(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|hostname|architecture|os_name|os_version|os_codename|os_major|NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_os_platform(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|hostname|architecture|os_name|os_version|os_codename|os_major|os_minor|NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_sysname(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|hostname|architecture|os_name|os_version|os_codename|os_major|os_minor|os_build|NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_release(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|hostname|architecture|os_name|os_version|os_codename|os_major|os_minor|os_build|os_platform|NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_version(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|hostname|architecture|os_name|os_version|os_codename|os_major|os_minor|os_build|os_platform|sysname|NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_no_os_release(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|hostname|architecture|os_name|os_version|os_codename|os_major|os_minor|os_build|os_platform|sysname|NULL|NULL|", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid OS info query syntax.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid OS info query syntax");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_error_saving(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|hostname|architecture|os_name|os_version|os_codename|os_major|os_minor|os_build|os_platform|sysname|release|NULL|NULL|NULL|NULL", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap_wdb_osinfo_save, scan_id, "scan_id");
    expect_string(__wrap_wdb_osinfo_save, scan_time, "scan_time");
    expect_string(__wrap_wdb_osinfo_save, hostname, "hostname");
    expect_string(__wrap_wdb_osinfo_save, architecture, "architecture");
    expect_string(__wrap_wdb_osinfo_save, os_name, "os_name");
    expect_string(__wrap_wdb_osinfo_save, os_version, "os_version");
    expect_string(__wrap_wdb_osinfo_save, os_codename, "os_codename");
    expect_string(__wrap_wdb_osinfo_save, os_major, "os_major");
    expect_string(__wrap_wdb_osinfo_save, os_minor, "os_minor");
    expect_string(__wrap_wdb_osinfo_save, os_build, "os_build");
    expect_string(__wrap_wdb_osinfo_save, os_platform, "os_platform");
    expect_string(__wrap_wdb_osinfo_save, sysname, "sysname");
    expect_string(__wrap_wdb_osinfo_save, release, "release");
    expect_string(__wrap_wdb_osinfo_save, checksum, "legacy");
    expect_value(__wrap_wdb_osinfo_save, replace, FALSE);
    will_return(__wrap_wdb_osinfo_save, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save OS information.");

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot save OS information.");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_osinfo_set_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("set scan_id|scan_time|hostname|architecture|os_name|os_version|os_codename|os_major|os_minor|os_build|os_platform|sysname|release|version|os_release|os_patch|os_display_version", query);

    // wdb_parse_agents_set_sys_osinfo
    expect_string(__wrap_wdb_osinfo_save, scan_id, "scan_id");
    expect_string(__wrap_wdb_osinfo_save, scan_time, "scan_time");
    expect_string(__wrap_wdb_osinfo_save, hostname, "hostname");
    expect_string(__wrap_wdb_osinfo_save, architecture, "architecture");
    expect_string(__wrap_wdb_osinfo_save, os_name, "os_name");
    expect_string(__wrap_wdb_osinfo_save, os_version, "os_version");
    expect_string(__wrap_wdb_osinfo_save, os_codename, "os_codename");
    expect_string(__wrap_wdb_osinfo_save, os_major, "os_major");
    expect_string(__wrap_wdb_osinfo_save, os_minor, "os_minor");
    expect_string(__wrap_wdb_osinfo_save, os_patch, "os_patch");
    expect_string(__wrap_wdb_osinfo_save, os_build, "os_build");
    expect_string(__wrap_wdb_osinfo_save, os_platform, "os_platform");
    expect_string(__wrap_wdb_osinfo_save, sysname, "sysname");
    expect_string(__wrap_wdb_osinfo_save, release, "release");
    expect_string(__wrap_wdb_osinfo_save, version, "version");
    expect_string(__wrap_wdb_osinfo_save, os_release, "os_release");
    expect_string(__wrap_wdb_osinfo_save, os_display_version, "os_display_version");
    expect_string(__wrap_wdb_osinfo_save, checksum, "legacy");
    expect_value(__wrap_wdb_osinfo_save, replace, FALSE);
    will_return(__wrap_wdb_osinfo_save, OS_SUCCESS);

    ret = wdb_parse_osinfo(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

/* wdb_parse_packages */

/* get */

void test_packages_get_success(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    char* result = NULL;
    os_strdup("get", query);
    os_strdup("[{\"status\":\"SUCCESS\"}]", result);
    cJSON *test =  cJSON_CreateObject();

    will_return(__wrap_wdb_agents_get_packages, test);
    will_return(__wrap_wdb_agents_get_packages, OS_SUCCESS);
    will_return(__wrap_cJSON_PrintUnformatted, result);

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok [{\"status\":\"SUCCESS\"}]");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_packages_get_null_response(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("get", query);

    will_return(__wrap_wdb_agents_get_packages, NULL);
    will_return(__wrap_wdb_agents_get_packages, OS_SUCCESS);
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting packages from sys_programs");

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Error getting packages from sys_programs");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_packages_get_err_response(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    char* result = NULL;
    os_strdup("get", query);
    os_strdup("[{\"status\":\"ERROR\"}]", result);
    cJSON *test =  cJSON_CreateObject();

    will_return(__wrap_wdb_agents_get_packages, test);
    will_return(__wrap_wdb_agents_get_packages, OS_INVALID);
    will_return(__wrap_cJSON_PrintUnformatted, result);

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "err [{\"status\":\"ERROR\"}]");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_packages_get_sock_err_response(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    char* result = NULL;
    os_strdup("get", query);
    os_strdup("[{\"status\":\"ERROR\"}]", result);
    cJSON *test =  cJSON_CreateObject();

    will_return(__wrap_wdb_agents_get_packages, test);
    will_return(__wrap_wdb_agents_get_packages, OS_SOCKTERR);
    will_return(__wrap_cJSON_PrintUnformatted, result);

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "");
    assert_int_equal(ret, OS_SOCKTERR);

    os_free(query);
}

/* save */

void test_packages_save_success(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("save 0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15", query);

    expect_string(__wrap_wdb_package_save, scan_id, "0");
    expect_string(__wrap_wdb_package_save, scan_time, "1");
    expect_string(__wrap_wdb_package_save, format, "2");
    expect_string(__wrap_wdb_package_save, name, "3");
    expect_string(__wrap_wdb_package_save, priority, "4");
    expect_string(__wrap_wdb_package_save, section, "5");
    expect_value(__wrap_wdb_package_save, size, 6);
    expect_string(__wrap_wdb_package_save, vendor, "7");
    expect_string(__wrap_wdb_package_save, install_time, "8");
    expect_string(__wrap_wdb_package_save, version, "9");
    expect_string(__wrap_wdb_package_save, architecture, "10");
    expect_string(__wrap_wdb_package_save, multiarch, "11");
    expect_string(__wrap_wdb_package_save, source, "12");
    expect_string(__wrap_wdb_package_save, description, "13");
    expect_string(__wrap_wdb_package_save, location, "14");
    expect_string(__wrap_wdb_package_save, checksum, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE);
    expect_string(__wrap_wdb_package_save, item_id, "15");
    expect_value(__wrap_wdb_package_save, replace, FALSE);
    will_return(__wrap_wdb_package_save, OS_SUCCESS);

    will_return(__wrap_time, 0);
    expect_value(__wrap_wdbi_update_attempt, component, WDB_SYSCOLLECTOR_PACKAGES);
    expect_value(__wrap_wdbi_update_attempt, timestamp, 0);
    expect_value(__wrap_wdbi_update_attempt, legacy, TRUE);
    expect_string(__wrap_wdbi_update_attempt, last_agent_checksum, "");
    expect_string(__wrap_wdbi_update_attempt, manager_checksum, "");

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_packages_save_success_null_items(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("save 0|1|2|3|4|5|NULL|7|8|9|10|11|12|13|NULL|NULL", query);

    expect_string(__wrap_wdb_package_save, scan_id, "0");
    expect_string(__wrap_wdb_package_save, scan_time, "1");
    expect_string(__wrap_wdb_package_save, format, "2");
    expect_string(__wrap_wdb_package_save, name, "3");
    expect_string(__wrap_wdb_package_save, priority, "4");
    expect_string(__wrap_wdb_package_save, section, "5");
    expect_value(__wrap_wdb_package_save, size, -1);
    expect_string(__wrap_wdb_package_save, vendor, "7");
    expect_string(__wrap_wdb_package_save, install_time, "8");
    expect_string(__wrap_wdb_package_save, version, "9");
    expect_string(__wrap_wdb_package_save, architecture, "10");
    expect_string(__wrap_wdb_package_save, multiarch, "11");
    expect_string(__wrap_wdb_package_save, source, "12");
    expect_string(__wrap_wdb_package_save, description, "13");
    expect_value (__wrap_wdb_package_save, location, NULL);
    expect_string(__wrap_wdb_package_save, checksum, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE);
    expect_value(__wrap_wdb_package_save, item_id, NULL);
    expect_value(__wrap_wdb_package_save, replace, FALSE);
    will_return(__wrap_wdb_package_save, OS_SUCCESS);

    will_return(__wrap_time, 0);
    expect_value(__wrap_wdbi_update_attempt, component, WDB_SYSCOLLECTOR_PACKAGES);
    expect_value(__wrap_wdbi_update_attempt, timestamp, 0);
    expect_value(__wrap_wdbi_update_attempt, legacy, TRUE);
    expect_string(__wrap_wdbi_update_attempt, last_agent_checksum, "");
    expect_string(__wrap_wdbi_update_attempt, manager_checksum, "");

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_packages_save_success_empty_items(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("save |1|2|3||5|6|7||9|10|11||13|14|", query);

    expect_string(__wrap_wdb_package_save, scan_id, "");
    expect_string(__wrap_wdb_package_save, scan_time, "1");
    expect_string(__wrap_wdb_package_save, format, "2");
    expect_string(__wrap_wdb_package_save, name, "3");
    expect_string(__wrap_wdb_package_save, priority, "");
    expect_string(__wrap_wdb_package_save, section, "5");
    expect_value(__wrap_wdb_package_save, size, 6);
    expect_string(__wrap_wdb_package_save, vendor, "7");
    expect_string(__wrap_wdb_package_save, install_time, "");
    expect_string(__wrap_wdb_package_save, version, "9");
    expect_string(__wrap_wdb_package_save, architecture, "10");
    expect_string(__wrap_wdb_package_save, multiarch, "11");
    expect_string(__wrap_wdb_package_save, source, "");
    expect_string(__wrap_wdb_package_save, description, "13");
    expect_string(__wrap_wdb_package_save, location, "14");
    expect_string(__wrap_wdb_package_save, checksum, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE);
    expect_string(__wrap_wdb_package_save, item_id, "");
    expect_value(__wrap_wdb_package_save, replace, FALSE);
    will_return(__wrap_wdb_package_save, OS_SUCCESS);

    will_return(__wrap_time, 0);
    expect_value(__wrap_wdbi_update_attempt, component, WDB_SYSCOLLECTOR_PACKAGES);
    expect_value(__wrap_wdbi_update_attempt, timestamp, 0);
    expect_value(__wrap_wdbi_update_attempt, legacy, TRUE);
    expect_string(__wrap_wdbi_update_attempt, last_agent_checksum, "");
    expect_string(__wrap_wdbi_update_attempt, manager_checksum, "");

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_packages_save_missing_items(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("save 0|1|2|3|4|5|6|7|8|9|10|11|12|13|14", query);

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid package info query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg,  "Package info query: 14");

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid package info query syntax, near '14'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_packages_save_err(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("save 0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15", query);

    expect_string(__wrap_wdb_package_save, scan_id, "0");
    expect_string(__wrap_wdb_package_save, scan_time, "1");
    expect_string(__wrap_wdb_package_save, format, "2");
    expect_string(__wrap_wdb_package_save, name, "3");
    expect_string(__wrap_wdb_package_save, priority, "4");
    expect_string(__wrap_wdb_package_save, section, "5");
    expect_value(__wrap_wdb_package_save, size, 6);
    expect_string(__wrap_wdb_package_save, vendor, "7");
    expect_string(__wrap_wdb_package_save, install_time, "8");
    expect_string(__wrap_wdb_package_save, version, "9");
    expect_string(__wrap_wdb_package_save, architecture, "10");
    expect_string(__wrap_wdb_package_save, multiarch, "11");
    expect_string(__wrap_wdb_package_save, source, "12");
    expect_string(__wrap_wdb_package_save, description, "13");
    expect_string(__wrap_wdb_package_save, location, "14");
    expect_string(__wrap_wdb_package_save, checksum, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE);
    expect_string(__wrap_wdb_package_save, item_id, "15");
    expect_value(__wrap_wdb_package_save, replace, FALSE);
    will_return(__wrap_wdb_package_save, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save package information.");

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot save package information.");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

/* del */

void test_packages_del_success(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("del 0", query);

    expect_string(__wrap_wdb_package_update, scan_id, "0");
    will_return(__wrap_wdb_package_update, OS_SUCCESS);

    expect_string(__wrap_wdb_package_delete, scan_id, "0");
    will_return(__wrap_wdb_package_delete, OS_SUCCESS);

    will_return(__wrap_time, 0);
    expect_value(__wrap_wdbi_update_completion, component, WDB_SYSCOLLECTOR_PACKAGES);
    expect_value(__wrap_wdbi_update_completion, timestamp, 0);
    expect_string(__wrap_wdbi_update_completion, last_agent_checksum, "");
    expect_string(__wrap_wdbi_update_completion, manager_checksum, "");

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_packages_del_success_null_items(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("del NULL", query);

    expect_value(__wrap_wdb_package_update, scan_id, NULL);
    will_return(__wrap_wdb_package_update, OS_SUCCESS);

    expect_value(__wrap_wdb_package_delete, scan_id, NULL);
    will_return(__wrap_wdb_package_delete, OS_SUCCESS);

    will_return(__wrap_time, 0);
    expect_value(__wrap_wdbi_update_completion, component, WDB_SYSCOLLECTOR_PACKAGES);
    expect_value(__wrap_wdbi_update_completion, timestamp, 0);
    expect_string(__wrap_wdbi_update_completion, last_agent_checksum, "");
    expect_string(__wrap_wdbi_update_completion, manager_checksum, "");

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_packages_del_update_err(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("del 0", query);

    expect_string(__wrap_wdb_package_update, scan_id, "0");
    will_return(__wrap_wdb_package_update, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot update scanned packages.");

    expect_string(__wrap_wdb_package_delete, scan_id, "0");
    will_return(__wrap_wdb_package_delete, OS_SUCCESS);

    will_return(__wrap_time, 0);
    expect_value(__wrap_wdbi_update_completion, component, WDB_SYSCOLLECTOR_PACKAGES);
    expect_value(__wrap_wdbi_update_completion, timestamp, 0);
    expect_string(__wrap_wdbi_update_completion, last_agent_checksum, "");
    expect_string(__wrap_wdbi_update_completion, manager_checksum, "");

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_packages_del_delete_err(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("del 0", query);

    expect_string(__wrap_wdb_package_update, scan_id, "0");
    will_return(__wrap_wdb_package_update, OS_SUCCESS);

    expect_string(__wrap_wdb_package_delete, scan_id, "0");
    will_return(__wrap_wdb_package_delete, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot delete old package information.");

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot delete old package information.");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

/* invalid action */

void test_packages_invalid_action(void **state) {

    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("invalid", query);

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid package info query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB query error near: invalid");

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid package info query syntax, near 'invalid'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_packages_no_action(void **state) {

    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("", query);

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid package info query syntax. Missing action");
    expect_string(__wrap__mdebug2, formatted_msg, "DB query error. Missing action");

    ret = wdb_parse_packages(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid package info query syntax. Missing action");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}


/* wdb_parse_hotfixes */

/* get */

void test_hotfixes_get_success(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    char* result = NULL;
    os_strdup("get", query);
    os_strdup("[{\"status\":\"SUCCESS\"}]", result);
    cJSON *test =  cJSON_CreateObject();

    will_return(__wrap_wdb_agents_get_hotfixes, test);
    will_return(__wrap_wdb_agents_get_hotfixes, OS_SUCCESS);
    will_return(__wrap_cJSON_PrintUnformatted, result);

    ret = wdb_parse_hotfixes(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok [{\"status\":\"SUCCESS\"}]");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_hotfixes_get_null_response(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("get", query);

    will_return(__wrap_wdb_agents_get_hotfixes, NULL);
    will_return(__wrap_wdb_agents_get_hotfixes, OS_SUCCESS);
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting hotfixes from sys_hotfixes");

    ret = wdb_parse_hotfixes(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Error getting hotfixes from sys_hotfixes");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_hotfixes_get_err_response(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    char* result = NULL;
    os_strdup("get", query);
    os_strdup("[{\"status\":\"ERROR\"}]", result);
    cJSON *test =  cJSON_CreateObject();

    will_return(__wrap_wdb_agents_get_hotfixes, test);
    will_return(__wrap_wdb_agents_get_hotfixes, OS_INVALID);
    will_return(__wrap_cJSON_PrintUnformatted, result);

    ret = wdb_parse_hotfixes(data->wdb, query, data->output);

    assert_string_equal(data->output, "err [{\"status\":\"ERROR\"}]");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_hotfixes_get_sock_err_response(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    char* result = NULL;
    os_strdup("get", query);
    os_strdup("[{\"status\":\"ERROR\"}]", result);
    cJSON *test =  cJSON_CreateObject();

    will_return(__wrap_wdb_agents_get_hotfixes, test);
    will_return(__wrap_wdb_agents_get_hotfixes, OS_SOCKTERR);
    will_return(__wrap_cJSON_PrintUnformatted, result);

    ret = wdb_parse_hotfixes(data->wdb, query, data->output);

    assert_string_equal(data->output, "");
    assert_int_equal(ret, OS_SOCKTERR);

    os_free(query);
}

/* save */

void test_hotfixes_save_success(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("save 0|1|2", query);

    expect_string(__wrap_wdb_hotfix_save, scan_id, "0");
    expect_string(__wrap_wdb_hotfix_save, scan_time, "1");
    expect_string(__wrap_wdb_hotfix_save, hotfix, "2");
    expect_string(__wrap_wdb_hotfix_save, checksum, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE);
    expect_value(__wrap_wdb_hotfix_save, replace, FALSE);
    will_return(__wrap_wdb_hotfix_save, OS_SUCCESS);

    will_return(__wrap_time, 0);
    expect_value(__wrap_wdbi_update_attempt, component, WDB_SYSCOLLECTOR_HOTFIXES);
    expect_value(__wrap_wdbi_update_attempt, timestamp, 0);
    expect_value(__wrap_wdbi_update_attempt, legacy, TRUE);
    expect_string(__wrap_wdbi_update_attempt, last_agent_checksum, "");
    expect_string(__wrap_wdbi_update_attempt, manager_checksum, "");

    ret = wdb_parse_hotfixes(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_hotfixes_save_success_null_items(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("save 0|NULL|2", query);

    expect_string(__wrap_wdb_hotfix_save, scan_id, "0");
    expect_value(__wrap_wdb_hotfix_save, scan_time, NULL);
    expect_string(__wrap_wdb_hotfix_save, hotfix, "2");
    expect_string(__wrap_wdb_hotfix_save, checksum, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE);
    expect_value(__wrap_wdb_hotfix_save, replace, FALSE);
    will_return(__wrap_wdb_hotfix_save, OS_SUCCESS);

    will_return(__wrap_time, 0);
    expect_value(__wrap_wdbi_update_attempt, component, WDB_SYSCOLLECTOR_HOTFIXES);
    expect_value(__wrap_wdbi_update_attempt, timestamp, 0);
    expect_value(__wrap_wdbi_update_attempt, legacy, TRUE);
    expect_string(__wrap_wdbi_update_attempt, last_agent_checksum, "");
    expect_string(__wrap_wdbi_update_attempt, manager_checksum, "");

    ret = wdb_parse_hotfixes(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_hotfixes_save_missing_items(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("save 0|1", query);

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid hotfix info query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg,  "Hotfix info query: 1");

    ret = wdb_parse_hotfixes(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid hotfix info query syntax, near '1'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_hotfixes_save_err(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("save 0|1|2", query);

    expect_string(__wrap_wdb_hotfix_save, scan_id, "0");
    expect_string(__wrap_wdb_hotfix_save, scan_time, "1");
    expect_string(__wrap_wdb_hotfix_save, hotfix, "2");
    expect_string(__wrap_wdb_hotfix_save, checksum, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE);
    expect_value(__wrap_wdb_hotfix_save, replace, FALSE);
    will_return(__wrap_wdb_hotfix_save, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save hotfix information.");

    ret = wdb_parse_hotfixes(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot save hotfix information.");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

/* del */

void test_hotfixes_del_success(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("del 0", query);

    expect_string(__wrap_wdb_hotfix_delete, scan_id, "0");
    will_return(__wrap_wdb_hotfix_delete, OS_SUCCESS);

    will_return(__wrap_time, 0);
    expect_value(__wrap_wdbi_update_completion, component, WDB_SYSCOLLECTOR_HOTFIXES);
    expect_value(__wrap_wdbi_update_completion, timestamp, 0);
    expect_string(__wrap_wdbi_update_completion, last_agent_checksum, "");
    expect_string(__wrap_wdbi_update_completion, manager_checksum, "");

    ret = wdb_parse_hotfixes(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_hotfixes_del_success_null_items(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("del NULL", query);

    expect_value(__wrap_wdb_hotfix_delete, scan_id, NULL);
    will_return(__wrap_wdb_hotfix_delete, OS_SUCCESS);

    will_return(__wrap_time, 0);
    expect_value(__wrap_wdbi_update_completion, component, WDB_SYSCOLLECTOR_HOTFIXES);
    expect_value(__wrap_wdbi_update_completion, timestamp, 0);
    expect_string(__wrap_wdbi_update_completion, last_agent_checksum, "");
    expect_string(__wrap_wdbi_update_completion, manager_checksum, "");

    ret = wdb_parse_hotfixes(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_hotfixes_del_delete_err(void **state) {
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("del 0", query);

    expect_string(__wrap_wdb_hotfix_delete, scan_id, "0");
    will_return(__wrap_wdb_hotfix_delete, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot delete old hotfix information.");

    ret = wdb_parse_hotfixes(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot delete old hotfix information.");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

/* invalid action */

void test_hotfixes_invalid_action(void **state) {

    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("invalid", query);

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid hotfix info query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB query error near: invalid");

    ret = wdb_parse_hotfixes(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid hotfix info query syntax, near 'invalid'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_hotfixes_no_action(void **state) {

    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    char* query = NULL;
    os_strdup("", query);

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid hotfix info query syntax. Missing action");
    expect_string(__wrap__mdebug2, formatted_msg, "DB query error. Missing action");

    ret = wdb_parse_hotfixes(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid hotfix info query syntax. Missing action");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

/* wdb_parse_dbsync */

void test_wdb_parse_dbsync_no_table(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;

    char * query = NULL;
    os_strdup("", query);

    expect_string(__wrap__mdebug2, formatted_msg, "DBSYNC query: ");

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid dbsync query syntax, near ''");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_no_operation(void ** state) {

    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("osinfo ", query);

    expect_string(__wrap__mdebug2, formatted_msg, "DBSYNC query: osinfo");

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid dbsync query syntax, near 'osinfo'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_no_delta_data(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("osinfo INSERTED ", query);

    expect_string(__wrap__mdebug2, formatted_msg, "DBSYNC query: osinfo");
    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid dbsync query syntax, near 'osinfo'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_invalid_table(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("not_existant_table INSERTED data", query);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_delta_data_not_json(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("osinfo INSERTED {\"unclosed\":\"json", query);

    expect_string(__wrap__mdebug1, formatted_msg, DB_DELTA_PARSING_ERR);
    expect_string(__wrap__mdebug2, formatted_msg, "JSON error near: json");

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_invalid_operation(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("osinfo NOOP {}", query);

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid operation type: NOOP");

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_insert_ok(void ** state) {

    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("osinfo INSERTED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_upsert_dbsync);
    will_return(__wrap_wdb_upsert_dbsync, true);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_wdb_parse_dbsync_insert_err(void ** state) {

    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("osinfo INSERTED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_upsert_dbsync);
    will_return(__wrap_wdb_upsert_dbsync, false);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_modified_ok(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("osinfo MODIFIED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_upsert_dbsync);
    will_return(__wrap_wdb_upsert_dbsync, true);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_wdb_parse_dbsync_modified_err(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("osinfo MODIFIED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_upsert_dbsync);
    will_return(__wrap_wdb_upsert_dbsync, false);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_deleted_ok(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("osinfo DELETED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_delete_dbsync);
    will_return(__wrap_wdb_delete_dbsync, true);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_wdb_parse_dbsync_deleted_err(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("osinfo DELETED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_delete_dbsync);
    will_return(__wrap_wdb_delete_dbsync, false);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

/* wdb_parse_dbsync groups*/
void test_wdb_parse_dbsync_groups_no_operation(void ** state) {

    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("groups ", query);

    expect_string(__wrap__mdebug2, formatted_msg, "DBSYNC query: groups");

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid dbsync query syntax, near 'groups'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_groups_no_delta_data(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("groups INSERTED ", query);

    expect_string(__wrap__mdebug2, formatted_msg, "DBSYNC query: groups");
    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid dbsync query syntax, near 'groups'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_groups_delta_data_not_json(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("groups INSERTED {\"unclosed\":\"json", query);

    expect_string(__wrap__mdebug1, formatted_msg, DB_DELTA_PARSING_ERR);
    expect_string(__wrap__mdebug2, formatted_msg, "JSON error near: json");

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_groups_invalid_operation(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("groups NOOP {}", query);

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid operation type: NOOP");

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_groups_insert_ok(void ** state) {

    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("groups INSERTED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_upsert_dbsync);
    will_return(__wrap_wdb_upsert_dbsync, true);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_wdb_parse_dbsync_groups_insert_err(void ** state) {

    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("groups INSERTED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_upsert_dbsync);
    will_return(__wrap_wdb_upsert_dbsync, false);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_groups_modified_ok(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("groups MODIFIED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_upsert_dbsync);
    will_return(__wrap_wdb_upsert_dbsync, true);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_wdb_parse_dbsync_groups_modified_err(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("groups MODIFIED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_upsert_dbsync);
    will_return(__wrap_wdb_upsert_dbsync, false);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_groups_deleted_ok(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("groups DELETED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_delete_dbsync);
    will_return(__wrap_wdb_delete_dbsync, true);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_wdb_parse_dbsync_groups_deleted_err(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("groups DELETED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_delete_dbsync);
    will_return(__wrap_wdb_delete_dbsync, false);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

/* wdb_parse_dbsync users*/
void test_wdb_parse_dbsync_users_no_operation(void ** state) {

    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("users ", query);

    expect_string(__wrap__mdebug2, formatted_msg, "DBSYNC query: users");

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid dbsync query syntax, near 'users'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_users_no_delta_data(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("users INSERTED ", query);

    expect_string(__wrap__mdebug2, formatted_msg, "DBSYNC query: users");
    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid dbsync query syntax, near 'users'");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_users_delta_data_not_json(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("users INSERTED {\"unclosed\":\"json", query);

    expect_string(__wrap__mdebug1, formatted_msg, DB_DELTA_PARSING_ERR);
    expect_string(__wrap__mdebug2, formatted_msg, "JSON error near: json");

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_users_invalid_operation(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("users NOOP {}", query);

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid operation type: NOOP");

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_users_insert_ok(void ** state) {

    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("users INSERTED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_upsert_dbsync);
    will_return(__wrap_wdb_upsert_dbsync, true);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_wdb_parse_dbsync_users_insert_err(void ** state) {

    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("users INSERTED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_upsert_dbsync);
    will_return(__wrap_wdb_upsert_dbsync, false);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_users_modified_ok(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("users MODIFIED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_upsert_dbsync);
    will_return(__wrap_wdb_upsert_dbsync, true);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_wdb_parse_dbsync_users_modified_err(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("users MODIFIED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_upsert_dbsync);
    will_return(__wrap_wdb_upsert_dbsync, false);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "err");
    assert_int_equal(ret, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_dbsync_users_deleted_ok(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("users DELETED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_delete_dbsync);
    will_return(__wrap_wdb_delete_dbsync, true);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
}

void test_wdb_parse_dbsync_users_deleted_err(void ** state) {
    test_struct_t * data = (test_struct_t *) *state;
    char * query = NULL;

    os_strdup("users DELETED {\"key\": \"value\"}", query);

    expect_function_call(__wrap_wdb_delete_dbsync);
    will_return(__wrap_wdb_delete_dbsync, false);

    const int ret = wdb_parse_dbsync(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(query);
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

/* Tests agent vacuum */

void test_wdb_parse_agent_vacuum_commit_error(void **state) {
    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("agent 000 vacuum", query);

    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: vacuum");

    will_return(__wrap_wdb_commit2, OS_INVALID);

    expect_function_call(__wrap_wdb_finalize_all_statements);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot end transaction.");
    expect_string(__wrap_w_is_file, file, "queue/db/000.db");
    will_return(__wrap_w_is_file, 1);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot end transaction");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_agent_vacuum_vacuum_error(void **state) {
    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("agent 000 vacuum", query);

    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: vacuum");
    will_return(__wrap_wdb_commit2, OS_SUCCESS);

    expect_function_call(__wrap_wdb_finalize_all_statements);

    will_return(__wrap_wdb_vacuum, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot vacuum database.");
    expect_string(__wrap_w_is_file, file, "queue/db/000.db");
    will_return(__wrap_w_is_file, 1);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot vacuum database");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_agent_vacuum_success_get_db_state_error(void **state) {
    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("agent 000 vacuum", query);

    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: vacuum");
    will_return(__wrap_wdb_commit2, OS_SUCCESS);

    expect_function_call(__wrap_wdb_finalize_all_statements);

    will_return(__wrap_wdb_vacuum, OS_SUCCESS);

    will_return(__wrap_wdb_get_db_state, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Couldn't get fragmentation after vacuum for the database.");
    expect_string(__wrap_w_is_file, file, "queue/db/000.db");
    will_return(__wrap_w_is_file, 1);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Vacuum performed, but couldn't get fragmentation information after vacuum");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_agent_vacuum_success_update_vacuum_error(void **state) {
    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("agent 000 vacuum", query);

    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: vacuum");
    will_return(__wrap_wdb_commit2, OS_SUCCESS);

    expect_function_call(__wrap_wdb_finalize_all_statements);

    will_return(__wrap_wdb_vacuum, OS_SUCCESS);

    will_return(__wrap_wdb_get_db_state, 10);

    will_return(__wrap_time, 16655);

    expect_string(__wrap_wdb_update_last_vacuum_data, last_vacuum_value, "10");
    will_return(__wrap_wdb_update_last_vacuum_data, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Couldn't update last vacuum info for the database.");
    expect_string(__wrap_w_is_file, file, "queue/db/000.db");
    will_return(__wrap_w_is_file, 1);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Vacuum performed, but last vacuum information couldn't be updated in the metadata table");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_agent_vacuum_success(void **state) {
    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;
    char* response = NULL;
    os_strdup("{\"fragmentation_after_vacuum\":10}", response);

    os_strdup("agent 000 vacuum", query);

    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: vacuum");
    will_return(__wrap_wdb_commit2, OS_SUCCESS);

    expect_function_call(__wrap_wdb_finalize_all_statements);

    will_return(__wrap_wdb_vacuum, OS_SUCCESS);

    will_return(__wrap_wdb_get_db_state, 10);

    will_return(__wrap_time, 16655);

    expect_string(__wrap_wdb_update_last_vacuum_data, last_vacuum_value, "10");
    will_return(__wrap_wdb_update_last_vacuum_data, OS_SUCCESS);

    will_return(__wrap_cJSON_PrintUnformatted, response);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok {\"fragmentation_after_vacuum\":10}");
    assert_int_equal(result, OS_SUCCESS);

    os_free(query);
}

/* Tests agent get_fragmentation */

void test_wdb_parse_agent_get_fragmentation_db_state_error(void **state) {
    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("agent 000 get_fragmentation", query);

    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: get_fragmentation");

    will_return(__wrap_wdb_get_db_state, OS_INVALID);
    will_return(__wrap_wdb_get_db_free_pages_percentage, 10);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot get database fragmentation.");
    expect_string(__wrap_w_is_file, file, "queue/db/000.db");
    will_return(__wrap_w_is_file, 1);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot get database fragmentation");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_agent_get_fragmentation_free_pages_error(void **state) {
    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("agent 000 get_fragmentation", query);

    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: get_fragmentation");

    will_return(__wrap_wdb_get_db_state, 10);
    will_return(__wrap_wdb_get_db_free_pages_percentage, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot get database fragmentation.");
    expect_string(__wrap_w_is_file, file, "queue/db/000.db");
    will_return(__wrap_w_is_file, 1);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot get database fragmentation");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_global_get_fragmentation_success(void **state) {
    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    char* response = NULL;
    os_strdup("{\"fragmentation\":50,\"free_pages_percentage\":10}", response);

    os_strdup("agent 000 get_fragmentation", query);

    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: get_fragmentation");

    will_return(__wrap_wdb_get_db_state, 50);
    will_return(__wrap_wdb_get_db_free_pages_percentage, 10);

    will_return(__wrap_cJSON_PrintUnformatted, response);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok {\"fragmentation\":50,\"free_pages_percentage\":10}");
    assert_int_equal(result, OS_SUCCESS);

    os_free(query);
}

void test_wdb_parse_delete_db_file (void **state) {
    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("agent 000 non-query", query);

    expect_value(__wrap_wdb_open_agent2, agent_id, atoi(data->wdb->id));
    will_return(__wrap_wdb_open_agent2, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: non-query");


    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) query error near: non-query");

    expect_string(__wrap_w_is_file, file, "queue/db/000.db");
    //DB file deleted manually
    will_return(__wrap_w_is_file, 0);

    expect_string(__wrap__mwarn, formatted_msg, "DB(queue/db/000.db) not found. This behavior is unexpected, the database will be recreated.");
    will_return(__wrap_wdb_close, NULL);
    will_return(__wrap_wdb_close, OS_SUCCESS);
    expect_function_call(__wrap_wdb_pool_leave);
    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'non-query'");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

int main()
{
    const struct CMUnitTest tests[] = {
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
        /*****************************************************************************************
        TODO-LEGACY-ANALYSISD-FIM: Delete this function when the new system is ready
        Should not depend on analsysid code
        cmocka_unit_test_setup_teardown(test_syscheck_save_file_type_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_file_nospace, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_file_type_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_registry_type_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_registry_type_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save2_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save2_ok, test_setup, test_teardown),
        *****************************************************************************************/
        cmocka_unit_test_setup_teardown(test_integrity_check_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_check_no_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_check_checksum_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_check_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_clear_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_clear_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_command, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_sca_no_space, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_sca_query_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_sca_query_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_sca_cannot_query, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_sca_invalid_insert, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_sca_invalid_insert_not_number_id, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_sca_invalid_insert_negative_number_id, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_badquery, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_delete_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_delete_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_invalid_no_next, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_no_ptr, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_date_max_long, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_update_cache_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_update_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_update_insert_cache_error,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_update_insert_success, test_setup, test_teardown),
        /* Tests osinfo */
        cmocka_unit_test_setup_teardown(test_osinfo_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_invalid_action, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_missing_action, test_setup, test_teardown),
        // osinfo get
        cmocka_unit_test_setup_teardown(test_osinfo_get_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_get_success, test_setup, test_teardown),
        // osinfo set
        cmocka_unit_test_setup_teardown(test_osinfo_set_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_scan_id, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_scan_time, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_hostname, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_architecture, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_os_name, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_os_version, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_os_codename, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_os_major, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_os_minor, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_os_build, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_os_platform, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_sysname, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_release, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_version, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_no_os_release, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_error_saving, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_osinfo_set_success, test_setup, test_teardown),
        // wdb_parse_packages
        cmocka_unit_test_setup_teardown(test_packages_get_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_get_null_response, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_get_err_response, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_get_sock_err_response, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_save_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_save_success_null_items, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_save_success_empty_items, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_save_missing_items, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_save_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_del_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_del_success_null_items, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_del_update_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_del_delete_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_invalid_action, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_packages_no_action, test_setup, test_teardown),
        // wdb_parse_hotfixes
        cmocka_unit_test_setup_teardown(test_hotfixes_get_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_hotfixes_get_null_response, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_hotfixes_get_err_response, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_hotfixes_get_sock_err_response, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_hotfixes_save_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_hotfixes_save_success_null_items, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_hotfixes_save_missing_items, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_hotfixes_save_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_hotfixes_del_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_hotfixes_del_success_null_items, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_hotfixes_del_delete_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_hotfixes_invalid_action, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_hotfixes_no_action, test_setup, test_teardown),
        /* dbsync Tests */
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_no_table, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_no_operation, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_no_delta_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_invalid_table, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_invalid_operation, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_delta_data_not_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_insert_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_insert_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_modified_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_modified_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_deleted_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_deleted_err, test_setup, test_teardown),
        /* dbsync tests users */
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_users_no_operation, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_users_no_delta_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_users_invalid_operation, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_users_delta_data_not_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_users_insert_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_users_insert_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_users_modified_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_users_modified_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_users_deleted_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_users_deleted_err, test_setup, test_teardown),
        /* dbsync tests groups */
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_groups_no_operation, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_groups_no_delta_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_groups_invalid_operation, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_groups_delta_data_not_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_groups_insert_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_groups_insert_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_groups_modified_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_groups_modified_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_groups_deleted_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_dbsync_groups_deleted_err, test_setup, test_teardown),
        /* wdb_parse_global_backup */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_backup_invalid_syntax, test_setup_global, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_backup_missing_action, test_setup_global, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_backup_invalid_action, test_setup_global, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_backup_create_failed, test_setup_global, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_backup_create_success, test_setup_global, test_teardown),
        /* wdb_parse_agent_vacuum */
        cmocka_unit_test_setup_teardown(test_wdb_parse_agent_vacuum_commit_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_agent_vacuum_vacuum_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_agent_vacuum_success_get_db_state_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_agent_vacuum_success_update_vacuum_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_agent_vacuum_success, test_setup, test_teardown),
        /* wdb_parse_agent_get_fragmentation */
        cmocka_unit_test_setup_teardown(test_wdb_parse_agent_get_fragmentation_db_state_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_agent_get_fragmentation_free_pages_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_fragmentation_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_delete_db_file, test_setup, test_teardown),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
