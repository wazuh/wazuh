
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "wazuh_db/wdb.h"

int __wrap__mdebug1()
{
    return 0;
}

int __wrap__mdebug2()
{
    return 0;
}

int __wrap__mwarn()
{
    return 0;
}

int __wrap__merror()
{
    return 0;
}

int __wrap_wdb_scan_info_get(wdb_t *socket, const char *module, char *field, long *output)
{
    *output = 0;
    return mock();
}

int __wrap_wdb_fim_update_date_entry(wdb_t* socket, const char *path)
{
    return mock();
}

int __wrap_wdb_fim_clean_old_entries(wdb_t* socket)
{
    return mock();
}

int __wrap_wdb_scan_info_update(wdb_t *socket, const char *module, char *field, long *output)
{
    return mock();
}

int __wrap_wdb_scan_info_fim_checks_control(wdb_t* socket,const char *last_check)
{
    return mock();
}

int __wrap_wdb_syscheck_load(wdb_t *wdb, const char *file, char *output, size_t size)
{
    snprintf(output, OS_MAXSTR + 1, "TEST STRING");
    return mock();
}

int __wrap_wdb_fim_delete(wdb_t *wdb, const char *file)
{
    return mock();
}

int __wrap_wdb_syscheck_save(wdb_t *wdb, int ftype, char *checksum, const char *file)
{
    return mock();
}

int __wrap_wdb_syscheck_save2(wdb_t *wdb, const char *payload)
{
    return mock();
}

int __wrap_wdbi_query_checksum(wdb_t *wdb, wdb_component_t component, const char *command, const char *payload)
{
    return mock();
}

int __wrap_wdbi_query_clear(wdb_t *wdb, wdb_component_t component, const char *payload)
{
    return mock();
}


typedef struct test_struct {
    wdb_t *socket;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data;
    init_data = malloc(sizeof(test_struct_t));
    init_data->socket = malloc(sizeof(wdb_t));
    init_data->socket->id = strdup("000");
    init_data->output = malloc(256*sizeof(char));
    *state = init_data;
    return 0;
}

static int test_teardown(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    free(data->output);
    free(data->socket->id);
    free(data->socket);
    free(data);
    return 0;
}

void test_wdb_parse_syscheck_no_space(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    ret = wdb_parse_syscheck(data->socket, "badquery_nospace", data->output);
    
    assert_string_equal(data->output, "err Invalid FIM query syntax, near \'badquery_nospace\'");
    assert_int_equal(ret, -1);
}

void test_scan_info_error(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_scan_info_get, -1);
    char *query = strdup("scan_info_get ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "err Cannot get fim scan info.");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_scan_info_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    
    will_return(__wrap_wdb_scan_info_get, 1);
    char *query = strdup("scan_info_get ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "ok 0");
    assert_int_equal(ret, 1);

    os_free(query);
}


void test_update_info_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_fim_update_date_entry, -1);
    char *query = strdup("updatedate ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "err Cannot update fim date field.");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_update_info_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_fim_update_date_entry, 1);
    char *query = strdup("updatedate ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}


void test_clean_old_entries_error(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_fim_clean_old_entries, -1);
    char *query = strdup("cleandb ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "err Cannot clean fim database.");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_clean_old_entries_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_fim_clean_old_entries, 1);
    char *query = strdup("cleandb ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}



void test_scan_info_update_noarg(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("scan_info_update ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near \'\'");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_scan_info_update_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_scan_info_update, -1);
    char *query = strdup("scan_info_update \"191919\" ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "err Cannot save fim control message");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_scan_info_update_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_scan_info_update, 1);
    char *query = strdup("scan_info_update \"191919\" ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}



void test_scan_info_fim_check_control_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_scan_info_fim_checks_control, -1);
    char *query = strdup("control ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "err Cannot save fim control message");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_scan_info_fim_check_control_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_scan_info_fim_checks_control, 1);
    char *query = strdup("control ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_syscheck_load_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_syscheck_load, -1);
    char *query = strdup("load ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "err Cannot load Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_load_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_syscheck_load, 1);
    char *query = strdup("load ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "ok TEST STRING");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_fim_delete_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_fim_delete, -1);
    char *query = strdup("delete ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "err Cannot delete Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_fim_delete_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_fim_delete, 1);
    char *query = strdup("delete ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);
    
    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_syscheck_save_noarg(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near \'\'");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_invalid_type(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save invalid_type ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near \'invalid_type\'");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_file_type_error(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save file 1212121 ");
    will_return(__wrap_wdb_syscheck_save, -1);
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "err Cannot save Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_file_nospace(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save file ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near \'\'");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_file_type_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save file !1212121 ");
    will_return(__wrap_wdb_syscheck_save, 1);
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_syscheck_save_registry_type_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save registry 1212121 ");
    will_return(__wrap_wdb_syscheck_save, -1);
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "err Cannot save Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_registry_type_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save registry !1212121 ");
    will_return(__wrap_wdb_syscheck_save, 1);
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_syscheck_save2_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save2 ");
    will_return(__wrap_wdb_syscheck_save2, -1);
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "err Cannot save Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save2_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save2 ");
    will_return(__wrap_wdb_syscheck_save2, 1);
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_integrity_check_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_check_ ");
    will_return(__wrap_wdbi_query_checksum, -1);
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "err Cannot perform range checksum");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_integrity_check_no_data(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_check_ ");
    will_return(__wrap_wdbi_query_checksum, 0);
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "ok no_data");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_integrity_check_checksum_fail(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_check_ ");
    will_return(__wrap_wdbi_query_checksum, 1);
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "ok checksum_fail");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_integrity_check_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_check_ ");
    will_return(__wrap_wdbi_query_checksum, 2);
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_integrity_clear_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_clear ");
    will_return(__wrap_wdbi_query_clear, -1);
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "err Cannot perform range checksum");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_integrity_clear_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_clear ");
    will_return(__wrap_wdbi_query_clear, 2);
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, 0);

    os_free(query);
}


void test_invalid_command(void **state){
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("wrong_command ");
    ret = wdb_parse_syscheck(data->socket, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near 'wrong_command'");
    assert_int_equal(ret, -1);

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
        cmocka_unit_test_setup_teardown(test_invalid_command, test_setup, test_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);

}