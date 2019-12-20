
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


void test_wdb_parse_syscheck_no_space(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    ret = wdb_parse_syscheck(socket, "badquery_nospace", output);
    
    assert_string_equal(output, "err Invalid FIM query syntax, near \'badquery_nospace\'");
    assert_int_equal(ret, -1);

    os_free(output);

}

void test_scan_info_error(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_scan_info_get, -1);
    char *query = strdup("scan_info_get ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "err Cannot get fim scan info.");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);

}

void test_scan_info_ok(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_scan_info_get, 1);
    char *query = strdup("scan_info_get ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "ok 0");
    assert_int_equal(ret, 1);

    os_free(query);
    os_free(output);

}


void test_update_info_error(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_fim_update_date_entry, -1);
    char *query = strdup("updatedate ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "err Cannot update fim date field.");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);

}

void test_update_info_ok(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_fim_update_date_entry, 1);
    char *query = strdup("updatedate ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
    os_free(output);

}


void test_clean_old_entries_error(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_fim_clean_old_entries, -1);
    char *query = strdup("cleandb ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "err Cannot clean fim database.");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);

}

void test_clean_old_entries_ok(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_fim_clean_old_entries, 1);
    char *query = strdup("cleandb ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
    os_free(output);

}



void test_scan_info_update_noarg(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket; 

    char *output;
    os_malloc(256, output);
    char *query = strdup("scan_info_update ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "err Invalid Syscheck query syntax, near \'\'");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);

}

void test_scan_info_update_error(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket; 

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_scan_info_update, -1);
    char *query = strdup("scan_info_update \"191919\" ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "err Cannot save fim control message");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);

}

void test_scan_info_update_ok(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket; 

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_scan_info_update, 1);
    char *query = strdup("scan_info_update \"191919\" ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
    os_free(output);

}



void test_scan_info_fim_check_control_error(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_scan_info_fim_checks_control, -1);
    char *query = strdup("control ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "err Cannot save fim control message");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);

}

void test_scan_info_fim_check_control_ok(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_scan_info_fim_checks_control, 1);
    char *query = strdup("control ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
    os_free(output);

}

void test_syscheck_load_error(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_syscheck_load, -1);
    char *query = strdup("load ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "err Cannot load Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);

}

void test_syscheck_load_ok(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_syscheck_load, 1);
    char *query = strdup("load ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "ok ");
    assert_int_equal(ret, 1);

    os_free(query);
    os_free(output);

}

void test_fim_delete_error(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_fim_delete, -1);
    char *query = strdup("delete ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "err Cannot delete Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);

}

void test_fim_delete_ok(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;

    char *output;
    os_malloc(256, output);
    will_return(__wrap_wdb_fim_delete, 1);
    char *query = strdup("delete ");
    ret = wdb_parse_syscheck(socket, query, output);
    
    assert_string_equal(output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
    os_free(output);

}

void test_syscheck_save_noarg(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("save ");
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "err Invalid Syscheck query syntax, near \'\'");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);
}

void test_syscheck_save_invalid_type(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("save invalid_type ");
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "err Invalid Syscheck query syntax, near \'invalid_type\'");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);
}

void test_syscheck_save_file_type_error(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("save file 1212121 ");
    will_return(__wrap_wdb_syscheck_save, -1);
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "err Cannot save Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);
}

void test_syscheck_save_file_type_ok(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("save file !1212121 ");
    will_return(__wrap_wdb_syscheck_save, 1);
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
    os_free(output);
}

void test_syscheck_save_registry_type_error(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("save registry 1212121 ");
    will_return(__wrap_wdb_syscheck_save, -1);
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "err Cannot save Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);
}

void test_syscheck_save_registry_type_ok(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("save registry !1212121 ");
    will_return(__wrap_wdb_syscheck_save, 1);
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
    os_free(output);
}

void test_syscheck_save2_error(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("save2 ");
    will_return(__wrap_wdb_syscheck_save2, -1);
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "err Cannot save Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);
}

void test_syscheck_save2_ok(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("save2 ");
    will_return(__wrap_wdb_syscheck_save2, 1);
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "ok");
    assert_int_equal(ret, 0);

    os_free(query);
    os_free(output);
}

void test_integrity_check_error(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("integrity_check_ ");
    will_return(__wrap_wdbi_query_checksum, -1);
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "err Cannot perform range checksum");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);
}

void test_integrity_check_no_data(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("integrity_check_ ");
    will_return(__wrap_wdbi_query_checksum, 0);
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "ok no_data");
    assert_int_equal(ret, 0);

    os_free(query);
    os_free(output);
}

void test_integrity_check_checksum_fail(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("integrity_check_ ");
    will_return(__wrap_wdbi_query_checksum, 1);
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "ok checksum_fail");
    assert_int_equal(ret, 0);

    os_free(query);
    os_free(output);
}

void test_integrity_check_ok(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("integrity_check_ ");
    will_return(__wrap_wdbi_query_checksum, 2);
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "ok ");
    assert_int_equal(ret, 0);

    os_free(query);
    os_free(output);
}

void test_integrity_clear_error(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("integrity_clear ");
    will_return(__wrap_wdbi_query_clear, -1);
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "err Cannot perform range checksum");
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(output);
}

void test_integrity_clear_ok(void **state)
{
    (void) state;
    int ret;

    wdb_t *socket;
    char *output;
    os_malloc(256, output);
    char *query = strdup("integrity_clear ");
    will_return(__wrap_wdbi_query_clear, 2);
    ret = wdb_parse_syscheck(socket, query, output);

    assert_string_equal(output, "ok ");
    assert_int_equal(ret, 0);

    os_free(query);
    os_free(output);
}

int main()
{
    const struct CMUnitTest tests[] = 
    {
        cmocka_unit_test(test_wdb_parse_syscheck_no_space),
        cmocka_unit_test(test_scan_info_error),
        cmocka_unit_test(test_scan_info_ok),
        cmocka_unit_test(test_update_info_error),
        cmocka_unit_test(test_update_info_ok),
        cmocka_unit_test(test_clean_old_entries_error),
        cmocka_unit_test(test_clean_old_entries_ok),
        cmocka_unit_test(test_scan_info_update_noarg),
        cmocka_unit_test(test_scan_info_update_error),
        cmocka_unit_test(test_scan_info_update_ok),
        cmocka_unit_test(test_scan_info_fim_check_control_error),
        cmocka_unit_test(test_scan_info_fim_check_control_ok),
        cmocka_unit_test(test_syscheck_load_error),
        cmocka_unit_test(test_syscheck_load_ok),
        cmocka_unit_test(test_fim_delete_error),
        cmocka_unit_test(test_fim_delete_ok),
        cmocka_unit_test(test_syscheck_save_noarg),
        cmocka_unit_test(test_syscheck_save_invalid_type),
        cmocka_unit_test(test_syscheck_save_file_type_error),
        cmocka_unit_test(test_syscheck_save_file_type_ok),
        cmocka_unit_test(test_syscheck_save_registry_type_error),
        cmocka_unit_test(test_syscheck_save_registry_type_ok),
        cmocka_unit_test(test_syscheck_save2_error),
        cmocka_unit_test(test_syscheck_save2_ok),
        cmocka_unit_test(test_integrity_check_error),
        cmocka_unit_test(test_integrity_check_no_data),
        cmocka_unit_test(test_integrity_check_checksum_fail	),
        cmocka_unit_test(test_integrity_check_ok),
        cmocka_unit_test(test_integrity_clear_error),
        cmocka_unit_test(test_integrity_clear_ok),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);

}