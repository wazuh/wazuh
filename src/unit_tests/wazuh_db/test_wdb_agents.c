
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "os_err.h"
#include "wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "wazuhdb_op.h"
#include "wazuh_db/wdb_agents.h"

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("000",init_data->wdb->id);
    os_calloc(256,sizeof(char),init_data->output);
    os_calloc(1,sizeof(sqlite3 *),init_data->wdb->db);
    *state = init_data;
    return 0;
}

static int test_teardown(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->wdb->id);
    os_free(data->wdb->db);
    os_free(data->wdb);
    os_free(data);
    return 0;
}

/* Tests wdb_agents_insert_vuln_cve */

void test_wdb_agents_insert_vuln_cve_fail(void **state)
{
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";

    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVE_INSERT);

    ret = wdb_agents_insert_vuln_cve(data->wdb, name, version, architecture, cve);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_insert_vuln_cve_success(void **state)
{
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;
    const char* name = "package";
    const char* version = "4.0";
    const char* architecture = "x86";
    const char* cve = "CVE-2021-1200";

    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVE_INSERT);

    will_return_count(__wrap_sqlite3_bind_text, OS_SUCCESS, -1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, version);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, architecture);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, cve);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    ret = wdb_agents_insert_vuln_cve(data->wdb, name, version, architecture, cve);

    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_agents_clear_vuln_cve */

void test_wdb_agents_clear_vuln_cve_fail(void **state)
{
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVE_CLEAR);

    ret = wdb_agents_clear_vuln_cve(data->wdb);

    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_agents_clear_vuln_cve_success(void **state)
{
    int ret = -1;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1); //Returning any value
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_VULN_CVE_CLEAR);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    ret = wdb_agents_clear_vuln_cve(data->wdb);

    assert_int_equal(ret, OS_SUCCESS);
}


int main()
{
    const struct CMUnitTest tests[] = {
        /* Tests wdb_agents_insert_vuln_cve */
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cve_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_insert_vuln_cve_success, test_setup, test_teardown),
        /* Tests wdb_agents_clear_vuln_cve */
        cmocka_unit_test_setup_teardown(test_wdb_agents_clear_vuln_cve_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_agents_clear_vuln_cve_success, test_setup, test_teardown)
      };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
