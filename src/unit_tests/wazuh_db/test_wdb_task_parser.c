
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "hash_op.h"
#include "os_err.h"
#include "wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_task_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "wazuhdb_op.h"

// Setup/teardown



// Tests



int main()
{
    const struct CMUnitTest tests[] = {
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
