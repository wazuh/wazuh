#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "logcollector.h"
#include "shared.h"
#include "../wrappers/common.h"
#include "../wrappers/libc/stdio_wrappers.h"

extern int maximum_lines;

static int group_setup(void ** state) {
    test_mode = 1;
    maximum_lines = 0;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

int __wrap_can_read() {
    return mock_type(int);
}

int __wrap_w_msg_hash_queues_push(const char *str, char *file, unsigned long size, logtarget *targets, char queue_mq) {
    check_expected(str);
    return 0;
}

int __wrap_check_ignore_and_restrict(OSList * ignore_exp, OSList * restrict_exp, const char *log_line) {
    return 0;
}

void test_read_command_skips_empty_lines(void **state) {
    FILE *fp = (FILE *) 1;
    logreader lf = { .command = "printf 'line1\\n\\nline2\\n'", .alias = "cmd-alias" };
    int rc = 0;

    expect_popen(lf.command, "r", fp);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "line1\n");
    expect_string(__wrap_w_msg_hash_queues_push, str, "wazuh: output: 'cmd-alias': line1");

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "\n");

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "line2\n");
    expect_string(__wrap_w_msg_hash_queues_push, str, "wazuh: output: 'cmd-alias': line2");

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_value(__wrap_pclose, __stream, fp);
    will_return(__wrap_pclose, 0);

    read_command(&lf, &rc, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_command_skips_empty_lines),
    };
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
