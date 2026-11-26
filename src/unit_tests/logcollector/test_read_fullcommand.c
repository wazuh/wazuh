#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "logcollector.h"
#include "shared.h"
#include "../wrappers/common.h"
#include "../wrappers/libc/stdio_wrappers.h"

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

int __wrap_w_msg_hash_queues_push(const char *str, char *file, unsigned long size, logtarget *targets, char queue_mq) {
    check_expected(str);
    return 0;
}

int __wrap_check_ignore_and_restrict(OSList * ignore_exp, OSList * restrict_exp, const char *log_line) {
    return 0;
}

void test_read_fullcommand_multiline_without_trailing_newline(void **state) {
    FILE *fp = (FILE *) 1;
    logreader lf = { .command = "printf 'line1\\nline2'", .alias = "full-nonl" };
    int rc = 0;

    expect_popen(lf.command, "r", fp);
    expect_fread("line1\nline2", strlen("line1\nline2"));
    expect_string(__wrap_w_msg_hash_queues_push, str, "wazuh: output: 'full-nonl':\nline1\nline2");
    expect_value(__wrap_pclose, __stream, fp);
    will_return(__wrap_pclose, 0);

    read_fullcommand(&lf, &rc, 0);
}

void test_read_fullcommand_single_line_without_trailing_newline(void **state) {
    FILE *fp = (FILE *) 1;
    logreader lf = { .command = "printf 'only-line'", .alias = "full-single" };
    int rc = 0;

    expect_popen(lf.command, "r", fp);
    expect_fread("only-line", strlen("only-line"));
    expect_string(__wrap_w_msg_hash_queues_push, str, "wazuh: output: 'full-single':\nonly-line");
    expect_value(__wrap_pclose, __stream, fp);
    will_return(__wrap_pclose, 0);

    read_fullcommand(&lf, &rc, 0);
}

void test_read_fullcommand_trims_trailing_newline(void **state) {
    FILE *fp = (FILE *) 1;
    logreader lf = { .command = "printf 'line1\\nline2\\n'", .alias = "full-nl" };
    int rc = 0;

    expect_popen(lf.command, "r", fp);
    expect_fread("line1\nline2\n", strlen("line1\nline2\n"));
    expect_string(__wrap_w_msg_hash_queues_push, str, "wazuh: output: 'full-nl':\nline1\nline2");
    expect_value(__wrap_pclose, __stream, fp);
    will_return(__wrap_pclose, 0);

    read_fullcommand(&lf, &rc, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_fullcommand_multiline_without_trailing_newline),
        cmocka_unit_test(test_read_fullcommand_single_line_without_trailing_newline),
        cmocka_unit_test(test_read_fullcommand_trims_trailing_newline),
    };
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
