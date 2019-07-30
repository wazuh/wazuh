#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../headers/audit_op.h"
#include "tap.h"

#define TEST_FOLDER "/tmp/test_tap"

int test_audit_add() {

    int ret = 0;
    if (audit_add_rule(TEST_FOLDER, "tap") > 0) {
        ret = 1;
    }
    return ret;
}

int test_audit_add_nok() {

    int ret = 0;
    if (audit_add_rule(TEST_FOLDER, "tap") <= 0) {
        ret = 1;
    }
    return ret;
}

int test_audit_search() {

    int ret = 0;

    int fd = audit_open();
    audit_get_rule_list(fd);
    audit_close(fd);

    if (search_audit_rule(TEST_FOLDER, "wa", "tap") == 1) {
        ret = 1;
    }
    return ret;
}

int test_audit_search_nok() {

    int ret = 0;
    if (search_audit_rule("/tmp/fail_tap", "wa", "tap") <= 0) {
        ret = 1;
    }
    return ret;
}

int test_audit_delete() {

    int ret = 0;
    if (audit_delete_rule(TEST_FOLDER, "tap") > 0) {
        ret = 1;
    }
    return ret;
}

int test_audit_delete_nok() {

    int ret = 0;
    if (audit_delete_rule(TEST_FOLDER, "tap") <= 0) {
        ret = 1;
    }
    return ret;
}


int main(void) {

    printf("\n\n   STARTING TEST - AUDIT_OP   \n\n");

    mkdir(TEST_FOLDER, 0755);

    TAP_TEST_MSG(test_audit_add(), "Add rule.");

    TAP_TEST_MSG(test_audit_add_nok(), "Add duplicated rule.");

    TAP_TEST_MSG(test_audit_search(), "Search existing rule.");

    TAP_TEST_MSG(test_audit_search_nok(), "Search not existing rule.");

    TAP_TEST_MSG(test_audit_delete(), "Delete existing rule.");

    TAP_TEST_MSG(test_audit_delete_nok(), "Delete not existing rule.");

    TAP_TEST_MSG(!audit_restart(), "Restart Audit.");

    rmdir(TEST_FOLDER);
    audit_free_list();

    TAP_PLAN;
    TAP_SUMMARY;

    printf("\n   ENDING TEST - AUDIT_OP   \n\n");
    return 0;

}
