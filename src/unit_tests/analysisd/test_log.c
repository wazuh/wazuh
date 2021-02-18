/*
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include "../wrappers/libc/stdio_wrappers.h"
#include "../../analysisd/alerts/log.h"
#include "../../headers/syscheck_op.h"

extern int test_mode;
extern FILE *_aflog;

// Setup / Teardown
DynamicField df[] = {
    [FIM_FILE] = {.key = "fim_file", .value = "/path/to/file"},
    [FIM_HARD_LINKS] = {.key = "fim_hard_links", .value = "/link/to/file"},
    [FIM_MODE] = {.key = "fim_mode", .value = "whodata"},
    [FIM_SIZE] = {.key = "fim_size", .value = "5000"},
    [FIM_SIZE_BEFORE] = {.key = "fim_size_before", .value = "4000"},
    [FIM_PERM] = {.key = "fim_perm", .value = "permission"},
    [FIM_PERM_BEFORE] = {.key = "fim_perm_before", .value = "permission_before"},
    [FIM_UID] = {.key = "fim_uid", .value = "1000"},
    [FIM_UID_BEFORE] = {.key = "fim_uid_before", .value = "999"},
    [FIM_GID] = {.key = "fim_gid", .value = "1000"},
    [FIM_GID_BEFORE] = {.key = "fim_gid_before", .value = "999"},
    [FIM_MD5] = {.key = "fim_md5", .value = "12345"},
    [FIM_MD5_BEFORE] = {.key = "fim_md5_before", .value = "54321"},
    [FIM_SHA1] = {.key = "fim_sha1", .value = "12345"},
    [FIM_SHA1_BEFORE] = {.key = "fim_sha1_before", .value = "54321"},
    [FIM_UNAME] = {.key = "fim_uname", .value = "user"},
    [FIM_UNAME_BEFORE] = {.key = "fim_uname_before", .value = "user_before"},
    [FIM_GNAME] = {.key = "fim_gname", .value = "group"},
    [FIM_GNAME_BEFORE] = {.key = "fim_gname_before", .value = "group_before"},
    [FIM_MTIME] = {.key = "fim_mtime", .value = "12345678"},
    [FIM_MTIME_BEFORE] = {.key = "fim_mtime_before", .value = "87654321"},
    [FIM_INODE] = {.key = "fim_inode", .value = "2222"},
    [FIM_INODE_BEFORE] = {.key = "fim_inode_before", .value = "1111"},
    [FIM_SHA256] = {.key = "fim_sha256", .value = "12345"},
    [FIM_SHA256_BEFORE] = {.key = "fim_sha256_before", .value = "54321"},
    [FIM_DIFF] = {.key = "fim_diff", .value = "diff"},
    [FIM_ATTRS] = {.key = "fim_attrs", .value = "attributes"},
    [FIM_ATTRS_BEFORE] = {.key = "fim_attrs_before", .value = "attributes_before"},
    [FIM_CHFIELDS] = {.key = "fim_chfields", .value = "changed_fields"},
    [FIM_USER_ID] = {.key = "fim_userid", .value = "2000"},
    [FIM_USER_NAME] = {.key = "fim_username", .value = "user_name"},
    [FIM_GROUP_ID] = {.key = "fim_groupid", .value = "2000"},
    [FIM_GROUP_NAME] = {.key = "fim_groupname", .value = "group_name"},
    [FIM_PROC_NAME] = {.key = "fim_proc_name", .value = "proc_name"},
    [FIM_PROC_PNAME] = {.key = "fim_proc_pname", .value = "proc_pname"},
    [FIM_AUDIT_CWD] = {.key = "fim_audit_cwd", .value = "/audit/cwd"},
    [FIM_AUDIT_PCWD] = {.key = "fim_audit_pcwd", .value = "/audit/pcwd"},
    [FIM_AUDIT_ID] = {.key = "fim_audit_id", .value = "6789"},
    [FIM_AUDIT_NAME] = {.key = "fim_audit_name", .value = "audit_name"},
    [FIM_EFFECTIVE_UID] = {.key = "fim_effective_uid", .value = "effective_uid"},
    [FIM_EFFECTIVE_NAME] = {.key = "fim_effective_name", .value = "effective_name"},
    [FIM_PPID] = {.key = "fim_ppid", .value = "ppid"},
    [FIM_PROC_ID] = {.key = "fim_proc_id", .value = "proc_id"},
    [FIM_TAG] = {.key = "fim_tag", .value = "tag1,tag2"},
    [FIM_SYM_PATH] = {.key = "fim_sym_path", .value = "/sym/path"},
    [FIM_REGISTRY_ARCH] = {.key = "fim_registry_arch", .value = "[x64]"},
    [FIM_REGISTRY_VALUE_NAME] = {.key = "fim_registry_value_name", .value = "value_name"},
    [FIM_REGISTRY_VALUE_TYPE] = {.key = "fim_registry_value_type", .value = "binary"},
    [FIM_ENTRY_TYPE] = {.key = "fim_entry_type", .value = "registry"},
    [FIM_EVENT_TYPE_STR] = {.key = "fim_event_type", .value = "modified"}
};





static int test_setup(void **state) {
    Eventinfo *lf = NULL;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(FIM_NFIELDS, sizeof(DynamicField), lf->fields);
    os_calloc(2, sizeof(wlabel_t), lf->labels);
    os_calloc(3, sizeof(char *), lf->last_events);
    os_calloc(1, sizeof(RuleInfo), lf->generated_rule);

    lf->labels[0].key = "key_label";
    lf->labels[0].value = "value_label";
    lf->labels[1].key = NULL;
    lf->labels[1].value = NULL;
    lf->nfields = FIM_NFIELDS;
    lf->last_events[0] = "Last";
    lf->last_events[1] = "event";
    lf->last_events[2] = NULL;
    lf->year = 2000;
    lf->mon[0] = 'm';
    lf->mon[1] = '\0';
    lf->day = 1;
    lf->hour[0] = 'h';
    lf->hour[1] = '\0';
    lf->generated_rule->sigid = 554;
    lf->generated_rule->level = 123;
    lf->generated_rule->group = "rule_group";
    lf->time.tv_sec = 160987966;
    lf->full_log = "full_log";
    lf->comment = "comment";
    lf->hostname = "hostname";

    char aux1[12];

    for (int i = 0; i < lf->nfields; i++) {
        lf->fields[i].value = df[i].value;
        lf->fields[i].key = df[i].key;
    }

    test_mode = 1;
    *state = lf;
    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    Eventinfo *lf = *state;

    os_free(lf->fields);
    os_free(lf->labels);
    os_free(lf->last_events);
    os_free(lf->generated_rule);
    os_free(lf);

    return OS_SUCCESS;
}

// Tests

void test_OS_Log_no_syscheck_event(void **state) {
    Eventinfo *lf = *state;
    lf->location = "no-syscheck";
    char buffer[FIM_NFIELDS][40];

    expect_fprintf(_aflog, "** Alert 160987966.0: - rule_group\n"
                           "2000 m 01 h hostname->no-syscheck\n"
                           "key_label: value_label\n"
                           "Rule: 554 (level 123) -> 'comment'\n"
                           "full_log\n", 0);

    for (int i = 0; i < lf->nfields; i++) {
        snprintf(buffer[i], 40, "%s: %s\n", df[i].key, df[i].value);
        expect_fprintf(_aflog, buffer[i], 0);
    }

    expect_fprintf(_aflog, "Last\n", 0);
    expect_fprintf(_aflog, "event\n", 0);
    expect_value(__wrap_fputc, character, '\n');
    expect_value(__wrap_fputc, stream, _aflog);
    will_return(__wrap_fputc, 0);

    OS_Log(lf);
}

void test_OS_Log_no_label_event(void **state) {
    Eventinfo *lf = *state;
    lf->location = "no-syscheck";
    char buffer[FIM_NFIELDS][40];
    lf->labels[0].key = NULL;
    lf->labels[0].value = NULL;

    expect_fprintf(_aflog, "** Alert 160987966.0: - rule_group\n"
                           "2000 m 01 h hostname->no-syscheck\n"
                           "Rule: 554 (level 123) -> 'comment'\n"
                           "full_log\n", 0);

    for (int i = 0; i < lf->nfields; i++) {
        snprintf(buffer[i], 40, "%s: %s\n", df[i].key, df[i].value);
        expect_fprintf(_aflog, buffer[i], 0);
    }

    expect_fprintf(_aflog, "Last\n", 0);
    expect_fprintf(_aflog, "event\n", 0);
    expect_value(__wrap_fputc, character, '\n');
    expect_value(__wrap_fputc, stream, _aflog);
    will_return(__wrap_fputc, 0);

    OS_Log(lf);
}

void test_OS_Log_syscheck_event(void **state) {
    Eventinfo *lf = *state;
    lf->location = "syscheck";
    lf->labels[0].key = "key_label";
    lf->labels[0].value = "value_label";

    expect_fprintf(_aflog, "** Alert 160987966.0: - rule_group\n"
                           "2000 m 01 h hostname->syscheck\n"
                           "key_label: value_label\n"
                           "Rule: 554 (level 123) -> 'comment'\n"
                           "full_log\n", 0);

    will_return(__wrap_fwrite, 13); // "Attributes:\n"
    expect_fprintf(_aflog, " - Size: 5000\n", 0);
    expect_fprintf(_aflog, " - Permissions: permission\n", 0);
    expect_fprintf(_aflog, " - Date: Sat May 23 21:21:18 1970\n", 0);
    expect_fprintf(_aflog, " - Inode: 2222\n", 0);
    expect_fprintf(_aflog, " - User: user (1000)\n", 0);
    expect_fprintf(_aflog, " - Group: group (1000)\n", 0);
    expect_fprintf(_aflog, " - MD5: 12345\n", 0);
    expect_fprintf(_aflog, " - SHA1: 12345\n", 0);
    expect_fprintf(_aflog, " - SHA256: 12345\n", 0);
    expect_fprintf(_aflog, " - File attributes: attributes\n", 0);
    expect_fprintf(_aflog, " - (Audit) User name: user_name\n", 0);
    expect_fprintf(_aflog, " - (Audit) Audit name: audit_name\n", 0);
    expect_fprintf(_aflog, " - (Audit) Effective name: effective_name\n", 0);
    expect_fprintf(_aflog, " - (Audit) Group name: group_name\n", 0);
    expect_fprintf(_aflog, " - (Audit) Process id: proc_id\n", 0);
    expect_fprintf(_aflog, " - (Audit) Process name: proc_name\n", 0);
    expect_fprintf(_aflog, " - (Audit) Process cwd: /audit/cwd\n", 0);
    expect_fprintf(_aflog, " - (Audit) Parent process name: proc_pname\n", 0);
    expect_fprintf(_aflog, " - (Audit) Parent process id: ppid\n", 0);
    expect_fprintf(_aflog, " - (Audit) Parent process cwd: /audit/pcwd\n", 0);
    expect_fprintf(_aflog, "\nWhat changed:\ndiff\n", 0);
    will_return(__wrap_fwrite, 8); // "\nTags:\n"
    expect_fprintf(_aflog, " - tag1\n", 0);
    expect_fprintf(_aflog, " - tag2\n", 0);
    expect_fprintf(_aflog, "Last\n", 0);
    expect_fprintf(_aflog, "event\n", 0);
    expect_value(__wrap_fputc, character, '\n');
    expect_value(__wrap_fputc, stream, _aflog);
    will_return(__wrap_fputc, 0);

    OS_Log(lf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // OS_Log (Legacy function testing)
        cmocka_unit_test(test_OS_Log_no_syscheck_event),
        cmocka_unit_test(test_OS_Log_no_label_event),
        cmocka_unit_test(test_OS_Log_syscheck_event)
    };

    return cmocka_run_group_tests(tests, test_setup, test_teardown);
}
