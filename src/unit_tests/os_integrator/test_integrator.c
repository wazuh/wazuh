/*
 * Copyright (C) 2015, Wazuh Inc.
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

#include "../headers/shared.h"
#include "../os_integrator/integrator.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"

static int test_setup(void **state) {
    test_mode = 1;

    IntegratorConfig *virustotal_config = calloc(1, sizeof(IntegratorConfig));
    IntegratorConfig *pagerduty_config = calloc(1, sizeof(IntegratorConfig));

    virustotal_config->name = "virustotal";
    virustotal_config->apikey = "123456";
    virustotal_config->group = "syscheck";
    virustotal_config->alert_format = "json";
    virustotal_config->enabled = 1;

    pagerduty_config->name = "pagerduty";
    pagerduty_config->apikey = "123456";
    pagerduty_config->group = "syscheck";
    pagerduty_config->enabled = 1;
    pagerduty_config->max_log = 165;
    pagerduty_config->alert_format = "json";
    pagerduty_config->options = "{\"location\":\"syscheck-X\"}";

    state[0] = virustotal_config;
    state[1] = pagerduty_config;

    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    test_mode = 0;

    (void) state;

    IntegratorConfig *virustotal_config = state[0];
    IntegratorConfig *pagerduty_config = state[1];

    os_free(virustotal_config->path);
    os_free(pagerduty_config->path);

    os_free(virustotal_config);
    os_free(pagerduty_config);

    return OS_SUCCESS;
}

void test_OS_IntegratorD(void **state) {
    IntegratorConfig *integrator_config[3];
    integrator_config[0] = state[0];
    integrator_config[1] = state[1];
    integrator_config[2] = NULL;

    wfd_t *wfd = NULL;
    os_calloc(1, sizeof(wfd_t), wfd);
    wfd->file_out = (FILE *)1;

    const char *al_string = "{\"timestamp\":\"2022-09-09T23:43:15.168+0200\",\"rule\":{\"level\":7,\"description\":\"Integrity checksum changed.\",\"id\":\"550\",\"mitre\":{\"id\":[\"T1565.001\"],\"tactic\":[\"Impact\"],\"technique\":[\"Stored Data Manipulation\"]},\"firedtimes\":2,\"mail\":false,\"groups\":[\"ossec\",\"syscheck\",\"syscheck_entry_modified\",\"syscheck_file\"],\"pci_dss\":[\"11.5\"],\"gpg13\":[\"4.11\"],\"gdpr\":[\"II_5.1.f\"],\"hipaa\":[\"164.312.c.1\",\"164.312.c.2\"],\"nist_800_53\":[\"SI.7\"],\"tsc\":[\"PI1.4\",\"PI1.5\",\"CC6.1\",\"CC6.8\",\"CC7.2\",\"CC7.3\"]},\"agent\":{\"id\":\"000\",\"name\":\"jellyfish\"},\"manager\":{\"name\":\"jellyfish\"},\"id\":\"1662759795.647670\",\"cluster\":{\"name\":\"wazuh\",\"node\":\"node01\"},\"full_log\":\"File '/tmp/test/test.txt' modified\nMode: realtime\nChanged attributes: size,mtime,md5,sha1,sha256\nSize changed from '54' to '57'\nOld modification time was: '1662759745', now it is '1662759795'\nOld md5sum was: '1e6f0765ec3e57572afde86319d460bf'\nNew md5sum is : '5192496b8adc2f0d705ca01bf3b4adba'\nOld sha1sum was: '652c1e4a301df0d1e7236689cb1e0bd071f2ea14'\nNew sha1sum is : 'dc090d4e165df77333ccf6adaf0d4f96541fb22b'\nOld sha256sum was: '1b32b746fe70a01ddd274f6b71bfaffd8a7fcd8023e18516078f31184da1135c'\nNew sha256sum is : '5583bbc9f63d24e44bbe34298d2f8421da25cdaada00e6c9ac765a16ded4204b'\n\",\"syscheck\":{\"path\":\"/tmp/test/test.txt\",\"mode\":\"realtime\",\"size_before\":\"54\",\"size_after\":\"57\",\"perm_after\":\"rw-r--r--\",\"uid_after\":\"0\",\"gid_after\":\"0\",\"md5_before\":\"1e6f0765ec3e57572afde86319d460bf\",\"md5_after\":\"5192496b8adc2f0d705ca01bf3b4adba\",\"sha1_before\":\"652c1e4a301df0d1e7236689cb1e0bd071f2ea14\",\"sha1_after\":\"dc090d4e165df77333ccf6adaf0d4f96541fb22b\",\"sha256_before\":\"1b32b746fe70a01ddd274f6b71bfaffd8a7fcd8023e18516078f31184da1135c\",\"sha256_after\":\"5583bbc9f63d24e44bbe34298d2f8421da25cdaada00e6c9ac765a16ded4204b\",\"uname_after\":\"root\",\"gname_after\":\"root\",\"mtime_before\":\"2022-09-09T23:42:25\",\"mtime_after\":\"2022-09-09T23:43:15\",\"inode_after\":2362547,\"changed_attributes\":[\"size\",\"mtime\",\"md5\",\"sha1\",\"sha256\"],\"event\":\"modified\"},\"decoder\":{\"name\":\"syscheck_integrity_changed\"},\"location\":\"syscheck\"}";
    const char *op_string = "{\"location\":\"syscheck-X\"}";

    cJSON *al_json = NULL;
    cJSON *op_json = NULL;
    al_json = cJSON_Parse(al_string);
    op_json = cJSON_Parse(op_string);
    char *unformatted = cJSON_PrintUnformatted(al_json);
    char *op_unformatted = cJSON_PrintUnformatted(op_json);
    char alert_to_virustotal[2048];
    char alert_to_pagerduty[2048];
    char options_to_pd[512];
    snprintf(alert_to_virustotal, 2048, "%s\n",unformatted);
    snprintf(alert_to_pagerduty, 2048, "%s\n",unformatted);
    snprintf(options_to_pd, 512, "%s\n",op_unformatted);

    const char *virustotal_file = "/tmp/virustotal-1111-2222.alert";
    const char *pagerduty_file = "/tmp/pagerduty-1111-2222.alert";

    const char *pd_options = "/tmp/pagerduty-1111-2222.options";

    will_return(__wrap_jqueue_open, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "JSON file queue connected.");

    expect_string(__wrap_File_DateofChange, file, "integrations/virustotal");
    will_return(__wrap_File_DateofChange, 1);

    expect_string(__wrap__minfo, formatted_msg, "Enabling integration for: 'virustotal'.");

    expect_string(__wrap_File_DateofChange, file, "integrations/pagerduty");
    will_return(__wrap_File_DateofChange, 1);

    expect_string(__wrap__minfo, formatted_msg, "Enabling integration for: 'pagerduty'.");

    will_return(__wrap_FOREVER, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "jqueue_next()");

    will_return(__wrap_jqueue_next, al_json);

    expect_string(__wrap__mdebug1, formatted_msg, "Sending new alert.");

    will_return(__wrap_time, 1111);

    will_return(__wrap_os_random, 2222);

    expect_string(__wrap_wfopen, path, virustotal_file);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, (FILE *)1);

    expect_fprintf((FILE *)1, alert_to_virustotal, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "File /tmp/virustotal-1111-2222.alert was written.");

    expect_fclose((FILE *)1, 0);

    will_return(__wrap_time, 1111);
    will_return(__wrap_os_random, 2222);

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, "test");

    expect_string(__wrap__mdebug2, formatted_msg, "test");

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, 0);

    will_return(__wrap_wpclose, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Command ran successfully.");

    expect_string(__wrap_unlink, file, virustotal_file);
    will_return(__wrap_unlink, 0);

    will_return(__wrap_time, 1111);
    will_return(__wrap_os_random, 2222);

    expect_string(__wrap_wfopen, path, pagerduty_file);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, (FILE *)1);

    expect_fprintf((FILE *)1, alert_to_pagerduty, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "File /tmp/pagerduty-1111-2222.alert was written.");

    expect_fclose((FILE *)1, 0);

    expect_string(__wrap_wfopen, path, pd_options);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, (FILE *)1);

    expect_fprintf((FILE *)1, options_to_pd, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "File /tmp/pagerduty-1111-2222.options was written.");

    expect_fclose((FILE *)1, 0);

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, "test");

    expect_string(__wrap__mdebug2, formatted_msg, "test");

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, 0);

    will_return(__wrap_wpclose, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Command ran successfully.");

    expect_string(__wrap_unlink, file, pagerduty_file);
    will_return(__wrap_unlink, 0);
    expect_string(__wrap_unlink, file, pd_options);
    will_return(__wrap_unlink, 0);

    will_return(__wrap_FOREVER, NULL);

    OS_IntegratorD(integrator_config);

    os_free(wfd);
    os_free(unformatted);
    os_free(op_unformatted);
    cJSON_Delete(op_json);
}

/* JSON-escaped value with shell metacharacters, a newline and a backslash, and its shell-format result. */
#define SHELL_PAYLOAD "evil'$(id)`id`;a\\nb\\\\c"
#define SHELL_PAYLOAD_SANITIZED "evil  (id) id ,a b/c"

void test_OS_IntegratorD_shell_format_sanitized(__attribute__((unused)) void **state) {
    IntegratorConfig shell_config = { .name = "custom-shell", .enabled = 1, .max_log = 165 };
    IntegratorConfig *integrator_config[2] = { &shell_config, NULL };

    wfd_t *wfd = NULL;
    os_calloc(1, sizeof(wfd_t), wfd);
    wfd->file_out = (FILE *)1;

    const char *al_string = "{\"timestamp\":\"2022-09-09T23:43:15.168+0200\",\"rule\":{\"level\":5,\"description\":\"desc-" SHELL_PAYLOAD "\",\"id\":\"5760" SHELL_PAYLOAD "\"},\"data\":{\"srcip\":\"10.0.0.5'$(id)\"},\"full_log\":\"log-" SHELL_PAYLOAD "\",\"location\":\"loc-" SHELL_PAYLOAD "\"}";
    const char *alert_to_shell = "alertdate='2022-09-09T23:43:15.168+0200'\n"
                                 "alertlocation='loc-" SHELL_PAYLOAD_SANITIZED "'\n"
                                 "ruleid='5760" SHELL_PAYLOAD_SANITIZED "'\n"
                                 "alertlevel='5'\n"
                                 "ruledescription='desc-" SHELL_PAYLOAD_SANITIZED "'\n"
                                 "alertlog='log-" SHELL_PAYLOAD_SANITIZED "'\n"
                                 "srcip='10.0.0.5   id '";
    const char *shell_file = "/tmp/custom-shell-1111-2222.alert";

    cJSON *al_json = cJSON_Parse(al_string);
    assert_non_null(al_json);

    will_return(__wrap_jqueue_open, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "JSON file queue connected.");

    expect_string(__wrap_File_DateofChange, file, "integrations/custom-shell");
    will_return(__wrap_File_DateofChange, 1);
    expect_string(__wrap__minfo, formatted_msg, "Enabling integration for: 'custom-shell'.");

    will_return(__wrap_FOREVER, 1);
    expect_string(__wrap__mdebug2, formatted_msg, "jqueue_next()");
    will_return(__wrap_jqueue_next, al_json);
    expect_string(__wrap__mdebug1, formatted_msg, "Sending new alert.");

    will_return(__wrap_time, 1111);
    will_return(__wrap_os_random, 2222);

    expect_string(__wrap_wfopen, path, shell_file);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, (FILE *)1);

    expect_fprintf((FILE *)1, alert_to_shell, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "File /tmp/custom-shell-1111-2222.alert was written.");
    expect_fclose((FILE *)1, 0);

    will_return(__wrap_wpopenv, wfd);
    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, 0);
    will_return(__wrap_wpclose, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "Command ran successfully.");

    expect_string(__wrap_unlink, file, shell_file);
    will_return(__wrap_unlink, 0);

    will_return(__wrap_FOREVER, NULL);

    OS_IntegratorD(integrator_config);

    os_free(shell_config.path);
    os_free(wfd);
}

void test_OS_IntegratorD_shell_format_keeps_alert(void **state) {
    /* Below the configurable minimum to exercise the truncation with a short log. */
    IntegratorConfig shell_config = { .name = "custom-shell", .enabled = 1, .max_log = 20 };
    IntegratorConfig *integrator_config[3] = { &shell_config, state[0], NULL };

    wfd_t *wfd = NULL;
    os_calloc(1, sizeof(wfd_t), wfd);
    wfd->file_out = (FILE *)1;

    const char *al_string = "{\"timestamp\":\"2022-09-09T23:43:15.168+0200\",\"rule\":{\"level\":5,\"description\":\"Integrity checksum changed.\",\"id\":\"550\",\"groups\":[\"syscheck\"]},\"data\":{\"srcip\":\"10.0.0.5'$(id)\"},\"full_log\":\"log-" SHELL_PAYLOAD "\",\"location\":\"loc-" SHELL_PAYLOAD "\"}";
    const char *alert_to_shell = "alertdate='2022-09-09T23:43:15.168+0200'\n"
                                 "alertlocation='loc-" SHELL_PAYLOAD_SANITIZED "'\n"
                                 "ruleid='550'\n"
                                 "alertlevel='5'\n"
                                 "ruledescription='Integrity checksum changed.'\n"
                                 "alertlog='log-evil  (id) id...'\n"
                                 "srcip='10.0.0.5   id '";
    const char *shell_file = "/tmp/custom-shell-1111-2222.alert";
    const char *virustotal_file = "/tmp/virustotal-3333-4444.alert";

    cJSON *al_json = cJSON_Parse(al_string);
    assert_non_null(al_json);
    char *unformatted = cJSON_PrintUnformatted(al_json);
    char alert_to_virustotal[2048];
    snprintf(alert_to_virustotal, 2048, "%s\n", unformatted);

    will_return(__wrap_jqueue_open, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "JSON file queue connected.");

    expect_string(__wrap_File_DateofChange, file, "integrations/custom-shell");
    will_return(__wrap_File_DateofChange, 1);
    expect_string(__wrap__minfo, formatted_msg, "Enabling integration for: 'custom-shell'.");

    expect_string(__wrap_File_DateofChange, file, "integrations/virustotal");
    will_return(__wrap_File_DateofChange, 1);
    expect_string(__wrap__minfo, formatted_msg, "Enabling integration for: 'virustotal'.");

    will_return(__wrap_FOREVER, 1);
    expect_string(__wrap__mdebug2, formatted_msg, "jqueue_next()");
    will_return(__wrap_jqueue_next, al_json);
    expect_string(__wrap__mdebug1, formatted_msg, "Sending new alert.");

    will_return(__wrap_time, 1111);
    will_return(__wrap_os_random, 2222);

    expect_string(__wrap_wfopen, path, shell_file);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, (FILE *)1);

    expect_fprintf((FILE *)1, alert_to_shell, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "File /tmp/custom-shell-1111-2222.alert was written.");
    expect_fclose((FILE *)1, 0);

    will_return(__wrap_wpopenv, wfd);
    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, 0);
    will_return(__wrap_wpclose, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "Command ran successfully.");

    expect_string(__wrap_unlink, file, shell_file);
    will_return(__wrap_unlink, 0);

    will_return(__wrap_time, 3333);
    will_return(__wrap_os_random, 4444);

    expect_string(__wrap_wfopen, path, virustotal_file);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, (FILE *)1);

    expect_fprintf((FILE *)1, alert_to_virustotal, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "File /tmp/virustotal-3333-4444.alert was written.");
    expect_fclose((FILE *)1, 0);

    will_return(__wrap_wpopenv, wfd);
    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, 0);
    will_return(__wrap_wpclose, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "Command ran successfully.");

    expect_string(__wrap_unlink, file, virustotal_file);
    will_return(__wrap_unlink, 0);

    will_return(__wrap_FOREVER, NULL);

    OS_IntegratorD(integrator_config);

    os_free(shell_config.path);
    os_free(wfd);
    os_free(unformatted);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_OS_IntegratorD, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_IntegratorD_shell_format_sanitized, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_OS_IntegratorD_shell_format_keeps_alert, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
