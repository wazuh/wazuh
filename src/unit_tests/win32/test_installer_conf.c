/*
 * Copyright (C) Wazuh Inc.
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
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../win32/installer/installer_conf.h"

#define PLACEHOLDER_CONF                                       \
    "<ossec_config>\r\n"                                       \
    "  <agent>\r\n"                                            \
    "    <manager>\r\n"                                        \
    "      <endpoint>IP:1517/wazuh-manager/</endpoint>\r\n"   \
    "    </manager>\r\n"                                       \
    "  </agent>\r\n"                                           \
    "</ossec_config>"

#define LEGACY_CONF                                 \
    "<ossec_config>\r\n"                            \
    "  <client>\r\n"                                \
    "    <server>\r\n"                              \
    "      <address>MANAGER_IP</address>\r\n"      \
    "      <port>1514</port>\r\n"                   \
    "    </server>\r\n"                             \
    "  </client>\r\n"                               \
    "</ossec_config>"

#define TOKEN "eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbCJ9"
#define ADR "ver: 1|adr: siem.example.local|credential: present"

static const char *const FIELD_NAMES[CAD_FIELDS] = {
    "APPLICATIONFOLDER", "OS_VERSION", "WAZUH_ENROLLMENT_TOKEN", "WAZUH_AGENT_NAME", "WAZUH_AGENT_GROUP",
    "WAZUH_KEEP_ALIVE_INTERVAL", "WAZUH_TIME_RECONNECT", "ENROLLMENT_DELAY", "WAZUH_SSL_VERIFICATION", "WAZUH_MANAGER",
    "WAZUH_MANAGER_PORT", "WAZUH_MANAGER_ENDPOINT", "WAZUH_REGISTRATION_SERVER", "WAZUH_REGISTRATION_PORT",
    "WAZUH_REGISTRATION_PASSWORD", "WAZUH_REGISTRATION_CA", "WAZUH_REGISTRATION_CERTIFICATE", "WAZUH_REGISTRATION_KEY",
    "SSL_VERIFICATION", "ADDRESS", "SERVER_PORT", "AUTHD_SERVER", "AUTHD_PORT", "PASSWORD", "CERTIFICATE", "PEM", "KEY"};

static char home[MAX_PATH];

/* This executable also plays wazuh-agent.exe for the installer, driven by STUB_* variables. */
static int run_as_agent_stub(int argc, char **argv)
{
    const char *status = getenv("STUB_STATUS");
    char buffer[4096];

    if (argc > 1 && !strcmp(argv[1], "--show-token")) {
        const char *out = getenv("STUB_OUTPUT");

        while (fread(buffer, 1, sizeof(buffer), stdin) > 0)
            ;
        for (; out && *out; out++) {
            putchar(*out == '|' ? '\n' : *out);
        }
        fflush(stdout);
        exit(status ? atoi(status) : 0);
    }
    if (argc > 1 && !strcmp(argv[1], "--shred-enrollment-password")) {
        const char *removes = getenv("STUB_REMOVES");

        if (removes && !strcmp(removes, "1")) {
            char path[MAX_PATH];
            char *slash;

            GetModuleFileNameA(NULL, path, MAX_PATH);
            if ((slash = strrchr(path, '\\'))) {
                strcpy(slash + 1, "authd.pass");
                DeleteFileA(path);
            }
        }
        exit(status ? atoi(status) : 0);
    }
    return 0;
}

static char *read_all(const char *name)
{
    char path[MAX_PATH];
    FILE *fp;
    char *data;
    long size;

    snprintf(path, sizeof(path), "%s%s", home, name);
    if (!(fp = fopen(path, "rb"))) {
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    data = calloc(size + 1, 1);
    fread(data, 1, size, fp);
    fclose(fp);
    return data;
}

static int has(const char *name, const char *needle)
{
    char *text = read_all(name);
    int found = text && strstr(text, needle);

    free(text);
    return found;
}

static int exists(const char *name)
{
    char path[MAX_PATH];

    snprintf(path, sizeof(path), "%s%s", home, name);
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static void write_all(const char *name, const char *text)
{
    char path[MAX_PATH];
    FILE *fp;

    snprintf(path, sizeof(path), "%s%s", home, name);
    fp = fopen(path, "wb");
    fputs(text, fp);
    fclose(fp);
}

static void remove_home(void)
{
    char cmd[MAX_PATH + 32];

    snprintf(cmd, sizeof(cmd), "cmd /c rmdir /s /q \"%s\"", home);
    system(cmd);
}

/* A throwaway install folder holding conf and a stub decoder that prints output and exits status. */
static void make_home(const char *output, int status, const char *conf)
{
    static int n;
    char self[MAX_PATH];
    char agent[MAX_PATH];
    char code[16];

    GetTempPathA(MAX_PATH, home);
    snprintf(home + strlen(home), MAX_PATH - strlen(home), "installer_conf_%lu_%d\\", GetCurrentProcessId(), n++);
    CreateDirectoryA(home, NULL);
    write_all("ossec.conf", conf);
    GetModuleFileNameA(NULL, self, MAX_PATH);
    snprintf(agent, sizeof(agent), "%swazuh-agent.exe", home);
    CopyFileA(self, agent, FALSE);
    snprintf(code, sizeof(code), "%d", status);
    SetEnvironmentVariableA("STUB_OUTPUT", output);
    SetEnvironmentVariableA("STUB_STATUS", code);
}

/* CustomActionData with only the named fields set. */
static wchar_t *payload(const char *token, const char *name, const char *ssl, const char *field, const char *value)
{
    char cad[4096] = "";
    wchar_t *wide;
    int i;

    for (i = 0; i < CAD_FIELDS; i++) {
        const char *v = "";

        if (i == CAD_HOME_DIR) {
            v = home;
        } else if (i == CAD_OS_VERSION) {
            v = "10";
        } else if (i == CAD_ENROLLMENT_TOKEN) {
            v = token;
        } else if (i == CAD_AGENT_NAME) {
            v = name;
        } else if (i == CAD_SSL_VERIFICATION) {
            v = ssl;
        }
        if (field && !strcmp(field, FIELD_NAMES[i])) {
            v = value;
        }
        snprintf(cad + strlen(cad), sizeof(cad) - strlen(cad), "%s\"%s\"", i ? "/+/" : "", v);
    }
    wide = calloc(strlen(cad) + 1, sizeof(*wide));
    MultiByteToWideChar(CP_ACP, 0, cad, -1, wide, (int)strlen(cad) + 1);
    return wide;
}

static int config(const char *token, const char *name, const char *ssl, const char *field, const char *value)
{
    wchar_t *cad = payload(token, name, ssl, field, value);
    int rc = installer_config(cad);

    free(cad);
    return rc;
}

static void test_token_alone(void **state)
{
    char *token;

    (void)state;
    make_home(ADR, 0, PLACEHOLDER_CONF);
    assert_int_equal(config(TOKEN, "", "", NULL, NULL), 0);
    assert_true(has("ossec.conf", "<endpoint>siem.example.local</endpoint>"));
    token = read_all("enrollment_token");
    assert_string_equal(token, TOKEN);
    free(token);
    assert_false(exists("authd.pass"));
    assert_true(has("ossec.log", "Enrollment token stored; the manager was set to 'siem.example.local'"));
    remove_home();
}

static void test_token_without_credential(void **state)
{
    (void)state;
    make_home("ver: 1|adr: siem.example.local|credential: absent", 0, PLACEHOLDER_CONF);
    assert_int_equal(config(TOKEN, "", "", NULL, NULL), 0);
    assert_true(has("ossec.conf", "<endpoint>siem.example.local</endpoint>"));
    remove_home();
}

static void test_token_refused(void **state)
{
    (void)state;
    make_home("", 2, PLACEHOLDER_CONF);
    assert_int_equal(config(TOKEN, "", "", NULL, NULL), 0);
    assert_true(has("ossec.log", "ERR_BAD_TOKEN"));
    assert_true(has("ossec.conf", "<endpoint>IP:1517/wazuh-manager/</endpoint>"));
    assert_false(exists("enrollment_token"));
    remove_home();
}

static void test_token_without_address(void **state)
{
    (void)state;
    make_home("ver: 1|credential: absent", 0, PLACEHOLDER_CONF);
    assert_int_equal(config(TOKEN, "", "", NULL, NULL), 0);
    assert_true(has("ossec.log", "ERR_BAD_TOKEN"));
    assert_false(exists("enrollment_token"));
    remove_home();
}

static void test_decoder_missing(void **state)
{
    char agent[MAX_PATH];

    (void)state;
    make_home(ADR, 0, PLACEHOLDER_CONF);
    snprintf(agent, sizeof(agent), "%swazuh-agent.exe", home);
    DeleteFileA(agent);
    assert_int_equal(config(TOKEN, "", "", NULL, NULL), 0);
    assert_true(has("ossec.log", "[ERR_NO_DECODER]: could not run wazuh-agent.exe --show-token (exit 127)"));
    assert_false(exists("enrollment_token"));
    remove_home();
}

static void test_token_with_modes(void **state)
{
    static const char *const modes[] = {"full", "certificate", "system", "none"};
    size_t i;

    (void)state;
    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        char tag[64];

        make_home(ADR, 0, PLACEHOLDER_CONF);
        assert_int_equal(config(TOKEN, "", modes[i], NULL, NULL), 0);
        snprintf(tag, sizeof(tag), "<verification_mode>%s</verification_mode>", modes[i]);
        assert_true(has("ossec.conf", "<endpoint>siem.example.local</endpoint>"));
        assert_true(has("ossec.conf", tag));
        assert_true(exists("enrollment_token"));
        remove_home();
    }
}

static void test_no_token(void **state)
{
    (void)state;
    make_home(ADR, 0, PLACEHOLDER_CONF);
    assert_int_equal(config("", "", "", NULL, NULL), 0);
    assert_true(has("ossec.log", "INFO_NO_MANAGER"));
    assert_true(has("ossec.log", "Manage > Enroll in the agent GUI"));
    assert_true(has("ossec.conf", "<endpoint>IP:1517/wazuh-manager/</endpoint>"));
    assert_false(exists("enrollment_token"));
    remove_home();
}

static void test_log_timestamp(void **state)
{
    char *log;
    int y, mo, d, h, mi, s;
    char c;

    (void)state;
    make_home(ADR, 0, PLACEHOLDER_CONF);
    assert_int_equal(config("", "", "", NULL, NULL), 0);
    log = read_all("ossec.log");
    assert_non_null(log);
    assert_int_equal(sscanf(log, "%4d/%2d/%2d %2d:%2d:%2d%c", &y, &mo, &d, &h, &mi, &s, &c), 7);
    assert_int_equal(c, ' ');
    assert_non_null(strstr(log, "\r\n"));
    free(log);
    remove_home();
}

static void test_no_token_still_applies_settings(void **state)
{
    (void)state;
    make_home(ADR, 0, PLACEHOLDER_CONF);
    assert_int_equal(config("", "hand-configured", "system", NULL, NULL), 0);
    assert_true(has("ossec.conf", "<agent_name>hand-configured</agent_name>"));
    assert_true(has("ossec.conf", "<verification_mode>system</verification_mode>"));
    remove_home();
}

static void test_legacy_file(void **state)
{
    (void)state;
    make_home(ADR, 0, LEGACY_CONF);
    assert_int_equal(config(TOKEN, "", "", NULL, NULL), 0);
    assert_true(has("ossec.conf", "<server>\r\n      <endpoint>siem.example.local</endpoint>\r\n    </server>"));
    assert_false(has("ossec.conf", "<manager>"));
    assert_false(has("ossec.conf", "<port>1514</port>"));
    remove_home();
}

static void test_removed_names(void **state)
{
    int i;

    (void)state;
    for (i = CAD_MANAGER; i < CAD_FIELDS; i++) {
        char line[128];

        make_home(ADR, 0, PLACEHOLDER_CONF);
        assert_int_equal(config(TOKEN, "", "", FIELD_NAMES[i], "some-value"), 0);
        if (i == CAD_SSL_VERIFICATION_OLD) {
            assert_true(has("ossec.log", "renamed to WAZUH_SSL_VERIFICATION; the old name is not read."));
            assert_false(has("ossec.conf", "<verification_mode>"));
        } else {
            /* Anchored on the leading space, so KEY is not satisfied by WAZUH_REGISTRATION_KEY. */
            snprintf(line, sizeof(line), " %s is not supported in 5.0", FIELD_NAMES[i]);
            assert_true(has("ossec.log", line));
        }
        remove_home();
    }
}

static void test_xml_escaped_address(void **state)
{
    (void)state;
    make_home("adr: a&b<c>", 0, PLACEHOLDER_CONF);
    assert_int_equal(config(TOKEN, "", "", NULL, NULL), 0);
    assert_true(has("ossec.conf", "<endpoint>a&amp;b&lt;c&gt;</endpoint>"));
    remove_home();
}

static void test_missing_ossec_conf(void **state)
{
    char path[MAX_PATH];

    (void)state;
    make_home(ADR, 0, PLACEHOLDER_CONF);
    snprintf(path, sizeof(path), "%sossec.conf", home);
    DeleteFileA(path);
    assert_int_equal(config("", "", "", NULL, NULL), -1);
    assert_true(exists("client.keys"));
    remove_home();
}

static char empty[] = "";

static void ignore_log(void *ctx, const char *message)
{
    (void)ctx;
    (void)message;
}

static void test_mode_existing_and_commented(void **state)
{
    static const char conf[] = "  <agent>\r\n"
                               "    <ssl>\r\n"
                               "      <!-- <verification_mode>full</verification_mode> -->\r\n"
                               "      <verification_mode>full</verification_mode>\r\n"
                               "    </ssl>\r\n"
                               "  </agent>";
    char *value[CAD_FIELDS];
    char *text;
    int i;

    (void)state;
    for (i = 0; i < CAD_FIELDS; i++) {
        value[i] = empty;
    }
    value[CAD_SSL_VERIFICATION] = "none";
    text = installer_apply_deployment(conf, value, NULL, ignore_log, NULL);
    assert_non_null(strstr(text, "<!-- <verification_mode>full</verification_mode> -->\r\n      <verification_mode>none</verification_mode>"));
    free(text);
}

static void test_mode_self_closing_and_ssl_block(void **state)
{
    char *value[CAD_FIELDS];
    char *text;
    int i;

    (void)state;
    for (i = 0; i < CAD_FIELDS; i++) {
        value[i] = empty;
    }
    value[CAD_SSL_VERIFICATION] = "system";
    text = installer_apply_deployment("  <agent>\r\n    <ssl>\r\n      <verification_mode/>\r\n    </ssl>\r\n  </agent>", value,
                                      NULL, ignore_log, NULL);
    assert_non_null(strstr(text, "      <verification_mode>system</verification_mode>\r\n    </ssl>"));
    free(text);

    text = installer_apply_deployment("  <agent>\r\n    <ssl>\r\n    </ssl>\r\n  </agent>", value, NULL, ignore_log, NULL);
    assert_string_equal(text, "  <agent>\r\n    <ssl>\r\n      <verification_mode>system</verification_mode>\r\n    </ssl>\r\n  </agent>");
    free(text);

    text = installer_apply_deployment("  <agent>\r\n  </agent>", value, NULL, ignore_log, NULL);
    assert_string_equal(text, "  <agent>\r\n    <ssl>\r\n      <verification_mode>system</verification_mode>\r\n    </ssl>\r\n  </agent>\r\n");
    free(text);
}

static int invalid_logged;

static void count_log(void *ctx, const char *message)
{
    (void)ctx;
    invalid_logged += strstr(message, "Invalid WAZUH_SSL_VERIFICATION 'System'") != NULL;
}

static void test_mode_invalid(void **state)
{
    char *value[CAD_FIELDS];
    char *text;
    int i;

    (void)state;
    for (i = 0; i < CAD_FIELDS; i++) {
        value[i] = empty;
    }
    value[CAD_SSL_VERIFICATION] = "System";
    text = installer_apply_deployment(PLACEHOLDER_CONF, value, NULL, count_log, NULL);
    assert_string_equal(text, PLACEHOLDER_CONF);
    assert_int_equal(invalid_logged, 1);
    free(text);
}

static void test_intervals_and_enrollment(void **state)
{
    char *value[CAD_FIELDS];
    char *text;
    int i;

    (void)state;
    for (i = 0; i < CAD_FIELDS; i++) {
        value[i] = empty;
    }
    value[CAD_KEEP_ALIVE] = "30";
    value[CAD_TIME_RECONNECT] = "120";
    value[CAD_AGENT_GROUP] = "g1,g2";
    value[CAD_ENROLLMENT_DELAY] = "5";
    text = installer_apply_deployment("  <agent>\r\n    <time-reconnect>60</time-reconnect>\r\n  </agent>", value, NULL,
                                      ignore_log, NULL);
    assert_string_equal(text, "  <agent>\r\n"
                              "    <time-reconnect>120</time-reconnect>\r\n"
                              "    <notify_time>30</notify_time>\r\n"
                              "    <enrollment>\r\n"
                              "      <enabled>yes</enabled>\r\n"
                              "      <groups>g1,g2</groups>\r\n"
                              "      <delay_after_enrollment>5</delay_after_enrollment>\r\n"
                              "    </enrollment>\r\n"
                              "  </agent>\r\n");
    free(text);
}

static void test_templates(void **state)
{
    char *text;

    (void)state;
    text = installer_apply_templates(PLACEHOLDER_CONF, "<config-profile>windows</config-profile>");
    assert_non_null(strstr(text, "    </manager>\r\n    <config-profile>windows</config-profile>\r\n  </agent>"));
    free(text);
    text = installer_apply_templates(LEGACY_CONF, "<config-profile>windows</config-profile>");
    assert_non_null(strstr(text, "    </server>\r\n    <config-profile>windows</config-profile>\r\n  </client>"));
    free(text);
    text = installer_apply_templates(PLACEHOLDER_CONF, NULL);
    assert_string_equal(text, PLACEHOLDER_CONF);
    free(text);
}

static void shred(const char *removes, int status, int with_agent)
{
    wchar_t whome[MAX_PATH];

    make_home("", status, PLACEHOLDER_CONF);
    SetEnvironmentVariableA("STUB_REMOVES", removes);
    if (!with_agent) {
        char agent[MAX_PATH];

        snprintf(agent, sizeof(agent), "%swazuh-agent.exe", home);
        DeleteFileA(agent);
    }
    write_all("authd.pass", "S3cr3t-fleet-pw");
    MultiByteToWideChar(CP_ACP, 0, home, -1, whome, MAX_PATH);
    installer_remove_fleet_password(whome);
}

static void test_fleet_password(void **state)
{
    (void)state;
    shred("1", 0, 1);
    assert_false(exists("authd.pass"));
    remove_home();

    /* An agent that reports success is believed. */
    shred("0", 0, 1);
    assert_true(exists("authd.pass"));
    remove_home();

    shred("0", 1, 1);
    assert_false(exists("authd.pass"));
    remove_home();

    shred("0", 0, 0);
    assert_false(exists("authd.pass"));
    remove_home();
}

static void test_cleanup_legacy_databases(void **state)
{
    wchar_t whome[MAX_PATH];
    char dir[MAX_PATH];

    (void)state;
    make_home("", 0, PLACEHOLDER_CONF);
    snprintf(dir, sizeof(dir), "%squeue", home);
    CreateDirectoryA(dir, NULL);
    snprintf(dir, sizeof(dir), "%squeue\\fim", home);
    CreateDirectoryA(dir, NULL);
    snprintf(dir, sizeof(dir), "%squeue\\fim\\db", home);
    CreateDirectoryA(dir, NULL);
    write_all("queue\\fim\\db\\fim.db", "db");
    MultiByteToWideChar(CP_ACP, 0, home, -1, whome, MAX_PATH);
    installer_cleanup_legacy_databases(whome);
    assert_false(exists("queue\\fim\\db\\fim.db"));
    remove_home();
}

static void test_pending_conflict(void **state)
{
    static const wchar_t entries[] = L"\\??\\C:\\Temp\\a.tmp\0\0\\??\\c:\\program files (x86)\\OSSEC-AGENT\\x.dll\0\0";
    size_t len = sizeof(entries) / sizeof(entries[0]) - 1;

    (void)state;
    assert_true(!wcscmp(installer_pending_conflict(entries, len, L"C:\\Program Files (x86)\\ossec-agent\\"),
                        L"\\??\\c:\\program files (x86)\\OSSEC-AGENT\\x.dll"));
    assert_null(installer_pending_conflict(entries, len, L"C:\\Other\\"));
}

static void test_remove_all(void **state)
{
    wchar_t whome[MAX_PATH];
    char dir[MAX_PATH];

    (void)state;
    make_home("", 0, PLACEHOLDER_CONF);
    write_all("client.keys", "001 a any k");
    snprintf(dir, sizeof(dir), "%sbackup", home);
    CreateDirectoryA(dir, NULL);
    snprintf(dir, sizeof(dir), "%slogs", home);
    CreateDirectoryA(dir, NULL);
    write_all("logs\\ossec.log", "x");
    MultiByteToWideChar(CP_ACP, 0, home, -1, whome, MAX_PATH);
    assert_int_equal(installer_remove_all(whome), 0);
    assert_true(exists("ossec.conf.save"));
    assert_true(exists("client.keys.save"));
    assert_true(exists("backup"));
    assert_false(exists("ossec.conf"));
    assert_false(exists("wazuh-agent.exe"));
    assert_false(exists("logs"));
    remove_home();
}

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_token_alone),
        cmocka_unit_test(test_token_without_credential),
        cmocka_unit_test(test_token_refused),
        cmocka_unit_test(test_token_without_address),
        cmocka_unit_test(test_decoder_missing),
        cmocka_unit_test(test_token_with_modes),
        cmocka_unit_test(test_no_token),
        cmocka_unit_test(test_log_timestamp),
        cmocka_unit_test(test_no_token_still_applies_settings),
        cmocka_unit_test(test_legacy_file),
        cmocka_unit_test(test_removed_names),
        cmocka_unit_test(test_xml_escaped_address),
        cmocka_unit_test(test_missing_ossec_conf),
        cmocka_unit_test(test_mode_existing_and_commented),
        cmocka_unit_test(test_mode_self_closing_and_ssl_block),
        cmocka_unit_test(test_mode_invalid),
        cmocka_unit_test(test_intervals_and_enrollment),
        cmocka_unit_test(test_templates),
        cmocka_unit_test(test_fleet_password),
        cmocka_unit_test(test_cleanup_legacy_databases),
        cmocka_unit_test(test_pending_conflict),
        cmocka_unit_test(test_remove_all),
    };

    run_as_agent_stub(argc, argv);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
