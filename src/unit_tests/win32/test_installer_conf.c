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
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../win32/installer/installer_conf.h"

#define CONF                                      \
    "<ossec_config>\r\n"                          \
    "  <client>\r\n"                              \
    "    <server>\r\n"                            \
    "      <address>0.0.0.0</address>\r\n"       \
    "      <port>1514</port>\r\n"                 \
    "      <protocol>tcp</protocol>\r\n"          \
    "    </server>\r\n"                           \
    "    <notify_time>10</notify_time>\r\n"       \
    "    <time-reconnect>60</time-reconnect>\r\n" \
    "  </client>\r\n"                             \
    "  <syscheck>\r\n"                            \
    "    <frequency>43200</frequency>\r\n"        \
    "  </syscheck>\r\n"                           \
    "</ossec_config>\r\n"

static char empty[] = "";

static void clear_values(char *value[CAD_FIELDS]) {
    int i;

    for (i = 0; i < CAD_FIELDS; i++) {
        value[i] = empty;
    }
}

static char *read_all(const char *path) {
    FILE *fp = fopen(path, "rb");
    char *data;
    long size;

    if (!fp) {
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

static void write_all(const char *path, const char *text) {
    FILE *fp = fopen(path, "wb");

    fputs(text, fp);
    fclose(fp);
}

static void test_cad_field(void **state) {
    wchar_t *field;

    (void)state;
    field = installer_cad_field(L"\"C:\\dir\\\"/+/\"10\"/+/\"a\"b\"", L"/+/", 2);
    assert_non_null(field);
    assert_true(!wcscmp(field, L"ab"));
    free(field);

    field = installer_cad_field(L"\"C:\\dir\\\"/+/\"10\"", L"/+/", 0);
    assert_true(!wcscmp(field, L"C:\\dir\\"));
    free(field);

    assert_null(installer_cad_field(L"\"a\"/+/\"b\"", L"/+/", 2));
}

static void test_cad_field_whole_path(void **state) {
    wchar_t *field = installer_cad_field(L"\"C:\\Program Files, x\\ossec-agent\\\"", NULL, 0);

    (void)state;
    assert_true(!wcscmp(field, L"C:\\Program Files, x\\ossec-agent\\"));
    free(field);
}

static void test_deployment_nothing_set(void **state) {
    char *value[CAD_FIELDS];
    char *text;

    (void)state;
    clear_values(value);
    text = installer_apply_deployment(CONF, value);
    assert_string_equal(text, CONF);
    free(text);
}

static void test_deployment_managers(void **state) {
    char *value[CAD_FIELDS];
    char *text;

    (void)state;
    clear_values(value);
    value[CAD_MANAGER] = "m1,m2,m1";
    value[CAD_PROTOCOL] = "UDP,TCP";
    text = installer_apply_deployment(CONF, value);
    assert_non_null(strstr(text, "  <client>\r\n"
                                 "    <server>\r\n      <address>m1</address>\r\n      <port>1514</port>\r\n"
                                 "      <protocol>udp</protocol>\r\n    </server>\r\n"
                                 "    <server>\r\n      <address>m2</address>\r\n      <port>1514</port>\r\n"
                                 "      <protocol>tcp</protocol>\r\n    </server>\r\n"
                                 "    <server>\r\n      <address>m1</address>\r\n      <port>1514</port>\r\n"
                                 "      <protocol>tcp</protocol>\r\n    </server>\r\n"
                                 "    <notify_time>"));
    assert_null(strstr(text, "0.0.0.0"));
    free(text);
}

static void test_deployment_managers_unique_with_tcp(void **state) {
    char *value[CAD_FIELDS];
    char *text;

    (void)state;
    clear_values(value);
    value[CAD_MANAGER] = "m1,m1";
    value[CAD_MANAGER_PORT] = "1515";
    text = installer_apply_deployment(CONF, value);
    assert_non_null(strstr(text, "<address>m1</address>\r\n      <port>1515</port>\r\n      <protocol>tcp</protocol>\r\n"
                                 "    </server>\r\n    <notify_time>"));
    assert_null(strstr(text, "1514"));
    free(text);
}

static void test_deployment_protocol_only(void **state) {
    char *value[CAD_FIELDS];
    char *text;

    (void)state;
    clear_values(value);
    value[CAD_PROTOCOL] = "UDP";
    text = installer_apply_deployment(CONF, value);
    assert_non_null(strstr(text, "<address>0.0.0.0</address>"));
    assert_non_null(strstr(text, "            <protocol>udp</protocol>\r\n"));
    free(text);
}

static void test_deployment_intervals(void **state) {
    char *value[CAD_FIELDS];
    char *text;

    (void)state;
    clear_values(value);
    value[CAD_KEEP_ALIVE] = "30";
    value[CAD_TIME_RECONNECT] = "120";
    value[CAD_NOTIFY_TIME] = "99";
    text = installer_apply_deployment(CONF, value);
    assert_non_null(strstr(text, "<notify_time>30</notify_time>"));
    assert_non_null(strstr(text, "<time-reconnect>120</time-reconnect>"));
    assert_null(strstr(text, "99"));
    free(text);
}

static void test_deployment_enrollment(void **state) {
    char *value[CAD_FIELDS];
    char *text;

    (void)state;
    clear_values(value);
    value[CAD_REG_SERVER] = "auth";
    value[CAD_REG_PASSWORD] = "secret";
    value[CAD_AGENT_NAME] = "agent-01";
    value[CAD_AGENT_GROUP] = "g1,g2";
    text = installer_apply_deployment(CONF, value);
    assert_non_null(strstr(text, "    <enrollment>\r\n      <enabled>yes</enabled>\r\n"
                                 "      <manager_address>auth</manager_address>\r\n"
                                 "      <authorization_pass_path>authd.pass</authorization_pass_path>\r\n"
                                 "      <agent_name>agent-01</agent_name>\r\n"
                                 "      <groups>g1,g2</groups>\r\n"
                                 "    </enrollment>\r\n  </client>\r\n\r\n  <syscheck>"));
    assert_null(strstr(text, "secret"));
    free(text);
}

static void test_templates(void **state) {
    char *text;

    (void)state;
    text = installer_apply_templates(CONF, "<config-profile>windows</config-profile>",
                                     "  <syscheck>\r\n    <disabled>yes</disabled>\r\n  </syscheck>", NULL);
    assert_non_null(strstr(text, "    </server>\r\n    <config-profile>windows</config-profile>\r\n    <notify_time>"));
    assert_non_null(strstr(text, "<disabled>yes</disabled>"));
    assert_null(strstr(text, "43200"));
    free(text);

    text = installer_apply_templates(CONF, NULL, NULL, NULL);
    assert_string_equal(text, CONF);
    free(text);
}

static void test_pending_conflict(void **state) {
    static const wchar_t entries[] = L"\\??\\C:\\Temp\\a.tmp\0\0\\??\\c:\\program files (x86)\\OSSEC-AGENT\\x.dll\0\0";
    size_t len = sizeof(entries) / sizeof(entries[0]) - 1;
    const wchar_t *hit;

    (void)state;
    hit = installer_pending_conflict(entries, len, L"C:\\Program Files (x86)\\ossec-agent\\");
    assert_non_null(hit);
    assert_true(!wcscmp(hit, L"\\??\\c:\\program files (x86)\\OSSEC-AGENT\\x.dll"));
    assert_null(installer_pending_conflict(entries, len, L"C:\\Other\\"));
}

static void make_dir(char *path, const char *name) {
    char root[MAX_PATH];

    GetTempPathA(MAX_PATH, root);
    snprintf(path, MAX_PATH, "%sinstaller_conf_%s_%lu\\", root, name, GetCurrentProcessId());
    CreateDirectoryA(path, NULL);
}

static wchar_t *wide(const char *s) {
    size_t n = strlen(s) + 1;
    wchar_t *w = malloc(n * sizeof(*w));

    MultiByteToWideChar(CP_ACP, 0, s, -1, w, (int)n);
    return w;
}

static void test_config_files(void **state) {
    char dir[MAX_PATH];
    char path[MAX_PATH];
    char cad[2048];
    wchar_t *wcad;
    char *text;

    (void)state;
    make_dir(dir, "config");
    snprintf(path, sizeof(path), "%sossec.conf", dir);
    write_all(path, CONF);
    snprintf(path, sizeof(path), "%sprofile-10.template", dir);
    write_all(path, "<config-profile>windows10</config-profile>");
    snprintf(cad, sizeof(cad),
             "\"%s\"/+/\"10\"/+/\"mgr\"/+/\"\"/+/\"\"/+/\"\"/+/\"\"/+/\"\"/+/\"pass\"/+/\"\"/+/\"\"/+/\"\"/+/\"\"/+/\"\"/+/"
             "\"\"/+/\"\"/+/\"\"",
             dir);
    wcad = wide(cad);
    assert_int_equal(installer_config(wcad), 0);
    free(wcad);

    snprintf(path, sizeof(path), "%sauthd.pass", dir);
    text = read_all(path);
    assert_string_equal(text, "pass\r\n");
    free(text);
    DeleteFileA(path);

    snprintf(path, sizeof(path), "%sclient.keys", dir);
    text = read_all(path);
    assert_string_equal(text, "");
    free(text);
    DeleteFileA(path);

    snprintf(path, sizeof(path), "%sossec.conf", dir);
    text = read_all(path);
    assert_non_null(strstr(text, "<address>mgr</address>"));
    assert_non_null(strstr(text, "    </server>\r\n    <config-profile>windows10</config-profile>\r\n"));
    assert_non_null(strstr(text, "</ossec_config>\r\n\r\n\r\n"));
    free(text);
    DeleteFileA(path);

    snprintf(path, sizeof(path), "%slocal_internal_options.conf", dir);
    text = read_all(path);
    assert_non_null(strstr(text, "# local_internal_options.conf\r\n"));
    free(text);
    DeleteFileA(path);

    snprintf(path, sizeof(path), "%sprofile-10.template", dir);
    DeleteFileA(path);
    RemoveDirectoryA(dir);
}

static void test_config_without_ossec_conf(void **state) {
    char dir[MAX_PATH];
    char path[MAX_PATH];
    char cad[2048];
    wchar_t *wcad;

    (void)state;
    make_dir(dir, "noconf");
    snprintf(cad, sizeof(cad),
             "\"%s\"/+/\"10\"/+/\"\"/+/\"\"/+/\"\"/+/\"\"/+/\"\"/+/\"\"/+/\"\"/+/\"\"/+/\"\"/+/\"\"/+/\"\"/+/"
             "\"\"/+/\"\"/+/\"\"/+/\"\"",
             dir);
    wcad = wide(cad);
    assert_int_equal(installer_config(wcad), -1);
    free(wcad);

    snprintf(path, sizeof(path), "%sclient.keys", dir);
    DeleteFileA(path);
    RemoveDirectoryA(dir);
}

static void test_config_missing_fields(void **state) {
    (void)state;
    assert_int_equal(installer_config(L"\"C:\\dir\\\"/+/\"10\""), -1);
}

static void test_remove_all(void **state) {
    static const char *const created[] = {"ossec.conf", "client.keys", "client.keys.save", "agent.exe", "backup\\", "upgrade\\",
                                          "Backup\\old.txt", "logs\\", "logs\\ossec.log", "logs\\sub\\", "logs\\sub\\a.txt"};
    char dir[MAX_PATH];
    char path[MAX_PATH];
    wchar_t *home;
    char *text;
    size_t i;

    (void)state;
    make_dir(dir, "remove");
    for (i = 0; i < sizeof(created) / sizeof(created[0]); i++) {
        snprintf(path, sizeof(path), "%s%s", dir, created[i]);
        if (path[strlen(path) - 1] == '\\') {
            CreateDirectoryA(path, NULL);
        } else {
            write_all(path, created[i]);
        }
    }
    snprintf(path, sizeof(path), "%sagent.exe", dir);
    SetFileAttributesA(path, FILE_ATTRIBUTE_READONLY);

    home = wide(dir);
    assert_int_equal(installer_remove_all(home), 0);
    free(home);

    snprintf(path, sizeof(path), "%sossec.conf.save", dir);
    text = read_all(path);
    assert_string_equal(text, "ossec.conf");
    free(text);
    DeleteFileA(path);
    snprintf(path, sizeof(path), "%sclient.keys.save", dir);
    text = read_all(path);
    assert_string_equal(text, "client.keys");
    free(text);
    DeleteFileA(path);

    snprintf(path, sizeof(path), "%sossec.conf", dir);
    assert_int_equal(GetFileAttributesA(path), INVALID_FILE_ATTRIBUTES);
    snprintf(path, sizeof(path), "%sagent.exe", dir);
    assert_int_equal(GetFileAttributesA(path), INVALID_FILE_ATTRIBUTES);
    snprintf(path, sizeof(path), "%slogs", dir);
    assert_int_equal(GetFileAttributesA(path), INVALID_FILE_ATTRIBUTES);

    /* "Backup" matches "backup" ignoring case, so its content is kept. */
    snprintf(path, sizeof(path), "%sbackup\\old.txt", dir);
    assert_int_not_equal(GetFileAttributesA(path), INVALID_FILE_ATTRIBUTES);
    DeleteFileA(path);
    snprintf(path, sizeof(path), "%sbackup", dir);
    RemoveDirectoryA(path);
    snprintf(path, sizeof(path), "%supgrade", dir);
    assert_int_not_equal(GetFileAttributesA(path), INVALID_FILE_ATTRIBUTES);
    RemoveDirectoryA(path);
    assert_true(RemoveDirectoryA(dir));
}

/* "C:\" becomes "C:" once the trailing backslash is dropped; a relative folder takes the same no-backslash path. */
static void test_remove_all_drive_root(void **state) {
    char *text;

    (void)state;
    CreateDirectoryA("installer_conf_root", NULL);
    write_all("installer_conf_root\\agent.exe", "agent");
    assert_int_equal(installer_remove_all(L"installer_conf_root\\"), 0);
    text = read_all("installer_conf_root\\agent.exe");
    assert_string_equal(text, "agent");
    free(text);
    DeleteFileA("installer_conf_root\\agent.exe");
    RemoveDirectoryA("installer_conf_root");
    assert_int_equal(installer_remove_all(L""), 0);
}

static void test_is_drive_root(void **state) {
    (void)state;
    assert_int_equal(installer_is_drive_root(L"C:\\"), 1);
    assert_int_equal(installer_is_drive_root(L"D:"), 1);
    assert_int_equal(installer_is_drive_root(L"C:\\Program Files (x86)\\ossec-agent\\"), 0);
    assert_int_equal(installer_is_drive_root(L"C:\\wazuh"), 0);
    assert_int_equal(installer_is_drive_root(L"\\\\server\\share\\"), 0);
}

static void test_wait_exit(void **state) {
    wchar_t self[MAX_PATH];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    const wchar_t *name;
    DWORD n = GetModuleFileNameW(NULL, self, MAX_PATH);

    (void)state;
    assert_true(n > 0 && n < MAX_PATH);
    name = wcsrchr(self, L'\\') ? wcsrchr(self, L'\\') + 1 : self;
    assert_int_equal(installer_wait_exit(name, 0), 0);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    assert_true(CreateProcessW(self, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi));
    assert_int_equal(installer_wait_exit(name, 200), 1);

    TerminateProcess(pi.hProcess, 0);
    assert_int_equal(installer_wait_exit(name, 5000), 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_cad_field),
        cmocka_unit_test(test_cad_field_whole_path),
        cmocka_unit_test(test_deployment_nothing_set),
        cmocka_unit_test(test_deployment_managers),
        cmocka_unit_test(test_deployment_managers_unique_with_tcp),
        cmocka_unit_test(test_deployment_protocol_only),
        cmocka_unit_test(test_deployment_intervals),
        cmocka_unit_test(test_deployment_enrollment),
        cmocka_unit_test(test_templates),
        cmocka_unit_test(test_pending_conflict),
        cmocka_unit_test(test_config_files),
        cmocka_unit_test(test_config_without_ossec_conf),
        cmocka_unit_test(test_config_missing_fields),
        cmocka_unit_test(test_remove_all),
        cmocka_unit_test(test_remove_all_drive_root),
        cmocka_unit_test(test_is_drive_root),
        cmocka_unit_test(test_wait_exit),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
