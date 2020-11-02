/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "../../headers/shared.h"
#include "../../wazuh_modules/wm_task_general.h"

#include "../../wrappers/common.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../../wrappers/wazuh/shared/validate_op_wrappers.h"
#include "../../wrappers/libc/string_wrappers.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"
#include "../../wrappers/externals/zlib/zlib_wrappers.h"

extern int test_mode;

extern size_t __real_strlen(const char *s);

extern int _jailfile(char finalpath[PATH_MAX + 1], const char * basedir, const char * filename);
extern int _unsign(const char * source, char dest[PATH_MAX + 1]);
extern int _uncompress(const char * source, const char *package, char dest[PATH_MAX + 1]);

extern char * wm_agent_upgrade_com_open(const cJSON* json_object);
extern char * wm_agent_upgrade_com_write(const cJSON* json_object);
extern char * wm_agent_upgrade_com_close(const cJSON* json_object);
extern char * wm_agent_upgrade_com_sha1(const cJSON* json_object);
extern char * wm_agent_upgrade_com_upgrade(const cJSON* json_object);

extern struct {char path[PATH_MAX + 1]; FILE * fp;} file;
extern const char * error_messages[];
/* Internal methods tests */

int setup_jailfile(void **state) {
    char *filename = malloc(sizeof(char) * OS_MAXSTR);
    sprintf(filename, "test_filename");
    *state = filename;
    test_mode = 1;
    return 0;
}

int teardown_jailfile(void **state) {
    char *filename = *state;
    test_mode = 0;
    os_free(filename);
    return 0;
}

void test_jailfile_invalid_path(void **state) {
    char finalpath[PATH_MAX + 1];
    char *filename = *state;

    expect_string(__wrap_w_ref_parent_folder, path, filename);
    will_return(__wrap_w_ref_parent_folder, 1);
    int ret = _jailfile(finalpath, TMP_DIR, filename);
    assert_int_equal(ret, -1);
}

void test_jailfile_valid_path(void **state) {
    char finalpath[PATH_MAX + 1];
    char *filename = *state;

    expect_string(__wrap_w_ref_parent_folder, path, filename);
    will_return(__wrap_w_ref_parent_folder, 0);
    int ret = _jailfile(finalpath, TMP_DIR, filename);
    assert_int_equal(ret, 0);
#ifdef TEST_WINAGENT
    assert_string_equal(finalpath, "tmp\\test_filename");
#else
    assert_string_equal(finalpath, "/var/ossec/tmp/test_filename");
#endif
}

void test_unsign_invalid_source_incomming(void **state) {
    char finalpath[PATH_MAX + 1];
    char *source =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 1);
    expect_string(__wrap__merror, formatted_msg, "At unsign(): Invalid file name 'test_filename'");
    int ret = _unsign(source, finalpath);
    assert_int_equal(ret, -1);
}

void test_unsign_invalid_source_temp(void **state) {
    char finalpath[PATH_MAX + 1];
    char *source =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);
    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 1);
    expect_string(__wrap__merror, formatted_msg, "At unsign(): Invalid file name 'test_filename'");
    int ret = _unsign(source, finalpath);
    assert_int_equal(ret, -1);
}

void test_unsign_invalid_source_len(void **state) {
    char finalpath[PATH_MAX + 1];
    char *source =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);
    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);

#ifdef TEST_WINAGENT
    expect_string(__wrap_strlen, s, "tmp\\test_filename");
#else
    expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_filename");
#endif
    will_return(__wrap_strlen, PATH_MAX);
    expect_string(__wrap__merror, formatted_msg, "At unsign(): Too long temp file.");

    int ret = _unsign(source, finalpath);
    assert_int_equal(ret, -1);
}

void test_unsign_temp_file_fail(void **state) {
    char finalpath[PATH_MAX + 1];
    char *source =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);
    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);

#ifdef TEST_WINAGENT
    expect_string(__wrap_strlen, s, "tmp\\test_filename");
    will_return(__wrap_strlen, strlen("tmp\\test_filename"));
    expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_filename");
    expect_string(__wrap__merror, formatted_msg, "At unsign: Couldn't unsign package file 'incoming\\test_filename'");
#else
    expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_filename");
    will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_filename"));
    expect_string(__wrap_w_wpk_unsign, source, "/var/ossec//var/incoming/test_filename");
    will_return(__wrap_mkstemp, 8);
    expect_any(__wrap_chmod, path);
    will_return(__wrap_chmod, 0);

    expect_string(__wrap__merror, formatted_msg, "At unsign: Couldn't unsign package file '/var/ossec//var/incoming/test_filename'");
#endif
    will_return(__wrap_w_wpk_unsign, -1);
    expect_any_count(__wrap_unlink, file, 2);
    will_return_count(__wrap_unlink, 0, 2);

    int ret = _unsign(source, finalpath);
    assert_int_equal(ret, -1);
}

void test_unsign_success(void **state) {
    char finalpath[PATH_MAX + 1];
    char *source =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);
    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);

#ifdef TEST_WINAGENT
    expect_string(__wrap_strlen, s, "tmp\\test_filename");
    will_return(__wrap_strlen, strlen("tmp\\test_filename"));
    expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_filename");
#else
    expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_filename");
    will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_filename"));
    expect_string(__wrap_w_wpk_unsign, source, "/var/ossec//var/incoming/test_filename");

    will_return(__wrap_mkstemp, 8);
    expect_any(__wrap_chmod, path);
    will_return(__wrap_chmod, 0);
#endif
    will_return(__wrap_w_wpk_unsign, 0);
    expect_any(__wrap_unlink, file);
    will_return(__wrap_unlink, 0);

    int ret = _unsign(source, finalpath);
    assert_int_equal(ret, 0);
}


void test_uncompress_invalid_filename(void **state) {
    char compressed[PATH_MAX + 1];
    char merged[PATH_MAX + 1];
    char *package =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, package);
    will_return(__wrap_w_ref_parent_folder, 1);
    expect_string(__wrap__merror, formatted_msg, "At uncompress(): Invalid file name 'test_filename'"); 

    int ret = _uncompress(compressed, package, merged);
    assert_int_equal(ret, -1);
}

void test_uncompress_invalid_file_len(void **state) {
    char merged[PATH_MAX + 1];
    char *package =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, package);
    will_return(__wrap_w_ref_parent_folder, 0);


#ifdef TEST_WINAGENT
    expect_string(__wrap_strlen, s, "tmp\\test_filename");
    will_return(__wrap_strlen, PATH_MAX);
#else
    expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_filename");
    will_return(__wrap_strlen, PATH_MAX);
#endif
    expect_string(__wrap__merror, formatted_msg, "At uncompress(): Too long temp file.");

    int ret = _uncompress("compressed_test", package, merged);
    assert_int_equal(ret, -1);
}

void test_uncompress_gzopen_fail(void **state) {
    char merged[PATH_MAX + 1];
    char *package =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, package);
    will_return(__wrap_w_ref_parent_folder, 0);

#ifdef TEST_WINAGENT
    expect_string(__wrap_strlen, s, "tmp\\test_filename");
    will_return(__wrap_strlen, strlen("tmp\\test_filename"));
#else
    expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_filename");
    will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_filename"));
#endif

    expect_string(__wrap_gzopen, path, "compressed_test");
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, NULL);
    expect_string(__wrap__merror, formatted_msg, "At uncompress(): Unable to open 'compressed_test'");

    int ret = _uncompress("compressed_test", package, merged);
    assert_int_equal(ret, -1);
}

void test_uncompress_fopen_fail(void **state) {
    char merged[PATH_MAX + 1];
    char *package =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, package);
    will_return(__wrap_w_ref_parent_folder, 0);

#ifdef TEST_WINAGENT
    expect_string(__wrap_strlen, s, "tmp\\test_filename");
    will_return(__wrap_strlen, strlen("tmp\\test_filename"));
#else
    expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_filename");
    will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_filename"));
#endif

    expect_string(__wrap_gzopen, path, "compressed_test");
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, 4);

#ifdef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "At uncompress(): Unable to open 'tmp\\test_filename.mg.XXXXXX'");
#else
    expect_string(__wrap__merror, formatted_msg, "At uncompress(): Unable to open '/var/ossec/tmp/test_filename.mg.XXXXXX'");
#endif
    expect_any(__wrap_fopen, path);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 0);

    expect_value(__wrap_gzclose, file, 4);
    will_return(__wrap_gzclose, 0);

    int ret = _uncompress("compressed_test", package, merged);
    assert_int_equal(ret, -1);
}

void test_uncompress_fwrite_fail(void **state) {
    char merged[PATH_MAX + 1];
    char *package =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, package);
    will_return(__wrap_w_ref_parent_folder, 0);

#ifdef TEST_WINAGENT
    expect_string(__wrap_strlen, s, "tmp\\test_filename");
    will_return(__wrap_strlen, strlen("tmp\\test_filename"));
#else
    expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_filename");
    will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_filename"));
#endif

    expect_string(__wrap_gzopen, path, "compressed_test");
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, 4);

    expect_any(__wrap_fopen, path);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 5);

    expect_value(__wrap_gzread, gz_fd, 4);
    will_return(__wrap_gzread, 4);
    will_return(__wrap_gzread, "test");

    will_return(__wrap_fwrite, -1);

    expect_any(__wrap_unlink, file);
    will_return(__wrap_unlink, 0);

    expect_value(__wrap_gzclose, file, 4);
    will_return(__wrap_gzclose, 0);

    expect_value(__wrap_fclose, _File, 5);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap__merror, formatted_msg, "At uncompress(): Unable to write 'compressed_test'");

    int ret = _uncompress("compressed_test", package, merged);
    assert_int_equal(ret, -1);
}

void test_uncompress_gzread_fail(void **state) {
    char merged[PATH_MAX + 1];
    char *package =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, package);
    will_return(__wrap_w_ref_parent_folder, 0);

#ifdef TEST_WINAGENT
    expect_string(__wrap_strlen, s, "tmp\\test_filename");
    will_return(__wrap_strlen, strlen("tmp\\test_filename"));
#else
    expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_filename");
    will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_filename"));
#endif

    expect_string(__wrap_gzopen, path, "compressed_test");
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, 4);

    expect_any(__wrap_fopen, path);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 5);

    expect_value(__wrap_gzread, gz_fd, 4);
    will_return(__wrap_gzread, -1);

    expect_value(__wrap_gzclose, file, 4);
    will_return(__wrap_gzclose, 0);

    expect_value(__wrap_fclose, _File, 5);
    will_return(__wrap_fclose, 0);

    expect_any(__wrap_unlink, file);
    will_return(__wrap_unlink, 0);

    expect_string(__wrap__merror, formatted_msg, "At uncompress(): Unable to read 'compressed_test'");

    int ret = _uncompress("compressed_test", package, merged);
    assert_int_equal(ret, -1);
}

void test_uncompress_success(void **state) {
    char merged[PATH_MAX + 1];
    char *package =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, package);
    will_return(__wrap_w_ref_parent_folder, 0);

#ifdef TEST_WINAGENT
    expect_string(__wrap_strlen, s, "tmp\\test_filename");
    will_return(__wrap_strlen, strlen("tmp\\test_filename"));
#else
    expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_filename");
    will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_filename"));
#endif

    expect_string(__wrap_gzopen, path, "compressed_test");
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, 4);

    expect_any(__wrap_fopen, path);
    expect_string(__wrap_fopen, mode, "wb");
    will_return(__wrap_fopen, 5);

    expect_value(__wrap_gzread, gz_fd, 4);
    will_return(__wrap_gzread, 4);
    will_return(__wrap_gzread, "test");

    will_return(__wrap_fwrite, 4);

    expect_value(__wrap_gzread, gz_fd, 4);
    will_return(__wrap_gzread, 0);

    expect_value(__wrap_gzclose, file, 4);
    will_return(__wrap_gzclose, 0);

    expect_value(__wrap_fclose, _File, 5);
    will_return(__wrap_fclose, 0);

    expect_any(__wrap_unlink, file);
    will_return(__wrap_unlink, 0);

    int ret = _uncompress("compressed_test", package, merged);
    assert_int_equal(ret, 0);
}

/* Commands tests */
int setup_open1(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "mode", "r");
    cJSON_AddStringToObject(command, "file", "test_file");
    *state = command;
    test_mode = 1;
    return 0;
}

int setup_open2(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "mode", "w");
    cJSON_AddStringToObject(command, "file", "test_file");
    *state = command;
    test_mode = 1;
    return 0;
}

int setup_write(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "buffer", "ABCDABCD");
    cJSON_AddStringToObject(command, "file", "test_file");
    cJSON_AddNumberToObject(command, "length", 8);
    *state = command;
    test_mode = 1;
    return 0;
}

int setup_sha1(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "file", "test_file");
    *state = command;
    test_mode = 1;
    return 0;
}

int setup_upgrade(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "file", "test_file");
    cJSON_AddStringToObject(command, "installer", "install.sh");
    *state = command;
    test_mode = 1;
    return 0;
}

int teardown_commands(void **state) {
    cJSON * command = *state;
    test_mode = 0;
    cJSON_Delete(command);
    return 0;
}

void test_wm_agent_upgrade_com_open_unsopported_mode(void **state) {
    cJSON * command = *state;

    sprintf(file.path, "existent_path");
    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg,  "At open: File 'existent_path' was opened. Closing.");

    expect_any(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg,  "At open: Unsupported mode 'r'");

    char *response = wm_agent_upgrade_com_open(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Unsupported file mode");
}

void test_wm_agent_upgrade_com_open_invalid_file_name(void **state) {
    cJSON * command = *state;

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg,  "At open: Invalid file name");

    char *response = wm_agent_upgrade_com_open(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Invalid file name");
}

void test_wm_agent_upgrade_com_open_invalid_open(void **state) {
    cJSON * command = *state;

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_any(__wrap_fopen, path);
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg,   "(1103): Could not open file 'test_file' due to [(2)-(No such file or directory)].");

    errno = 2;

    char *response = wm_agent_upgrade_com_open(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "File Open Error: No such file or directory");
}

void test_wm_agent_upgrade_com_open_success(void **state) {
    cJSON * command = *state;

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_any(__wrap_fopen, path);
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 4);

    char *response = wm_agent_upgrade_com_open(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "ok");
}

void test_wm_agent_upgrade_com_write_file_closed(void **state) {
    cJSON * command = *state;

    sprintf(file.path, "%s", "\0");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg,   "At write: File not opened. Agent might have been auto-restarted during upgrade.");

    char *response = wm_agent_upgrade_com_write(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "File not opened. Agent might have been auto-restarted during upgrade");
}

void test_wm_agent_upgrade_com_write_invalid_file_name(void **state) {
    cJSON * command = *state;

    sprintf(file.path, "%s", "test_file");

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg,   "At write: Invalid file name");

    char *response = wm_agent_upgrade_com_write(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Invalid file name");
}

void test_wm_agent_upgrade_com_write_different_file_name(void **state) {
    cJSON * command = *state;

    sprintf(file.path, "%s", "test_file_different");

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "At write: The target file doesn't match the opened file (test_file_different).");

    char *response = wm_agent_upgrade_com_write(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "The target file doesn't match the opened file");
}

void test_wm_agent_upgrade_com_write_error(void **state) {
    cJSON * command = *state;
#ifdef TEST_WINAGENT
    sprintf(file.path, "incoming\\test_filename");
#else
    sprintf(file.path, "/var/ossec//var/incoming/test_file");
#endif

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    will_return(__wrap_fwrite, -1);

    expect_string(__wrap_strlen, s, "ABCDABCD");
    will_return(__wrap_strlen, __real_strlen);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
#ifdef TEST_WINAGENT
    expect_string(__wrap__mterror, formatted_msg, "At write: Cannot write on 'incoming\\test_filename'");
#else
    expect_string(__wrap__mterror, formatted_msg, "At write: Cannot write on '/var/ossec//var/incoming/test_file'");
#endif

    char *response = wm_agent_upgrade_com_write(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Cannot write file");
}

void test_wm_agent_upgrade_com_write_success(void **state) {
    cJSON * command = *state;
#ifdef TEST_WINAGENT
    sprintf(file.path, "incoming\\test_filename");
#else
    sprintf(file.path, "/var/ossec//var/incoming/test_file");
#endif

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    will_return(__wrap_fwrite, 8);

    expect_string(__wrap_strlen, s, "ABCDABCD");
    will_return(__wrap_strlen, __real_strlen);

    char *response = wm_agent_upgrade_com_write(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "ok");
}

void test_wm_agent_upgrade_com_close_file_opened(void **state) {
    cJSON * command = *state;

    sprintf(file.path, "%s", "\0");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "At close: No file is opened.");

    char *response = wm_agent_upgrade_com_close(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "No file opened");
}

void test_wm_agent_upgrade_com_close_invalid_file_name(void **state) {
    cJSON * command = *state;

    sprintf(file.path, "test_file");

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "At close: Invalid file name");

    char *response = wm_agent_upgrade_com_close(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Invalid file name");
}

void test_wm_agent_upgrade_com_close_different_file_name(void **state) {
    cJSON * command = *state;

    sprintf(file.path, "%s", "test_file_different");

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "At close: The target file doesn't match the opened file (test_file_different).");

    char *response = wm_agent_upgrade_com_close(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "The target file doesn't match the opened file");
}

void test_wm_agent_upgrade_com_close_failed(void **state) {
    cJSON * command = *state;

    #ifdef TEST_WINAGENT
    sprintf(file.path, "incoming\\test_file");
    #else
    sprintf(file.path, "/var/ossec//var/incoming/test_file");
    #endif

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_any(__wrap_fclose, _File);
    will_return(__wrap_fclose, -1);

    errno = EPERM;
    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "At close: Operation not permitted");

    char *response = wm_agent_upgrade_com_close(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Cannot close file");
}

void test_wm_agent_upgrade_com_close_success(void **state) {
    cJSON * command = *state;

    #ifdef TEST_WINAGENT
    sprintf(file.path, "incoming\\test_file");
    #else
    sprintf(file.path, "/var/ossec//var/incoming/test_file");
    #endif

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_any(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);

    char *response = wm_agent_upgrade_com_close(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "ok");
}

void test_wm_agent_upgrade_sha1_invalid_file(void **state) {
    cJSON * command = *state;

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "At sha1: Invalid file name");

    char *response = wm_agent_upgrade_com_sha1(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Invalid file name");
}

void test_wm_agent_upgrade_sha1_sha_error(void **state) {
    cJSON * command = *state;

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_any(__wrap_OS_SHA1_File, fname);
    expect_value(__wrap_OS_SHA1_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA1_File, "");
    will_return(__wrap_OS_SHA1_File, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "At sha1: Error generating SHA1.");

    char *response = wm_agent_upgrade_com_sha1(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Cannot generate SHA1");
}

void test_wm_agent_upgrade_sha1_sha_success(void **state) {
    cJSON * command = *state;

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_any(__wrap_OS_SHA1_File, fname);
    expect_value(__wrap_OS_SHA1_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA1_File, "2c312ada12ab321a253ad321af65983fa412e3a1");
    will_return(__wrap_OS_SHA1_File, 0);

    char *response = wm_agent_upgrade_com_sha1(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "2c312ada12ab321a253ad321af65983fa412e3a1");
}

void test_wm_agent_upgrade_com_upgrade_unsign_error(void **state) {
    cJSON * command = *state;

    will_return(__wrap_getDefine_Int, 3600);

    // Unsign
    {
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 1);
        expect_string(__wrap__merror, formatted_msg, "At unsign(): Invalid file name 'test_file'");
    }
    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "At upgrade: Could not verify signature");

    char *response = wm_agent_upgrade_com_upgrade(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Could not verify signature");
}

void test_wm_agent_upgrade_com_upgrade_uncompress_error(void **state) {
    cJSON * command = *state;

    will_return(__wrap_getDefine_Int, 3600);

    // Unsign
    {
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);

        #ifdef TEST_WINAGENT
            expect_string(__wrap_strlen, s, "tmp\\test_file");
            will_return(__wrap_strlen, strlen("tmp\\test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_file");
            will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "/var/ossec//var/incoming/test_file");

            will_return(__wrap_mkstemp, 8);
            expect_any(__wrap_chmod, path);
            will_return(__wrap_chmod, 0);
        #endif
        will_return(__wrap_w_wpk_unsign, 0);
        expect_any(__wrap_unlink, file);
        will_return(__wrap_unlink, 0);
    }

    // Uncompress
    {
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 1);
        expect_string(__wrap__merror, formatted_msg, "At uncompress(): Invalid file name 'test_file'");
    }

    expect_any(__wrap_unlink, file);
    will_return(__wrap_unlink, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "At upgrade: Could not uncompress package");

    char *response = wm_agent_upgrade_com_upgrade(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Could not uncompress package");
}


void test_wm_agent_upgrade_com_upgrade_clean_directory_error(void **state) {
    cJSON * command = *state;

    will_return(__wrap_getDefine_Int, 3600);

    // Unsign
    {
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);

        #ifdef TEST_WINAGENT
            expect_string(__wrap_strlen, s, "tmp\\test_file");
            will_return(__wrap_strlen, strlen("tmp\\test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_file");
            will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "/var/ossec//var/incoming/test_file");

            will_return(__wrap_mkstemp, 8);
            expect_any(__wrap_chmod, path);
            will_return(__wrap_chmod, 0);
        #endif
        will_return(__wrap_w_wpk_unsign, 0);
        expect_any(__wrap_unlink, file);
        will_return(__wrap_unlink, 0);
    }

    // Uncompress
    {
        expect_any(__wrap_w_ref_parent_folder, path);
        will_return(__wrap_w_ref_parent_folder, 0);

    #ifdef TEST_WINAGENT
        expect_string(__wrap_strlen, s, "tmp\\test_file");
        will_return(__wrap_strlen, strlen("tmp\\test_file"));
    #else
        expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_file");
        will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_file"));
    #endif

        expect_any(__wrap_gzopen, path);
        expect_string(__wrap_gzopen, mode, "rb");
        will_return(__wrap_gzopen, 4);

        expect_any(__wrap_fopen, path);
        expect_string(__wrap_fopen, mode, "wb");
        will_return(__wrap_fopen, 5);

        expect_value(__wrap_gzread, gz_fd, 4);
        will_return(__wrap_gzread, 4);
        will_return(__wrap_gzread, "test");

        will_return(__wrap_fwrite, 4);

        expect_value(__wrap_gzread, gz_fd, 4);
        will_return(__wrap_gzread, 0);

        expect_value(__wrap_gzclose, file, 4);
        will_return(__wrap_gzclose, 0);

        expect_value(__wrap_fclose, _File, 5);
        will_return(__wrap_fclose, 0);

        expect_any(__wrap_unlink, file);
        will_return(__wrap_unlink, 0);
    }

    will_return(__wrap_cldir_ex, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "At upgrade: Could not clean up upgrade directory");

    char *response = wm_agent_upgrade_com_upgrade(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Could not clean up upgrade directory");
}

void test_wm_agent_upgrade_com_unmerge_error(void **state) {
    cJSON * command = *state;

    will_return(__wrap_getDefine_Int, 3600);

    // Unsign
    {
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);

        #ifdef TEST_WINAGENT
            expect_string(__wrap_strlen, s, "tmp\\test_file");
            will_return(__wrap_strlen, strlen("tmp\\test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_file");
            will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "/var/ossec//var/incoming/test_file");

            will_return(__wrap_mkstemp, 8);
            expect_any(__wrap_chmod, path);
            will_return(__wrap_chmod, 0);
        #endif
        will_return(__wrap_w_wpk_unsign, 0);
        expect_any(__wrap_unlink, file);
        will_return(__wrap_unlink, 0);
    }

    // Uncompress
    {
        expect_any(__wrap_w_ref_parent_folder, path);
        will_return(__wrap_w_ref_parent_folder, 0);

    #ifdef TEST_WINAGENT
        expect_string(__wrap_strlen, s, "tmp\\test_file");
        will_return(__wrap_strlen, strlen("tmp\\test_file"));
    #else
        expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_file");
        will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_file"));
    #endif

        expect_any(__wrap_gzopen, path);
        expect_string(__wrap_gzopen, mode, "rb");
        will_return(__wrap_gzopen, 4);

        expect_any(__wrap_fopen, path);
        expect_string(__wrap_fopen, mode, "wb");
        will_return(__wrap_fopen, 5);

        expect_value(__wrap_gzread, gz_fd, 4);
        will_return(__wrap_gzread, 4);
        will_return(__wrap_gzread, "test");

        will_return(__wrap_fwrite, 4);

        expect_value(__wrap_gzread, gz_fd, 4);
        will_return(__wrap_gzread, 0);

        expect_value(__wrap_gzclose, file, 4);
        will_return(__wrap_gzclose, 0);

        expect_value(__wrap_fclose, _File, 5);
        will_return(__wrap_fclose, 0);

        expect_any(__wrap_unlink, file);
        will_return(__wrap_unlink, 0);
    }

    will_return(__wrap_cldir_ex, 0);

    expect_any(__wrap_UnmergeFiles, finalpath);
    expect_any(__wrap_UnmergeFiles, optdir);
    expect_value(__wrap_UnmergeFiles, mode, OS_BINARY);
    will_return(__wrap_UnmergeFiles, 0);

    expect_any(__wrap_unlink, file);
    will_return(__wrap_unlink, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_any(__wrap__mterror, formatted_msg);

    char *response = wm_agent_upgrade_com_upgrade(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Error unmerging file");
}

void test_wm_agent_upgrade_com_installer_error(void **state) {
    cJSON * command = *state;

    will_return(__wrap_getDefine_Int, 3600);
    // Unsign
    {
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);

        #ifdef TEST_WINAGENT
            expect_string(__wrap_strlen, s, "tmp\\test_file");
            will_return(__wrap_strlen, strlen("tmp\\test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_file");
            will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "/var/ossec//var/incoming/test_file");

            will_return(__wrap_mkstemp, 8);
            expect_any(__wrap_chmod, path);
            will_return(__wrap_chmod, 0);
        #endif
        will_return(__wrap_w_wpk_unsign, 0);
        expect_any(__wrap_unlink, file);
        will_return(__wrap_unlink, 0);
    }
    // Uncompress
    {
        expect_any(__wrap_w_ref_parent_folder, path);
        will_return(__wrap_w_ref_parent_folder, 0);

    #ifdef TEST_WINAGENT
        expect_string(__wrap_strlen, s, "tmp\\test_file");
        will_return(__wrap_strlen, strlen("tmp\\test_file"));
    #else
        expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_file");
        will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_file"));
    #endif

        expect_any(__wrap_gzopen, path);
        expect_string(__wrap_gzopen, mode, "rb");
        will_return(__wrap_gzopen, 4);

        expect_any(__wrap_fopen, path);
        expect_string(__wrap_fopen, mode, "wb");
        will_return(__wrap_fopen, 5);

        expect_value(__wrap_gzread, gz_fd, 4);
        will_return(__wrap_gzread, 4);
        will_return(__wrap_gzread, "test");

        will_return(__wrap_fwrite, 4);

        expect_value(__wrap_gzread, gz_fd, 4);
        will_return(__wrap_gzread, 0);

        expect_value(__wrap_gzclose, file, 4);
        will_return(__wrap_gzclose, 0);

        expect_value(__wrap_fclose, _File, 5);
        will_return(__wrap_fclose, 0);

        expect_any(__wrap_unlink, file);
        will_return(__wrap_unlink, 0);
    }

    will_return(__wrap_cldir_ex, 0);

    expect_any(__wrap_UnmergeFiles, finalpath);
    expect_any(__wrap_UnmergeFiles, optdir);
    expect_value(__wrap_UnmergeFiles, mode, OS_BINARY);
    will_return(__wrap_UnmergeFiles, -1);

    expect_any(__wrap_unlink, file);
    will_return(__wrap_unlink, 0);

    expect_any(__wrap_w_ref_parent_folder, path);
    will_return(__wrap_w_ref_parent_folder, 1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "At upgrade: Invalid file name");

    char *response = wm_agent_upgrade_com_upgrade(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Invalid file name");
}

#ifndef TEST_WINAGENT
void test_wm_agent_upgrade_com_chmod_error(void **state) {
    cJSON * command = *state;

    will_return(__wrap_getDefine_Int, 3600);
    // Unsign
    {
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);

        #ifdef TEST_WINAGENT
            expect_string(__wrap_strlen, s, "tmp\\test_file");
            will_return(__wrap_strlen, strlen("tmp\\test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_file");
            will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "/var/ossec//var/incoming/test_file");

            will_return(__wrap_mkstemp, 8);
            expect_any(__wrap_chmod, path);
            will_return(__wrap_chmod, 0);
        #endif
        will_return(__wrap_w_wpk_unsign, 0);
        expect_any(__wrap_unlink, file);
        will_return(__wrap_unlink, 0);
    }
    // Uncompress
    {
        expect_any(__wrap_w_ref_parent_folder, path);
        will_return(__wrap_w_ref_parent_folder, 0);

    #ifdef TEST_WINAGENT
        expect_string(__wrap_strlen, s, "tmp\\test_file");
        will_return(__wrap_strlen, strlen("tmp\\test_file"));
    #else
        expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_file");
        will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_file"));
    #endif

        expect_any(__wrap_gzopen, path);
        expect_string(__wrap_gzopen, mode, "rb");
        will_return(__wrap_gzopen, 4);

        expect_any(__wrap_fopen, path);
        expect_string(__wrap_fopen, mode, "wb");
        will_return(__wrap_fopen, 5);

        expect_value(__wrap_gzread, gz_fd, 4);
        will_return(__wrap_gzread, 4);
        will_return(__wrap_gzread, "test");

        will_return(__wrap_fwrite, 4);

        expect_value(__wrap_gzread, gz_fd, 4);
        will_return(__wrap_gzread, 0);

        expect_value(__wrap_gzclose, file, 4);
        will_return(__wrap_gzclose, 0);

        expect_value(__wrap_fclose, _File, 5);
        will_return(__wrap_fclose, 0);

        expect_any(__wrap_unlink, file);
        will_return(__wrap_unlink, 0);
    }

    will_return(__wrap_cldir_ex, 0);

    expect_any(__wrap_UnmergeFiles, finalpath);
    expect_any(__wrap_UnmergeFiles, optdir);
    expect_value(__wrap_UnmergeFiles, mode, OS_BINARY);
    will_return(__wrap_UnmergeFiles, -1);

    expect_any(__wrap_unlink, file);
    will_return(__wrap_unlink, 0);

    // Jailfile
    {
        expect_string(__wrap_w_ref_parent_folder, path, "install.sh");
        will_return(__wrap_w_ref_parent_folder, 0);
    }

    expect_string(__wrap_chmod, path, "/var/ossec//var/upgrade/install.sh");
    will_return(__wrap_chmod, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "At upgrade: Could not chmod '/var/ossec//var/upgrade/install.sh'");

    char *response = wm_agent_upgrade_com_upgrade(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Could not chmod");
}
#endif

void test_wm_agent_upgrade_com_execute_error(void **state) {
    cJSON * command = *state;

    will_return(__wrap_getDefine_Int, 3600);
    // Unsign
    {
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);

        #ifdef TEST_WINAGENT
            expect_string(__wrap_strlen, s, "tmp\\test_file");
            will_return(__wrap_strlen, strlen("tmp\\test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_file");
            will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "/var/ossec//var/incoming/test_file");

            will_return(__wrap_mkstemp, 8);
            expect_any(__wrap_chmod, path);
            will_return(__wrap_chmod, 0);
        #endif
        will_return(__wrap_w_wpk_unsign, 0);
        expect_any(__wrap_unlink, file);
        will_return(__wrap_unlink, 0);
    }
    // Uncompress
    {
        expect_any(__wrap_w_ref_parent_folder, path);
        will_return(__wrap_w_ref_parent_folder, 0);

    #ifdef TEST_WINAGENT
        expect_string(__wrap_strlen, s, "tmp\\test_file");
        will_return(__wrap_strlen, strlen("tmp\\test_file"));
    #else
        expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_file");
        will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_file"));
    #endif

        expect_any(__wrap_gzopen, path);
        expect_string(__wrap_gzopen, mode, "rb");
        will_return(__wrap_gzopen, 4);

        expect_any(__wrap_fopen, path);
        expect_string(__wrap_fopen, mode, "wb");
        will_return(__wrap_fopen, 5);

        expect_value(__wrap_gzread, gz_fd, 4);
        will_return(__wrap_gzread, 4);
        will_return(__wrap_gzread, "test");

        will_return(__wrap_fwrite, 4);

        expect_value(__wrap_gzread, gz_fd, 4);
        will_return(__wrap_gzread, 0);

        expect_value(__wrap_gzclose, file, 4);
        will_return(__wrap_gzclose, 0);

        expect_value(__wrap_fclose, _File, 5);
        will_return(__wrap_fclose, 0);

        expect_any(__wrap_unlink, file);
        will_return(__wrap_unlink, 0);
    }

    will_return(__wrap_cldir_ex, 0);

    expect_any(__wrap_UnmergeFiles, finalpath);
    expect_any(__wrap_UnmergeFiles, optdir);
    expect_value(__wrap_UnmergeFiles, mode, OS_BINARY);
    will_return(__wrap_UnmergeFiles, -1);

    expect_any(__wrap_unlink, file);
    will_return(__wrap_unlink, 0);

    // Jailfile
    {
        expect_string(__wrap_w_ref_parent_folder, path, "install.sh");
        will_return(__wrap_w_ref_parent_folder, 0);
    }

    #ifndef TEST_WINAGENT
    expect_string(__wrap_chmod, path, "/var/ossec//var/upgrade/install.sh");
    will_return(__wrap_chmod, 0);
    expect_string(__wrap_wm_exec, command, "/var/ossec//var/upgrade/install.sh");

    #else
    expect_string(__wrap_wm_exec, command, "upgrade/install.sh");
    #endif


    expect_value(__wrap_wm_exec, secs, 3600);
    expect_value(__wrap_wm_exec, add_path, NULL);
    will_return(__wrap_wm_exec, "OUTPUT COMMAND");
    will_return(__wrap_wm_exec, -1);
    will_return(__wrap_wm_exec, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");

    #ifndef TEST_WINAGENT
    expect_string(__wrap__mterror, formatted_msg, "At upgrade: Error executing command [/var/ossec//var/upgrade/install.sh]");
    #else
    expect_string(__wrap__mterror, formatted_msg, "At upgrade: Error executing command [upgrade/install.sh]");
    #endif

    char *response = wm_agent_upgrade_com_upgrade(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Error executing command");
}

void test_wm_agent_upgrade_com_success(void **state) {
    cJSON * command = *state;

    will_return(__wrap_getDefine_Int, 3600);
    // Unsign
    {
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);

        #ifdef TEST_WINAGENT
            expect_string(__wrap_strlen, s, "tmp\\test_file");
            will_return(__wrap_strlen, strlen("tmp\\test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_file");
            will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_file"));
            expect_string(__wrap_w_wpk_unsign, source, "/var/ossec//var/incoming/test_file");

            will_return(__wrap_mkstemp, 8);
            expect_any(__wrap_chmod, path);
            will_return(__wrap_chmod, 0);
        #endif
        will_return(__wrap_w_wpk_unsign, 0);
        expect_any(__wrap_unlink, file);
        will_return(__wrap_unlink, 0);
    }
    // Uncompress
    {
        expect_any(__wrap_w_ref_parent_folder, path);
        will_return(__wrap_w_ref_parent_folder, 0);

    #ifdef TEST_WINAGENT
        expect_string(__wrap_strlen, s, "tmp\\test_file");
        will_return(__wrap_strlen, strlen("tmp\\test_file"));
    #else
        expect_string(__wrap_strlen, s, "/var/ossec/tmp/test_file");
        will_return(__wrap_strlen, strlen("/var/ossec/tmp/test_file"));
    #endif

        expect_any(__wrap_gzopen, path);
        expect_string(__wrap_gzopen, mode, "rb");
        will_return(__wrap_gzopen, 4);

        expect_any(__wrap_fopen, path);
        expect_string(__wrap_fopen, mode, "wb");
        will_return(__wrap_fopen, 5);

        expect_value(__wrap_gzread, gz_fd, 4);
        will_return(__wrap_gzread, 4);
        will_return(__wrap_gzread, "test");

        will_return(__wrap_fwrite, 4);

        expect_value(__wrap_gzread, gz_fd, 4);
        will_return(__wrap_gzread, 0);

        expect_value(__wrap_gzclose, file, 4);
        will_return(__wrap_gzclose, 0);

        expect_value(__wrap_fclose, _File, 5);
        will_return(__wrap_fclose, 0);

        expect_any(__wrap_unlink, file);
        will_return(__wrap_unlink, 0);
    }

    will_return(__wrap_cldir_ex, 0);

    expect_any(__wrap_UnmergeFiles, finalpath);
    expect_any(__wrap_UnmergeFiles, optdir);
    expect_value(__wrap_UnmergeFiles, mode, OS_BINARY);
    will_return(__wrap_UnmergeFiles, -1);

    expect_any(__wrap_unlink, file);
    will_return(__wrap_unlink, 0);

    // Jailfile
    {
        expect_string(__wrap_w_ref_parent_folder, path, "install.sh");
        will_return(__wrap_w_ref_parent_folder, 0);
    }

    #ifndef TEST_WINAGENT
    expect_string(__wrap_chmod, path, "/var/ossec//var/upgrade/install.sh");
    will_return(__wrap_chmod, 0);
    expect_string(__wrap_wm_exec, command, "/var/ossec//var/upgrade/install.sh");

    #else
    expect_string(__wrap_wm_exec, command, "upgrade/install.sh");
    #endif


    expect_value(__wrap_wm_exec, secs, 3600);
    expect_value(__wrap_wm_exec, add_path, NULL);
    will_return(__wrap_wm_exec, "OUTPUT COMMAND");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    char *response = wm_agent_upgrade_com_upgrade(command);
    assert_string_equal(cJSON_GetObjectItem(cJSON_Parse(response), task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "0");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_jailfile_invalid_path, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_jailfile_valid_path, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_unsign_invalid_source_incomming, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_unsign_invalid_source_temp, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_unsign_invalid_source_len, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_unsign_temp_file_fail, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_unsign_success, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_uncompress_invalid_filename, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_uncompress_invalid_file_len, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_uncompress_gzopen_fail, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_uncompress_fopen_fail, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_uncompress_fwrite_fail, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_uncompress_gzread_fail, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_uncompress_success, setup_jailfile, teardown_jailfile),
        // Test commands
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_open_unsopported_mode, setup_open1, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_open_invalid_file_name, setup_open2, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_open_invalid_open, setup_open2, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_open_success, setup_open2, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_write_file_closed, setup_write, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_write_invalid_file_name, setup_write, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_write_different_file_name, setup_write, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_write_error, setup_write, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_write_success, setup_write, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_close_file_opened, setup_write, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_close_invalid_file_name, setup_write, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_close_different_file_name, setup_write, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_close_failed, setup_write, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_close_success, setup_write, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_sha1_invalid_file, setup_sha1, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_sha1_sha_error, setup_sha1, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_upgrade_unsign_error, setup_upgrade, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_upgrade_uncompress_error, setup_upgrade, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_upgrade_clean_directory_error, setup_upgrade, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_unmerge_error, setup_upgrade, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_installer_error, setup_upgrade, teardown_commands),
    #ifndef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_chmod_error, setup_upgrade, teardown_commands),
    #endif
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_execute_error, setup_upgrade, teardown_commands),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_success, setup_upgrade, teardown_commands),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
