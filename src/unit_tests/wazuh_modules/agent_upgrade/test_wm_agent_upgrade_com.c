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

#include "../../headers/shared.h"
#include "../../wazuh_modules/wm_task_general.h"
#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/agent_upgrade/wm_agent_upgrade.h"
#include "../../wazuh_modules/agent_upgrade/agent/wm_agent_upgrade_agent.h"

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
extern char * wm_agent_upgrade_com_clear_result();

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

#ifdef TEST_WINAGENT
int setup_jailfile_long_name(void **state) {
    char *filename = malloc(sizeof(char) * OS_MAXSTR);
    const unsigned int length = PATH_MAX - strlen(INCOMING_DIR) - 2;
    for(int i=0; i < length; i++) {
        sprintf(&filename[i], "a");
    }
    *state = filename;
    test_mode = 1;
    return 0;
}
#endif

int setup_jailfile_long_name2(void **state) {
    char *filename = malloc(sizeof(char) * OS_MAXSTR);
    const unsigned int length = PATH_MAX - strlen(TMP_DIR) - 2;
    for(int i=0; i < length; i++) {
        sprintf(&filename[i], "a");
    }
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

int setup_clear_result(void **state) {
    test_mode = 1;
    return 0;
}

int teadown_clear_result(void **state) {
    test_mode = 0;
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
    assert_string_equal(finalpath, "tmp/test_filename");
#endif
}

void test_unsign_invalid_source_incomming(void **state) {
    char finalpath[PATH_MAX + 1];
    char *source =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 1);
    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8126): At unsign(): Invalid file name.");
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
    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8126): At unsign(): Invalid file name.");
    int ret = _unsign(source, finalpath);
    assert_int_equal(ret, -1);
}

#ifdef TEST_WINAGENT
void test_unsign_invalid_source_len(void **state) {
    char finalpath[PATH_MAX + 1];
    char *source =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);
    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8137): At unsign(): Too long temp file.");

    int ret = _unsign(source, finalpath);
    assert_int_equal(ret, -1);
}
#endif

void test_unsign_temp_file_fail(void **state) {
    char finalpath[PATH_MAX + 1];
    char *source =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);
    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);

#ifdef TEST_WINAGENT
    will_return(wrap_mktemp_s, 1);
#else
    will_return(__wrap_mkstemp, -1);
#endif
    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8138): At unsign(): Could not create temporary compressed file.");

    expect_any(__wrap_unlink, file);
    will_return(__wrap_unlink, 0);

    int ret = _unsign(source, finalpath);
    assert_int_equal(ret, -1);
}

void test_unsign_wpk_using_fail(void **state) {
    char finalpath[PATH_MAX + 1];
    char *source =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);
    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);

#ifdef TEST_WINAGENT
    will_return(wrap_mktemp_s,  NULL);
    expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_filename");
    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8139): At unsign(): Could not unsign package file 'incoming\\test_filename'");
#else
    expect_string(__wrap_w_wpk_unsign, source, "var/incoming/test_filename");
    will_return(__wrap_mkstemp, 8);
    expect_any(__wrap_chmod, path);
    will_return(__wrap_chmod, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8139): At unsign(): Could not unsign package file 'var/incoming/test_filename'");
#endif
    will_return(__wrap_w_wpk_unsign, -1);
    expect_any_count(__wrap_unlink, file, 2);
    will_return_count(__wrap_unlink, 0, 2);

    int ret = _unsign(source, finalpath);
    assert_int_equal(ret, -1);
}

void test_unsign_temp_chmod_fail(void **state) {
    char finalpath[PATH_MAX + 1];
    char *source =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);
    expect_string(__wrap_w_ref_parent_folder, path, source);
    will_return(__wrap_w_ref_parent_folder, 0);

    will_return(__wrap_mkstemp, 8);
    expect_any(__wrap_chmod, path);
    will_return(__wrap_chmod, -1);

    expect_any_count(__wrap_unlink, file, 2);
    will_return_count(__wrap_unlink, 0, 2);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8134): At unsign(): Could not chmod 'tmp/test_filename.gz.XXXXXX'");

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
    will_return(wrap_mktemp_s,  NULL);
    expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_filename");
#else
    expect_string(__wrap_w_wpk_unsign, source, "var/incoming/test_filename");

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

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8126): At uncompress(): Invalid file name.");

    int ret = _uncompress(compressed, package, merged);
    assert_int_equal(ret, -1);
}

void test_uncompress_invalid_file_len(void **state) {
    char merged[PATH_MAX + 1];
    char *package =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, package);
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8137): At uncompress(): Too long temp file.");

    int ret = _uncompress("compressed_test", package, merged);
    assert_int_equal(ret, -1);
}

void test_uncompress_gzopen_fail(void **state) {
    char merged[PATH_MAX + 1];
    char *package =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, package);
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_string(__wrap_gzopen, path, "compressed_test");
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, NULL);
    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8140): At uncompress(): Unable to open 'compressed_test'");

    int ret = _uncompress("compressed_test", package, merged);
    assert_int_equal(ret, -1);
}

void test_uncompress_fopen_fail(void **state) {
    char merged[PATH_MAX + 1];
    char *package =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, package);
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_string(__wrap_gzopen, path, "compressed_test");
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, 4);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
#ifdef TEST_WINAGENT
    expect_string(__wrap__mterror, formatted_msg, "(8140): At uncompress(): Unable to open 'tmp\\test_filename.mg.XXXXXX'");
#else
    expect_string(__wrap__mterror, formatted_msg, "(8140): At uncompress(): Unable to open 'tmp/test_filename.mg.XXXXXX'");
#endif
    expect_any(__wrap_wfopen, path);
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, 0);

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

    expect_string(__wrap_gzopen, path, "compressed_test");
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, 4);

    expect_any(__wrap_wfopen, path);
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, 5);

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

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8129): At uncompress(): Cannot write on 'compressed_test'");

    int ret = _uncompress("compressed_test", package, merged);
    assert_int_equal(ret, -1);
}

void test_uncompress_gzread_fail(void **state) {
    char merged[PATH_MAX + 1];
    char *package =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, package);
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_string(__wrap_gzopen, path, "compressed_test");
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, 4);

    expect_any(__wrap_wfopen, path);
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, 5);

    expect_value(__wrap_gzread, gz_fd, 4);
    will_return(__wrap_gzread, -1);

    expect_value(__wrap_gzclose, file, 4);
    will_return(__wrap_gzclose, 0);

    expect_value(__wrap_fclose, _File, 5);
    will_return(__wrap_fclose, 0);

    expect_any(__wrap_unlink, file);
    will_return(__wrap_unlink, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8141): At uncompress(): Unable to read 'compressed_test'");

    int ret = _uncompress("compressed_test", package, merged);
    assert_int_equal(ret, -1);
}

void test_uncompress_success(void **state) {
    char merged[PATH_MAX + 1];
    char *package =  *state;

    expect_string(__wrap_w_ref_parent_folder, path, package);
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_string(__wrap_gzopen, path, "compressed_test");
    expect_string(__wrap_gzopen, mode, "rb");
    will_return(__wrap_gzopen, 4);

    expect_any(__wrap_wfopen, path);
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, 5);

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
    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtwarn, formatted_msg,  "(8124): At open: File 'existent_path' was opened. Closing.");

    expect_any(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg,  "(8125): At open: Unsupported mode.");

    char *response = wm_agent_upgrade_com_open(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Unsupported file mode");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_open_invalid_file_name(void **state) {
    cJSON * command = *state;

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg,  "(8126): At open: Invalid file name.");

    char *response = wm_agent_upgrade_com_open(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Invalid file name");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_open_invalid_open(void **state) {
    cJSON * command = *state;

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_any(__wrap_wfopen, path);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg,   "(1103): Could not open file 'test_file' due to [(2)-(No such file or directory)].");

    errno = 2;

    char *response = wm_agent_upgrade_com_open(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "File Open Error: No such file or directory");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_open_success(void **state) {
    cJSON * command = *state;

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_any(__wrap_wfopen, path);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, 4);

    char *response = wm_agent_upgrade_com_open(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "ok");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_write_file_closed(void **state) {
    cJSON * command = *state;

    sprintf(file.path, "%s", "\0");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg,   "(8127): At write: File not opened. Agent might have been auto-restarted during upgrade.");

    char *response = wm_agent_upgrade_com_write(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "File not opened. Agent might have been auto-restarted during upgrade");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_write_invalid_file_name(void **state) {
    cJSON * command = *state;

    sprintf(file.path, "%s", "test_file");

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg,   "(8126): At write: Invalid file name.");

    char *response = wm_agent_upgrade_com_write(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Invalid file name");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_write_different_file_name(void **state) {
    cJSON * command = *state;

    sprintf(file.path, "%s", "test_file_different");

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8128): At write: The target file doesn't match the opened file 'test_file_different'");

    char *response = wm_agent_upgrade_com_write(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "The target file doesn't match the opened file");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_write_error(void **state) {
    cJSON * command = *state;
#ifdef TEST_WINAGENT
    sprintf(file.path, "incoming\\test_file");
#else
    sprintf(file.path, "var/incoming/test_file");
#endif

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    will_return(__wrap_fwrite, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
#ifdef TEST_WINAGENT
    expect_string(__wrap__mterror, formatted_msg, "(8129): At write: Cannot write on 'incoming\\test_file'");
#else
    expect_string(__wrap__mterror, formatted_msg, "(8129): At write: Cannot write on 'var/incoming/test_file'");
#endif

    char *response = wm_agent_upgrade_com_write(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Cannot write file");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_write_success(void **state) {
    cJSON * command = *state;
#ifdef TEST_WINAGENT
    sprintf(file.path, "incoming\\test_file");
#else
    sprintf(file.path, "var/incoming/test_file");
#endif

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    will_return(__wrap_fwrite, 8);

    char *response = wm_agent_upgrade_com_write(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "ok");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_close_file_opened(void **state) {
    cJSON * command = *state;

    sprintf(file.path, "%s", "\0");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8130): At close: No file is opened.");

    char *response = wm_agent_upgrade_com_close(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "No file opened");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_close_invalid_file_name(void **state) {
    cJSON * command = *state;

    sprintf(file.path, "test_file");

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8126): At close: Invalid file name.");

    char *response = wm_agent_upgrade_com_close(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Invalid file name");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_close_different_file_name(void **state) {
    cJSON * command = *state;

    sprintf(file.path, "%s", "test_file_different");

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8128): At close: The target file doesn't match the opened file 'test_file_different'");

    char *response = wm_agent_upgrade_com_close(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "The target file doesn't match the opened file");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_close_failed(void **state) {
    cJSON * command = *state;

    #ifdef TEST_WINAGENT
    sprintf(file.path, "incoming\\test_file");
    #else
    sprintf(file.path, "var/incoming/test_file");
    #endif

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_any(__wrap_fclose, _File);
    will_return(__wrap_fclose, -1);

    errno = EPERM;
    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8131): At close: 'Operation not permitted'");

    char *response = wm_agent_upgrade_com_close(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Cannot close file");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_close_success(void **state) {
    cJSON * command = *state;

    #ifdef TEST_WINAGENT
    sprintf(file.path, "incoming\\test_file");
    #else
    sprintf(file.path, "var/incoming/test_file");
    #endif

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 0);

    expect_any(__wrap_fclose, _File);
    will_return(__wrap_fclose, 0);

    char *response = wm_agent_upgrade_com_close(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "ok");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_sha1_invalid_file(void **state) {
    cJSON * command = *state;

    expect_string(__wrap_w_ref_parent_folder, path, "test_file");
    will_return(__wrap_w_ref_parent_folder, 1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8126): At sha1: Invalid file name.");

    char *response = wm_agent_upgrade_com_sha1(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Invalid file name");
    cJSON_Delete(response_object);
    os_free(response);
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
    expect_string(__wrap__mterror, formatted_msg, "(8132): At sha1: Error generating SHA1.");

    char *response = wm_agent_upgrade_com_sha1(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Cannot generate SHA1");
    cJSON_Delete(response_object);
    os_free(response);
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
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "2c312ada12ab321a253ad321af65983fa412e3a1");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_upgrade_unsign_error(void **state) {
    cJSON * command = *state;

    will_return(__wrap_getDefine_Int, 3600);

    // Unsign
    {
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 1);
        expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
        expect_string(__wrap__mterror, formatted_msg, "(8126): At unsign(): Invalid file name.");
    }
    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8131): At upgrade: 'Could not verify signature'");

    char *response = wm_agent_upgrade_com_upgrade(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Could not verify signature");
    cJSON_Delete(response_object);
    os_free(response);
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
            will_return(wrap_mktemp_s,  NULL);
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_w_wpk_unsign, source, "var/incoming/test_file");

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
        expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
        expect_string(__wrap__mterror, formatted_msg, "(8126): At uncompress(): Invalid file name.");
    }

    expect_any(__wrap_unlink, file);
    will_return(__wrap_unlink, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8131): At upgrade: 'Could not uncompress package'");

    char *response = wm_agent_upgrade_com_upgrade(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Could not uncompress package");
    cJSON_Delete(response_object);
    os_free(response);
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
            will_return(wrap_mktemp_s,  NULL);
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_w_wpk_unsign, source, "var/incoming/test_file");

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

        expect_any(__wrap_gzopen, path);
        expect_string(__wrap_gzopen, mode, "rb");
        will_return(__wrap_gzopen, 4);

        expect_any(__wrap_wfopen, path);
        expect_string(__wrap_wfopen, mode, "wb");
        will_return(__wrap_wfopen, 5);

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
    expect_string(__wrap__mterror, formatted_msg, "(8131): At upgrade: 'Could not clean up upgrade directory'");

    char *response = wm_agent_upgrade_com_upgrade(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Could not clean up upgrade directory");
    cJSON_Delete(response_object);
    os_free(response);
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
            will_return(wrap_mktemp_s,  NULL);
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_w_wpk_unsign, source, "var/incoming/test_file");

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

        expect_any(__wrap_gzopen, path);
        expect_string(__wrap_gzopen, mode, "rb");
        will_return(__wrap_gzopen, 4);

        expect_any(__wrap_wfopen, path);
        expect_string(__wrap_wfopen, mode, "wb");
        will_return(__wrap_wfopen, 5);

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
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Error unmerging file");
    cJSON_Delete(response_object);
    os_free(response);
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
            will_return(wrap_mktemp_s,  NULL);
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_w_wpk_unsign, source, "var/incoming/test_file");

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

        expect_any(__wrap_gzopen, path);
        expect_string(__wrap_gzopen, mode, "rb");
        will_return(__wrap_gzopen, 4);

        expect_any(__wrap_wfopen, path);
        expect_string(__wrap_wfopen, mode, "wb");
        will_return(__wrap_wfopen, 5);

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
    expect_string(__wrap__mterror, formatted_msg, "(8126): At upgrade: Invalid file name.");

    char *response = wm_agent_upgrade_com_upgrade(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Invalid file name");
    cJSON_Delete(response_object);
    os_free(response);
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
            will_return(wrap_mktemp_s,  NULL);
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_w_wpk_unsign, source, "var/incoming/test_file");

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

        expect_any(__wrap_gzopen, path);
        expect_string(__wrap_gzopen, mode, "rb");
        will_return(__wrap_gzopen, 4);

        expect_any(__wrap_wfopen, path);
        expect_string(__wrap_wfopen, mode, "wb");
        will_return(__wrap_wfopen, 5);

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

    expect_string(__wrap_chmod, path, "var/upgrade/install.sh");
    will_return(__wrap_chmod, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8134): At upgrade: Could not chmod 'var/upgrade/install.sh'");

    char *response = wm_agent_upgrade_com_upgrade(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Could not chmod");
    cJSON_Delete(response_object);
    os_free(response);
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
            will_return(wrap_mktemp_s,  NULL);
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_w_wpk_unsign, source, "var/incoming/test_file");

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

        expect_any(__wrap_gzopen, path);
        expect_string(__wrap_gzopen, mode, "rb");
        will_return(__wrap_gzopen, 4);

        expect_any(__wrap_wfopen, path);
        expect_string(__wrap_wfopen, mode, "wb");
        will_return(__wrap_wfopen, 5);

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
    expect_string(__wrap_chmod, path, "var/upgrade/install.sh");
    will_return(__wrap_chmod, 0);
    expect_string(__wrap_wm_exec, command, "var/upgrade/install.sh");

    #else
    expect_string(__wrap_wm_exec, command, "upgrade\\install.sh");
    #endif


    expect_value(__wrap_wm_exec, secs, 3600);
    expect_value(__wrap_wm_exec, add_path, NULL);
    will_return(__wrap_wm_exec, "OUTPUT COMMAND");
    will_return(__wrap_wm_exec, -1);
    will_return(__wrap_wm_exec, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");

    #ifndef TEST_WINAGENT
    expect_string(__wrap__mterror, formatted_msg, "(8135): At upgrade: Error executing command [var/upgrade/install.sh]");
    #else
    expect_string(__wrap__mterror, formatted_msg, "(8135): At upgrade: Error executing command [upgrade\\install.sh]");
    #endif

    char *response = wm_agent_upgrade_com_upgrade(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Error executing command");
    cJSON_Delete(response_object);
    os_free(response);
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
            will_return(wrap_mktemp_s,  NULL);
            expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
        #else
            expect_string(__wrap_w_wpk_unsign, source, "var/incoming/test_file");

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

        expect_any(__wrap_gzopen, path);
        expect_string(__wrap_gzopen, mode, "rb");
        will_return(__wrap_gzopen, 4);

        expect_any(__wrap_wfopen, path);
        expect_string(__wrap_wfopen, mode, "wb");
        will_return(__wrap_wfopen, 5);

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
    expect_string(__wrap_chmod, path, "var/upgrade/install.sh");
    will_return(__wrap_chmod, 0);
    expect_string(__wrap_wm_exec, command, "var/upgrade/install.sh");

    #else
    expect_string(__wrap_wm_exec, command, "upgrade\\install.sh");
    #endif


    expect_value(__wrap_wm_exec, secs, 3600);
    expect_value(__wrap_wm_exec, add_path, NULL);
    will_return(__wrap_wm_exec, "OUTPUT COMMAND");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    char *response = wm_agent_upgrade_com_upgrade(command);
    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "0");
    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_clear_result_failed(void **state) {
    allow_upgrades = false;

    #ifndef TEST_WINAGENT
        expect_string(__wrap_remove, filename, "var/upgrade/upgrade_result");
    #else
        expect_string(__wrap_remove, filename, "upgrade\\upgrade_result");
    #endif
    will_return(__wrap_remove, -1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    #ifndef TEST_WINAGENT
        expect_string(__wrap__mtdebug1, formatted_msg,  "(8136): At clear_upgrade_result: Could not erase file 'var/upgrade/upgrade_result'");
    #else
        expect_string(__wrap__mtdebug1, formatted_msg,  "(8136): At clear_upgrade_result: Could not erase file 'upgrade\\upgrade_result'");
    #endif

    char *response = wm_agent_upgrade_com_clear_result();

    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "Could not erase upgrade_result file");

    assert_int_equal(allow_upgrades, false);

    cJSON_Delete(response_object);
    os_free(response);
}

void test_wm_agent_upgrade_com_clear_result_success(void **state) {
    allow_upgrades = false;

    #ifndef TEST_WINAGENT
        expect_string(__wrap_remove, filename, "var/upgrade/upgrade_result");
    #else
        expect_string(__wrap_remove, filename, "upgrade\\upgrade_result");
    #endif
    will_return(__wrap_remove, 0);

    char *response = wm_agent_upgrade_com_clear_result();

    cJSON *response_object = cJSON_Parse(response);
    assert_string_equal(cJSON_GetObjectItem(response_object, task_manager_json_keys[WM_TASK_ERROR_MESSAGE])->valuestring, "ok");

    assert_int_equal(allow_upgrades, true);

    cJSON_Delete(response_object);
    os_free(response);
}

/* Process commands */
int setup_process_clear_upgrade(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "command", "clear_upgrade_result");
    char *ptr = cJSON_PrintUnformatted(command);
    *state = ptr;
    cJSON_Delete(command);
    test_mode = 1;
    return 0;
}

int teardown_process(void **state) {
    char *buffer = *state;
    os_free(buffer);
    allow_upgrades = true;
    test_mode = 0;
    return 0;
}

int setup_process_no_parameters(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "command", "open");
    char *ptr = cJSON_PrintUnformatted(command);
    *state = ptr;
    cJSON_Delete(command);
    test_mode = 1;
    return 0;
}

int setup_process_open(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "command", "open");
    cJSON * parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "mode", "w");
    cJSON_AddStringToObject(parameters, "file", "test_file");
    cJSON_AddItemToObject(command, "parameters", parameters);
    char *ptr = cJSON_PrintUnformatted(command);
    *state = ptr;
    cJSON_Delete(command);
    test_mode = 1;
    return 0;
}

int setup_process_write(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "command", "write");
    cJSON * parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "buffer", "ABCDABCD");
    cJSON_AddStringToObject(parameters, "file", "test_file");
    cJSON_AddNumberToObject(parameters, "length", 8);
    cJSON_AddItemToObject(command, "parameters", parameters);
    char *ptr = cJSON_PrintUnformatted(command);
    *state = ptr;
    cJSON_Delete(command);
    test_mode = 1;
    return 0;
}

int setup_process_close(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "command", "close");
    cJSON * parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "file", "test_file");
    cJSON_AddItemToObject(command, "parameters", parameters);
    char *ptr = cJSON_PrintUnformatted(command);
    *state = ptr;
    cJSON_Delete(command);
    test_mode = 1;
    return 0;
}

int setup_process_sha1(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "command", "sha1");
    cJSON * parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "file", "test_file");
    cJSON_AddItemToObject(command, "parameters", parameters);
    char *ptr = cJSON_PrintUnformatted(command);
    *state = ptr;
    cJSON_Delete(command);
    test_mode = 1;
    return 0;
}

int setup_process_upgrade(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "command", "upgrade");
    cJSON * parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "file", "test_file");
    cJSON_AddStringToObject(parameters, "installer", "install.sh");
    cJSON_AddItemToObject(command, "parameters", parameters);
    char *ptr = cJSON_PrintUnformatted(command);
    *state = ptr;
    cJSON_Delete(command);
    test_mode = 1;
    return 0;
}

int setup_process_upgrade_not_allowed(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "command", "open");
    char *ptr = cJSON_PrintUnformatted(command);
    *state = ptr;
    cJSON_Delete(command);
    test_mode = 1;
    // Turn off upgrades
    allow_upgrades = false;
    return 0;
}

int setup_process_unknown(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "command", "abcd");
    cJSON * parameters = cJSON_CreateObject();
    cJSON_AddItemToObject(command, "parameters", parameters);
    char *ptr = cJSON_PrintUnformatted(command);
    *state = ptr;
    cJSON_Delete(command);
    test_mode = 1;
    return 0;
}

void test_wm_agent_upgrade_process_clear_command(void **state) {
    char * buffer = *state;
    char *output = NULL;

    {
        #ifndef TEST_WINAGENT
            expect_string(__wrap_remove, filename, "var/upgrade/upgrade_result");
        #else
            expect_string(__wrap_remove, filename, "upgrade\\upgrade_result");
        #endif
        will_return(__wrap_remove, 0);
    }

    size_t length = wm_agent_upgrade_process_command(buffer, &output);
    cJSON *response = cJSON_Parse(output);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "ok");
    assert_int_equal(strlen(output), length);
    cJSON_Delete(response);
    os_free(output);
}

void test_wm_agent_upgrade_process_open_no_parameters(void **state) {
    char * buffer = *state;
    char *output = NULL;

    size_t length = wm_agent_upgrade_process_command(buffer, &output);
    cJSON *response = cJSON_Parse(output);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Required parameters were not found");
    assert_int_not_equal(cJSON_GetObjectItem(response, "error")->valueint, 0);
    assert_int_equal(strlen(output), length);
    cJSON_Delete(response);
    os_free(output);
}

void test_wm_agent_upgrade_process_open_command(void **state) {
    char * buffer = *state;
    char *output = NULL;
    // Open
    {
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);

        expect_any(__wrap_wfopen, path);
        expect_string(__wrap_wfopen, mode, "w");
        will_return(__wrap_wfopen, 4);
    }

    size_t length = wm_agent_upgrade_process_command(buffer, &output);
    cJSON *response = cJSON_Parse(output);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "ok");
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 0);
    assert_int_equal(strlen(output), length);
    cJSON_Delete(response);
    os_free(output);
}

void test_wm_agent_upgrade_process_write_command(void **state) {
    char * buffer = *state;
    char *output = NULL;
    // Write
    {
        #ifdef TEST_WINAGENT
            sprintf(file.path, "incoming\\test_file");
        #else
            sprintf(file.path, "var/incoming/test_file");
        #endif

        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);

        will_return(__wrap_fwrite, 8);
    }

    size_t length = wm_agent_upgrade_process_command(buffer, &output);
    cJSON *response = cJSON_Parse(output);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "ok");
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 0);
    assert_int_equal(strlen(output), length);
    cJSON_Delete(response);
    os_free(output);
}

void test_wm_agent_upgrade_process_close_command(void **state) {
    char * buffer = *state;
    char *output = NULL;
    // Close
    {
        #ifdef TEST_WINAGENT
        sprintf(file.path, "incoming\\test_file");
        #else
        sprintf(file.path, "var/incoming/test_file");
        #endif

        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);

        expect_any(__wrap_fclose, _File);
        will_return(__wrap_fclose, 0);
    }

    size_t length = wm_agent_upgrade_process_command(buffer, &output);
    cJSON *response = cJSON_Parse(output);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "ok");
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 0);
    assert_int_equal(strlen(output), length);
    cJSON_Delete(response);
    os_free(output);
}

void test_wm_agent_upgrade_process_sha1_command(void **state) {
    char * buffer = *state;
    char *output = NULL;
    // sha1
    {
        expect_string(__wrap_w_ref_parent_folder, path, "test_file");
        will_return(__wrap_w_ref_parent_folder, 0);

        expect_any(__wrap_OS_SHA1_File, fname);
        expect_value(__wrap_OS_SHA1_File, mode, OS_BINARY);
        will_return(__wrap_OS_SHA1_File, "2c312ada12ab321a253ad321af65983fa412e3a1");
        will_return(__wrap_OS_SHA1_File, 0);
    }

    size_t length = wm_agent_upgrade_process_command(buffer, &output);
    cJSON *response = cJSON_Parse(output);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "2c312ada12ab321a253ad321af65983fa412e3a1");
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 0);
    assert_int_equal(strlen(output), length);
    cJSON_Delete(response);
    os_free(output);
}

void test_wm_agent_upgrade_process_upgrade_command(void **state) {
    char * buffer = *state;
    char *output = NULL;
    // upgrade
    {
        will_return(__wrap_getDefine_Int, 3600);
        // Unsign
        {
            expect_string(__wrap_w_ref_parent_folder, path, "test_file");
            will_return(__wrap_w_ref_parent_folder, 0);
            expect_string(__wrap_w_ref_parent_folder, path, "test_file");
            will_return(__wrap_w_ref_parent_folder, 0);

            #ifdef TEST_WINAGENT
                will_return(wrap_mktemp_s,  NULL);
                expect_string(__wrap_w_wpk_unsign, source, "incoming\\test_file");
            #else
                expect_string(__wrap_w_wpk_unsign, source, "var/incoming/test_file");

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

            expect_any(__wrap_gzopen, path);
            expect_string(__wrap_gzopen, mode, "rb");
            will_return(__wrap_gzopen, 4);

            expect_any(__wrap_wfopen, path);
            expect_string(__wrap_wfopen, mode, "wb");
            will_return(__wrap_wfopen, 5);

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
        expect_string(__wrap_chmod, path, "var/upgrade/install.sh");
        will_return(__wrap_chmod, 0);
        expect_string(__wrap_wm_exec, command, "var/upgrade/install.sh");

        #else
        expect_string(__wrap_wm_exec, command, "upgrade\\install.sh");
        #endif


        expect_value(__wrap_wm_exec, secs, 3600);
        expect_value(__wrap_wm_exec, add_path, NULL);
        will_return(__wrap_wm_exec, "OUTPUT COMMAND");
        will_return(__wrap_wm_exec, 0);
        will_return(__wrap_wm_exec, 0);
    }

    size_t length = wm_agent_upgrade_process_command(buffer, &output);
    cJSON *response = cJSON_Parse(output);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "0");
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 0);
    assert_int_equal(strlen(output), length);
    cJSON_Delete(response);
    os_free(output);
}

void test_wm_agent_upgrade_process_upgrade_not_allowed(void **state) {
    char * buffer = *state;
    char *output = NULL;

    size_t length = wm_agent_upgrade_process_command(buffer, &output);
    cJSON *response = cJSON_Parse(output);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Upgrade module is disabled or not ready yet");
    assert_int_not_equal(cJSON_GetObjectItem(response, "error")->valueint, 0);
    assert_int_equal(strlen(output), length);
    cJSON_Delete(response);
    os_free(output);
}

void test_wm_agent_upgrade_process_unknown(void **state) {
    char * buffer = *state;
    char *output = NULL;

    size_t length = wm_agent_upgrade_process_command(buffer, &output);
    cJSON *response = cJSON_Parse(output);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Command not found");
    assert_int_not_equal(cJSON_GetObjectItem(response, "error")->valueint, 0);
    assert_int_equal(strlen(output), length);
    cJSON_Delete(response);
    os_free(output);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_jailfile_invalid_path, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_jailfile_valid_path, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_unsign_invalid_source_incomming, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_unsign_invalid_source_temp, setup_jailfile, teardown_jailfile),
        #ifdef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_unsign_invalid_source_len, setup_jailfile_long_name, teardown_jailfile),
        #endif
        cmocka_unit_test_setup_teardown(test_unsign_temp_file_fail, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_unsign_wpk_using_fail, setup_jailfile, teardown_jailfile),
        #ifndef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_unsign_temp_chmod_fail, setup_jailfile, teardown_jailfile),
        #endif
        cmocka_unit_test_setup_teardown(test_unsign_success, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_uncompress_invalid_filename, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_uncompress_invalid_file_len, setup_jailfile_long_name2, teardown_jailfile),
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
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_sha1_sha_success, setup_sha1, teardown_commands),
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
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_clear_result_failed, setup_clear_result, teadown_clear_result),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_com_clear_result_success, setup_clear_result, teadown_clear_result),
        // Command dispatcher
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_clear_command, setup_process_clear_upgrade, teardown_process),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_open_no_parameters, setup_process_no_parameters, teardown_process),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_open_command, setup_process_open, teardown_process),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_write_command, setup_process_write, teardown_process),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_close_command, setup_process_close, teardown_process),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_sha1_command, setup_process_sha1, teardown_process),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_command, setup_process_upgrade, teardown_process),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_not_allowed, setup_process_upgrade_not_allowed, teardown_process),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_unknown, setup_process_unknown, teardown_process)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
