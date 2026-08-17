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
#include <errno.h>

#include "shared.h"
#include "wmodules.h"
#include "wm_agent_upgrade.h"
#include "wm_agent_upgrade_agent.h"

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

extern char * wm_agent_upgrade_com_upgrade(const cJSON* json_object);

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
    assert_string_equal(cJSON_GetObjectItem(response_object, upgrade_json_keys[WM_UPGRADE_ERROR_MESSAGE])->valuestring, "Could not verify signature");
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
    assert_string_equal(cJSON_GetObjectItem(response_object, upgrade_json_keys[WM_UPGRADE_ERROR_MESSAGE])->valuestring, "Could not uncompress package");
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
    assert_string_equal(cJSON_GetObjectItem(response_object, upgrade_json_keys[WM_UPGRADE_ERROR_MESSAGE])->valuestring, "Could not clean up upgrade directory");
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
    assert_string_equal(cJSON_GetObjectItem(response_object, upgrade_json_keys[WM_UPGRADE_ERROR_MESSAGE])->valuestring, "Error unmerging file");
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
    assert_string_equal(cJSON_GetObjectItem(response_object, upgrade_json_keys[WM_UPGRADE_ERROR_MESSAGE])->valuestring, "Invalid file name");
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
    assert_string_equal(cJSON_GetObjectItem(response_object, upgrade_json_keys[WM_UPGRADE_ERROR_MESSAGE])->valuestring, "Could not chmod");
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
    assert_string_equal(cJSON_GetObjectItem(response_object, upgrade_json_keys[WM_UPGRADE_ERROR_MESSAGE])->valuestring, "Error executing command");
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
    assert_string_equal(cJSON_GetObjectItem(response_object, upgrade_json_keys[WM_UPGRADE_ERROR_MESSAGE])->valuestring, "0");
    cJSON_Delete(response_object);
    os_free(response);
}

/* Process commands */
int teardown_process(void **state) {
    char *buffer = *state;
    os_free(buffer);
    allow_upgrades = true;
    test_mode = 0;
    return 0;
}

int setup_process_upgrade_no_parameters(void **state) {
    cJSON * command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "command", "upgrade");
    char *ptr = cJSON_PrintUnformatted(command);
    *state = ptr;
    cJSON_Delete(command);
    test_mode = 1;
    // This test is about the missing-parameters error path specifically, not the
    // allow_upgrades gate (covered separately by *_not_allowed below), and the com
    // tests above never route through wm_agent_upgrade_process_command() so the
    // module-level allow_upgrades flag is otherwise left at its initial false.
    allow_upgrades = true;
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
    cJSON_AddStringToObject(command, "command", "upgrade");
    cJSON * parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "file", "test_file");
    cJSON_AddStringToObject(parameters, "installer", "install.sh");
    cJSON_AddItemToObject(command, "parameters", parameters);
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

void test_wm_agent_upgrade_process_upgrade_no_parameters(void **state) {
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
        // Command dispatcher
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_no_parameters, setup_process_upgrade_no_parameters, teardown_process),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_command, setup_process_upgrade, teardown_process),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_not_allowed, setup_process_upgrade_not_allowed, teardown_process),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_unknown, setup_process_unknown, teardown_process)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
