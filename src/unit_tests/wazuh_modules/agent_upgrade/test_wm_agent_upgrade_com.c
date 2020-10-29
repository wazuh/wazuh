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

#include "../../wrappers/common.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../../wrappers/libc/string_wrappers.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"
#include "../../wrappers/externals/zlib/zlib_wrappers.h"

extern int test_mode;

extern int _jailfile(char finalpath[PATH_MAX + 1], const char * basedir, const char * filename);
extern int _unsign(const char * source, char dest[PATH_MAX + 1]);
extern int _uncompress(const char * source, const char *package, char dest[PATH_MAX + 1]);

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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
