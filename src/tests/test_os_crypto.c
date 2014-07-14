/* Copyright (C) 2014 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <check.h>
#include <stdlib.h>

#include "../os_crypto/blowfish/bf_op.h"
#include "../os_crypto/md5/md5_op.h"
#include "../os_crypto/sha1/sha1_op.h"
#include "../os_crypto/md5_sha1/md5_sha1_op.h"

Suite *test_suite(void);

START_TEST(test_blowfish)
{
    const char *key = "test_key";
    const char *string = "test string";
    const int buffersize = 1024;
    char buffer1[buffersize];
    char buffer2[buffersize];

    OS_BF_Str(string, buffer1, key, buffersize, OS_ENCRYPT);
    OS_BF_Str(buffer1, buffer2, key, buffersize, OS_DECRYPT);

    ck_assert_str_eq(buffer2, string);
}
END_TEST

START_TEST(test_md5string)
{
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    os_md5 buffer;

    OS_MD5_Str(string, buffer);

    ck_assert_str_eq(buffer, string_md5);
}
END_TEST

START_TEST(test_md5file)
{
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_md5 buffer;
    ck_assert_int_eq(OS_MD5_File(file_name, buffer), 0);

    ck_assert_str_eq(buffer, string_md5);
}
END_TEST

START_TEST(test_md5file_fail)
{
    os_md5 buffer;
    ck_assert_int_eq(OS_MD5_File("not_existing_file", buffer), -1);
}
END_TEST

START_TEST(test_sha1file)
{
    const char *string = "teststring";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_sha1 buffer;
    ck_assert_int_eq(OS_SHA1_File(file_name, buffer), 0);

    ck_assert_str_eq(buffer, string_sha1);
}
END_TEST

START_TEST(test_sha1file_fail)
{
    os_sha1 buffer;
    ck_assert_int_eq(OS_SHA1_File("not_existing_file", buffer), -1);
}
END_TEST

START_TEST(test_md5sha1file)
{
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_md5 md5buffer;
    os_sha1 sha1buffer;

    ck_assert_int_eq(OS_MD5_SHA1_File(file_name, NULL, md5buffer, sha1buffer), 0);

    ck_assert_str_eq(md5buffer, string_md5);
    ck_assert_str_eq(sha1buffer, string_sha1);
}
END_TEST

START_TEST(test_md5sha1cmdfile)
{
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_md5 md5buffer;
    os_sha1 sha1buffer;

    ck_assert_int_eq(OS_MD5_SHA1_File(file_name, "cat ", md5buffer, sha1buffer), 0);

    ck_assert_str_eq(md5buffer, string_md5);
    ck_assert_str_eq(sha1buffer, string_sha1);
}
END_TEST

START_TEST(test_md5sha1cmdfile_fail)
{
    os_md5 md5buffer;
    os_sha1 sha1buffer;

    ck_assert_int_eq(OS_MD5_SHA1_File("not_existing_file", NULL, md5buffer, sha1buffer), -1);
}
END_TEST

Suite *test_suite(void)
{
    Suite *s = suite_create("os_crypto");

    TCase *tc_blowfish = tcase_create("blowfish");
    tcase_add_test(tc_blowfish, test_blowfish);

    TCase *tc_md5 = tcase_create("md5");
    tcase_add_test(tc_md5, test_md5string);
    tcase_add_test(tc_md5, test_md5file);
    tcase_add_test(tc_md5, test_md5file_fail);

    TCase *tc_sha1 = tcase_create("sha1");
    tcase_add_test(tc_sha1, test_sha1file);
    tcase_add_test(tc_sha1, test_sha1file_fail);

    TCase *tc_md5sha1 = tcase_create("md5_sha1");
    tcase_add_test(tc_md5sha1, test_md5sha1file);
    tcase_add_test(tc_md5sha1, test_md5sha1cmdfile);
    tcase_add_test(tc_md5sha1, test_md5sha1cmdfile_fail);

    suite_add_tcase(s, tc_blowfish);
    suite_add_tcase(s, tc_md5);
    suite_add_tcase(s, tc_sha1);
    suite_add_tcase(s, tc_md5sha1);

    return (s);
}

int main(void)
{
    Suite *s = test_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return ((number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
}
