// #include "lib_tap.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <defs.h>

#include "../os_crypto/blowfish/bf_op.h"
#include "../os_crypto/md5/md5_op.h"
#include "../os_crypto/sha1/sha1_op.h"
#include "../os_crypto/md5_sha1/md5_sha1_op.h"
#include "tap.h"

int test_blowfish() {
    const char *key = "test_key";
    const char *string = "test string";
    const int buffersize = 1024;
    char buffer1[buffersize];
    char buffer2[buffersize];

    OS_BF_Str(string, buffer1, key, buffersize, OS_ENCRYPT);
    OS_BF_Str(buffer1, buffer2, key, buffersize, OS_DECRYPT);

    w_assert_str_eq(buffer2, string);
    return 1;
}

int test_md5_string() {
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";
    os_md5 buffer;

    OS_MD5_Str(string, -1, buffer);

    w_assert_str_eq(buffer, string_md5);
    return 1;
}

int test_md5_file() {
    const char *string = "teststring";
    const char *string_md5 = "d67c5cbf5b01c9f91932e3b8def5e5f8";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_md5 buffer;
    w_assert_int_eq(OS_MD5_File(file_name, buffer, OS_TEXT), 0);

    w_assert_str_eq(buffer, string_md5);
    return 1;
}

int test_md5_file_fail() {
    os_md5 buffer;
    w_assert_int_eq(OS_MD5_File("not_existing_file", buffer, OS_TEXT), -1);
    return 1;
}

int test_sha1_string() {
    const char *string = "teststring";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_sha1 buffer;
    w_assert_int_eq(OS_SHA1_File(file_name, buffer, OS_TEXT), 0);

    w_assert_str_eq(buffer, string_sha1);
    return 1;
}

int test_sha1_file() {
    const char *string = "teststring";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";

    /* create tmp file */
    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);
    int fd = mkstemp(file_name);

    write(fd, string, strlen(string));
    close(fd);

    os_sha1 buffer;
    w_assert_int_eq(OS_SHA1_File(file_name, buffer, OS_TEXT), 0);

    w_assert_str_eq(buffer, string_sha1);
    return 1;
}

int test_sha1_file_fail() {
    os_sha1 buffer;
    w_assert_int_eq(OS_SHA1_File("not_existing_file", buffer, OS_TEXT), -1);
    return 1;
}

int test_md5_sha1_file() {
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

    w_assert_int_eq(OS_MD5_SHA1_File(file_name, NULL, md5buffer, sha1buffer, OS_TEXT), 0);

    w_assert_str_eq(md5buffer, string_md5);
    w_assert_str_eq(sha1buffer, string_sha1);
    return 1;
}

int test_md5_sha1_cmd_file() {
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

    w_assert_int_eq(OS_MD5_SHA1_File(file_name, "cat ", md5buffer, sha1buffer, OS_TEXT), 0);

    w_assert_str_eq(md5buffer, string_md5);
    w_assert_str_eq(sha1buffer, string_sha1);
    return 1;
}

int test_md5_sha1_cmd_file_fail() {
    os_md5 md5buffer;
    os_sha1 sha1buffer;

    w_assert_int_eq(OS_MD5_SHA1_File("not_existing_file", NULL, md5buffer, sha1buffer, OS_TEXT), -1);
    return 1;
}

int main(void) {
    printf("\n\n   STARTING TEST - OS_CRYPTO   \n\n");

    // Encrypts and decrypts a string using blowfish algorithm
    TAP_TEST_MSG(test_blowfish(), "Blowfish encryption test.");

    // Encrypts a string using MD5 algorithm
    TAP_TEST_MSG(test_md5_string(), "MD5 encryption test.");

    // Encrypts text readed from a temporal file using MD5 algorithm
    TAP_TEST_MSG(test_md5_file(), "MD5 file reading encryption test.");

    // Attempts to read from a non-existing file.
    TAP_TEST_MSG(test_md5_file_fail(), "MD5 non-existing file to read from.");

    // Encrypts a string using SHA1 algorithm
    TAP_TEST_MSG(test_sha1_string(), "SHA1 encryption test.");

    // Encrypts text readed from a temporal file using SHA1 algorithm
    TAP_TEST_MSG(test_sha1_file(), "SHA1 file reading encryption test.");

    // Attempts to read from a non-existing file.
    TAP_TEST_MSG(test_sha1_file_fail(), "SHA1 non-existing file to read from.");

    // Encrypts text readed from a temporal file using SHA1 and MD5 algorithm
    TAP_TEST_MSG(test_md5_sha1_file(), "MD5+SHA1 file reading encryption test.");

    // Encrypts text readed executing a command using SHA1 and MD5 algorithm
    TAP_TEST_MSG(test_md5_sha1_cmd_file(), "MD5+SHA1 reading from file using command encryption test.");

    // Attempts to read from a non-existing file.
    TAP_TEST_MSG(test_md5_sha1_cmd_file_fail(), "MD5+SHA1 non-existing file to read from using command.");

    TAP_PLAN;
    TAP_SUMMARY;
    printf("\n    ENDING TEST  - OS_CRYPTO   \n\n");
    return 0;
}