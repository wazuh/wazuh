/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <sys/statvfs.h>

#include "shared.h"
#include "signature.h"
#include "../../wrappers/common.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"

#define CONTENT_LEN 10000
#define WPK_SIGNLEN 256

static const char PAYLOAD[] = "appended after the content was read";

static char test_dir[64];
static char work_dir[128];
static char ca_path[128];
static const char * ca_store[2];
static EVP_PKEY * key;
static X509 * cert;
static unsigned char content[CONTENT_LEN];

// File to append PAYLOAD to right before the signature is checked
static const char * append_on_verify;

// File to append PAYLOAD to while its content is being read
static const char * append_on_read;

// Free space fstatvfs() reports, when set
static bool no_free_space;

int __real_EVP_PKEY_verify(EVP_PKEY_CTX * ctx, const unsigned char * sig, size_t siglen, const unsigned char * tbs, size_t tbslen);

int __wrap_EVP_PKEY_verify(EVP_PKEY_CTX * ctx, const unsigned char * sig, size_t siglen, const unsigned char * tbs, size_t tbslen) {
    if (append_on_verify) {
        FILE * fp = fopen(append_on_verify, "ab");

        if (fp) {
            fwrite(PAYLOAD, 1, sizeof(PAYLOAD), fp);
            fclose(fp);
        }
    }

    return __real_EVP_PKEY_verify(ctx, sig, siglen, tbs, tbslen);
}

int __real_EVP_DigestUpdate(EVP_MD_CTX * ctx, const void * data, size_t count);

int __wrap_EVP_DigestUpdate(EVP_MD_CTX * ctx, const void * data, size_t count) {
    if (append_on_read) {
        FILE * fp = fopen(append_on_read, "ab");

        if (fp) {
            fwrite(PAYLOAD, 1, sizeof(PAYLOAD), fp);
            fclose(fp);
        }

        append_on_read = NULL;
    }

    return __real_EVP_DigestUpdate(ctx, data, count);
}

int __real_fstatvfs(int fd, struct statvfs * buf);

int __wrap_fstatvfs(int fd, struct statvfs * buf) {
    int ret = __real_fstatvfs(fd, buf);

    if (ret == 0 && no_free_space) {
        buf->f_bavail = 0;
    }

    return ret;
}

static void join(char out[PATH_MAX], const char * name) {
    snprintf(out, PATH_MAX, "%s/%s", work_dir, name);
}

static X509 * make_ca_cert(EVP_PKEY * pkey) {
    X509 * x = X509_new();
    X509_NAME * name;
    X509V3_CTX v3;
    X509_EXTENSION * ext;

    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), -60);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, pkey);
    name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"wpk test", -1, -1, 0);
    X509_set_issuer_name(x, name);
    X509V3_set_ctx_nodb(&v3);
    X509V3_set_ctx(&v3, x, x, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &v3, NID_basic_constraints, "critical,CA:TRUE");
    X509_add_ext(x, ext, -1);
    X509_EXTENSION_free(ext);
    X509_sign(x, pkey, EVP_sha256());
    return x;
}

// Writes a WPK256 file holding data, signed by the test key
static void write_wpk(const char * path, const unsigned char * data, size_t len) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned char sig[WPK_SIGNLEN];
    size_t siglen = sizeof(sig);
    EVP_PKEY_CTX * ctx;
    FILE * fp;

    EVP_Digest(data, len, digest, NULL, EVP_sha256(), NULL);
    ctx = EVP_PKEY_CTX_new(key, NULL);
    assert_non_null(ctx);
    assert_int_equal(EVP_PKEY_sign_init(ctx), 1);
    assert_true(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0);
    assert_true(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) > 0);
    assert_int_equal(EVP_PKEY_sign(ctx, sig, &siglen, digest, sizeof(digest)), 1);
    assert_int_equal(siglen, WPK_SIGNLEN);
    EVP_PKEY_CTX_free(ctx);

    fp = fopen(path, "wb");
    assert_non_null(fp);
    assert_int_equal(fwrite("WPK256", 1, sizeof("WPK256"), fp), sizeof("WPK256"));
    assert_int_equal(PEM_write_X509(fp, cert), 1);
    assert_int_equal(fputc('\0', fp), 0);
    assert_int_equal(fwrite(sig, 1, siglen, fp), siglen);
    assert_int_equal(fwrite(data, 1, len, fp), len);
    assert_int_equal(fclose(fp), 0);
}

static void assert_file_equals(const char * path, const unsigned char * data, size_t len) {
    unsigned char * read_back;
    struct stat st;
    FILE * fp;

    assert_int_equal(stat(path, &st), 0);
    assert_int_equal((size_t)st.st_size, len);
    os_malloc(len, read_back);
    fp = fopen(path, "rb");
    assert_non_null(fp);
    assert_int_equal(fread(read_back, 1, len, fp), len);
    fclose(fp);
    assert_memory_equal(read_back, data, len);
    os_free(read_back);
}

static void expect_opening_error(int error) {
    // expect_string() keeps the pointer until the call is checked
    static char msg[PATH_MAX + OS_SIZE_256];

    snprintf(msg, sizeof(msg), "opening input file: %s", strerror(error));
    expect_string(__wrap__merror, formatted_msg, msg);
}

/* setups/teardowns */

static int setup_group(void ** state) {
    FILE * fp;
    size_t i;

    test_mode = 1;
    snprintf(test_dir, sizeof(test_dir), "/tmp/test_signature_XXXXXX");

    if (!mkdtemp(test_dir)) {
        return -1;
    }

    if (key = EVP_RSA_gen(2048), !key) {
        return -1;
    }

    cert = make_ca_cert(key);
    snprintf(ca_path, sizeof(ca_path), "%s/ca.pem", test_dir);
    snprintf(work_dir, sizeof(work_dir), "%s/work", test_dir);

    if (mkdir(work_dir, 0700) < 0) {
        return -1;
    }

    if (fp = fopen(ca_path, "w"), !fp) {
        return -1;
    }

    PEM_write_X509(fp, cert);
    fclose(fp);
    ca_store[0] = ca_path;
    ca_store[1] = NULL;

    for (i = 0; i < CONTENT_LEN; i++) {
        content[i] = (unsigned char)(i * 31 + 7);
    }

    return 0;
}

static int teardown_group(void ** state) {
    rmdir_ex(test_dir);
    X509_free(cert);
    EVP_PKEY_free(key);
    test_mode = 0;
    return 0;
}

static int teardown_test(void ** state) {
    append_on_verify = NULL;
    append_on_read = NULL;
    no_free_space = false;
    return cldir_ex(work_dir);
}

/* tests */

void test_w_wpk_unsign_ok(void ** state) {
    char source[PATH_MAX];
    char target[PATH_MAX];

    join(source, "agent.wpk");
    join(target, "out");
    write_wpk(source, content, sizeof(content));

    assert_int_equal(w_wpk_unsign(source, target, ca_store), 0);
    assert_file_equals(target, content, sizeof(content));
}

void test_w_wpk_unsign_tampered_content(void ** state) {
    char source[PATH_MAX];
    char target[PATH_MAX];
    FILE * fp;

    join(source, "agent.wpk");
    join(target, "out");
    write_wpk(source, content, sizeof(content));

    fp = fopen(source, "ab");
    assert_non_null(fp);
    fwrite(PAYLOAD, 1, sizeof(PAYLOAD), fp);
    fclose(fp);

    expect_string(__wrap__merror, formatted_msg, "Failed to verify signature.");

    assert_int_equal(w_wpk_unsign(source, target, ca_store), -1);
}

void test_w_wpk_unsign_bad_magic(void ** state) {
    char source[PATH_MAX];
    char target[PATH_MAX];
    FILE * fp;

    join(source, "agent.wpk");
    join(target, "out");
    fp = fopen(source, "wb");
    assert_non_null(fp);
    fwrite("WPK128", 1, sizeof("WPK128"), fp);
    fclose(fp);

    expect_string(__wrap__merror, formatted_msg, "Invalid input file (bad magic number).");

    assert_int_equal(w_wpk_unsign(source, target, ca_store), -1);
}

// The output holds the verified content only
void test_w_wpk_unsign_append_after_read(void ** state) {
    char source[PATH_MAX];
    char target[PATH_MAX];

    join(source, "agent.wpk");
    join(target, "out");
    write_wpk(source, content, sizeof(content));
    append_on_verify = source;

    assert_int_equal(w_wpk_unsign(source, target, ca_store), 0);
    assert_file_equals(target, content, sizeof(content));
}

// Only the size the file had when opened is read
void test_w_wpk_unsign_grows_while_read(void ** state) {
    char source[PATH_MAX];
    char target[PATH_MAX];

    join(source, "agent.wpk");
    join(target, "out");
    write_wpk(source, content, sizeof(content));
    append_on_read = source;

    assert_int_equal(w_wpk_unsign(source, target, ca_store), 0);
    assert_file_equals(target, content, sizeof(content));
}

void test_w_wpk_unsign_no_free_space(void ** state) {
    char source[PATH_MAX];
    char target[PATH_MAX];
    static char msg[PATH_MAX + OS_SIZE_256];

    join(source, "agent.wpk");
    join(target, "out");
    write_wpk(source, content, sizeof(content));
    no_free_space = true;
    snprintf(msg, sizeof(msg), "Not enough disk space to extract '%s'.", source);
    expect_string(__wrap__merror, formatted_msg, msg);

    assert_int_equal(w_wpk_unsign(source, target, ca_store), -1);
}

void test_w_wpk_unsign_output_error(void ** state) {
    char source[PATH_MAX];
    char target[PATH_MAX];
    static char msg[PATH_MAX + OS_SIZE_256];

    join(source, "agent.wpk");
    join(target, "missing/out");
    write_wpk(source, content, sizeof(content));
    snprintf(msg, sizeof(msg), "Opening output file: %s", strerror(ENOENT));
    expect_string(__wrap__merror, formatted_msg, msg);

    assert_int_equal(w_wpk_unsign(source, target, ca_store), -1);
}

void test_w_wpk_unsign_symlink(void ** state) {
    char real[PATH_MAX];
    char source[PATH_MAX];
    char target[PATH_MAX];

    join(real, "real.wpk");
    join(source, "agent.wpk");
    join(target, "out");
    write_wpk(real, content, sizeof(content));
    assert_int_equal(symlink(real, source), 0);

    expect_opening_error(ELOOP);

    assert_int_equal(w_wpk_unsign(source, target, ca_store), -1);
}

void test_w_wpk_unsign_hardlink(void ** state) {
    char real[PATH_MAX];
    char source[PATH_MAX];
    char target[PATH_MAX];

    join(real, "real.wpk");
    join(source, "agent.wpk");
    join(target, "out");
    write_wpk(real, content, sizeof(content));
    assert_int_equal(link(real, source), 0);

    expect_opening_error(EMLINK);

    assert_int_equal(w_wpk_unsign(source, target, ca_store), -1);
}

// A FIFO is rejected without blocking
void test_w_wpk_unsign_fifo(void ** state) {
    char source[PATH_MAX];
    char target[PATH_MAX];

    join(source, "agent.wpk");
    join(target, "out");
    assert_int_equal(mkfifo(source, 0600), 0);

    expect_opening_error(EINVAL);

    assert_int_equal(w_wpk_unsign(source, target, ca_store), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_w_wpk_unsign_ok, teardown_test),
        cmocka_unit_test_teardown(test_w_wpk_unsign_tampered_content, teardown_test),
        cmocka_unit_test_teardown(test_w_wpk_unsign_bad_magic, teardown_test),
        cmocka_unit_test_teardown(test_w_wpk_unsign_append_after_read, teardown_test),
        cmocka_unit_test_teardown(test_w_wpk_unsign_grows_while_read, teardown_test),
        cmocka_unit_test_teardown(test_w_wpk_unsign_no_free_space, teardown_test),
        cmocka_unit_test_teardown(test_w_wpk_unsign_output_error, teardown_test),
        cmocka_unit_test_teardown(test_w_wpk_unsign_symlink, teardown_test),
        cmocka_unit_test_teardown(test_w_wpk_unsign_hardlink, teardown_test),
        cmocka_unit_test_teardown(test_w_wpk_unsign_fifo, teardown_test),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
