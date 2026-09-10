/*
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"
#include "x509_op.h"

/* Frozen test material (public certificates only), also used by test_enrollment_token:
 *  - ROOT_CA_PEM: the CA, SPKI pin 6091dc36...0aa2, no subject alternative names.
 *  - LEAF_PEM: a listener certificate signed by that CA, CN wazuh-1, SAN IP:127.0.0.1,
 *    DNS:wazuh-manager, DNS:localhost, DNS:host.docker.internal, DNS:wazuh-1.
 *  - LOOPBACK_PEM: self-signed, CN loopback-only, SAN DNS:localhost, IP:127.0.0.1, IP:::1.
 */
#define ROOT_CA_PEM \
    "-----BEGIN CERTIFICATE-----\n" \
    "MIIDSzCCAjOgAwIBAgIUJP7/SAPLSdxLbWKDzjDp88k4AAAwDQYJKoZIhvcNAQEL\n" \
    "BQAwNTEOMAwGA1UECwwFV2F6dWgxDjAMBgNVBAoMBVdhenVoMRMwEQYDVQQHDApD\n" \
    "YWxpZm9ybmlhMB4XDTI2MDQxNDEzNTAzN1oXDTM2MDQxMTEzNTAzN1owNTEOMAwG\n" \
    "A1UECwwFV2F6dWgxDjAMBgNVBAoMBVdhenVoMRMwEQYDVQQHDApDYWxpZm9ybmlh\n" \
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQFyQMfZg9BkCde6Sa6O\n" \
    "8834rzeI81clYfEuDjflnwUTyp6BwHZTZ4F/cOBchKt2ZtnNR7Vx2wU5muDdF1QR\n" \
    "xnzDEV3vqETcGN7dxarYQtNCuvi/V0Zm0rme9Q9tW8u4iVwhva/jB5VJuDxlREfH\n" \
    "RL9pcjf9Dmvr1A9QRBgN0gsofAPri6gi8fLOfqddyNhLDHVd4BhYvB4wgxN5gXs/\n" \
    "KOCPGBhIuBb7BbdZDXMm+1PrBebZ1PgL1NEN4dtLQEq7/JXsJpeh8HGsH+WA91V7\n" \
    "HRI6O2nsT7YEiw4lGK/DfNroPrQ+G5Qq+Ouy5Z+8NnWV/WJu6tsv2TtqVCNG2Ift\n" \
    "vwIDAQABo1MwUTAdBgNVHQ4EFgQU2CaFfHEP1s0zMeo5QL/yLQl69EAwHwYDVR0j\n" \
    "BBgwFoAU2CaFfHEP1s0zMeo5QL/yLQl69EAwDwYDVR0TAQH/BAUwAwEB/zANBgkq\n" \
    "hkiG9w0BAQsFAAOCAQEAW2F0iQS92w4Q1im3ijS9qg2rnLuzrFeLkbhDNc1P4UIR\n" \
    "Wst/FKUV0MsYBvbotf2gNWSZEsKqDV5kYB4Ad1RUFIJGq0HEnrLEIgXZDgUkHaLQ\n" \
    "2FXSWDbq4Q3tROB2SiXk61Md6HOvfgT4/MYx/IoZB3fE8pP0vINA/TPw6WZsbz+K\n" \
    "93PEjHaMASUlUoowImFgV4uxzgfVWYWcUwi+IUehMqBgU3apvZ1ntUgw8CZTR7BQ\n" \
    "E3f6uPqaFJnQg2NZpc0bST6iF/bwKemDhdtd0pwgTivB3RrgSDjBqcR0DGTCKydU\n" \
    "gifB+SqxOI0UFNS5zvIQzUTRxMVDcdnB4NnkcZ/CBQ==\n" \
    "-----END CERTIFICATE-----\n"

#define LEAF_PEM \
    "-----BEGIN CERTIFICATE-----\n" \
    "MIID2DCCAsCgAwIBAgIUQcNO9z95jw8UN2qvaK01c2ct7b0wDQYJKoZIhvcNAQEL\n" \
    "BQAwNTEOMAwGA1UECwwFV2F6dWgxDjAMBgNVBAoMBVdhenVoMRMwEQYDVQQHDApD\n" \
    "YWxpZm9ybmlhMB4XDTI2MDkwNzIzMDgyMloXDTM2MDkwNDIzMDgyMlowVDELMAkG\n" \
    "A1UEBhMCVVMxEzARBgNVBAcMCkNhbGlmb3JuaWExDjAMBgNVBAoMBVdhenVoMQ4w\n" \
    "DAYDVQQLDAVXYXp1aDEQMA4GA1UEAwwHd2F6dWgtMTCCASIwDQYJKoZIhvcNAQEB\n" \
    "BQADggEPADCCAQoCggEBAMvfNwpc9p1Jle9xYGqevBKluw8mM2zMJTsCuIFTLkPF\n" \
    "dPs+LJTPLsALsVq7up0CZidtjliywLumwzC+oKWp1nPC6UoQb6M5jvtl0VuVHvKB\n" \
    "j1jSGRej886pggeytBdPO6Cp2todUtLvHM+uwseb4qtyjEQutk6CbEaFpkngGsCB\n" \
    "/NZ4kOL1GQhnq2raT3B/AlsW8RN26iJikBhrHRaqqqGLRFa7XYj39wjPtx2Urs4p\n" \
    "qkQNSgR+xtDYCkNX5PHdzKiMmdWwoLZIwPxMG3RSB0ixEUQO8DFtOKvk4WHoeKoU\n" \
    "3wxkAhofWJbM2S5HbVOH9cnewyzNmvWxBJYG8aI2qo0CAwEAAaOBwDCBvTAfBgNV\n" \
    "HSMEGDAWgBTYJoV8cQ/WzTMx6jlAv/ItCXr0QDAdBgNVHQ4EFgQU8hFY3dAJ/GsP\n" \
    "PKyzLSDkb51VonkwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0l\n" \
    "BAwwCgYIKwYBBQUHAwEwSAYDVR0RBEEwP4cEfwAAAYINd2F6dWgtbWFuYWdlcoIJ\n" \
    "bG9jYWxob3N0ghRob3N0LmRvY2tlci5pbnRlcm5hbIIHd2F6dWgtMTANBgkqhkiG\n" \
    "9w0BAQsFAAOCAQEAWv+qe+VgCsESlg8ubbx7Ftzci0Wco8x399OLanQuKvp8560k\n" \
    "nf0T5+kghdj6KxRshgTmVXgEpd1G9tiVFk2z2phy90LGgat2HYwzaIfzuA7DqbyM\n" \
    "v5DNnF7UcqhRC5WOL3XDb2zWQMfYScyvUAF58B1MEFPATkdi6zN6/0yroX9B6SLe\n" \
    "iPTDEB8jFG9R6qtMYftP+7ZOacKo0Fy0rRdhlQZNl1i5gunUWrpD2w+9EYfYDrXn\n" \
    "MykvRq++INuyYbizQMFYSHiYmjpm7XJwlgH1F8p5YxxSs0RagtH0ZERlC8yv7NEK\n" \
    "cdIcE8DrGEViL31/r8a6SCRb1c8Tdi7ukLQCXg==\n" \
    "-----END CERTIFICATE-----\n"

#define LOOPBACK_PEM \
    "-----BEGIN CERTIFICATE-----\n" \
    "MIIDQDCCAiigAwIBAgIUThyXoTqzjTsSr+M69T0+JScLXu8wDQYJKoZIhvcNAQEL\n" \
    "BQAwGDEWMBQGA1UEAwwNbG9vcGJhY2stb25seTAeFw0yNjA5MDgwMjI0MzJaFw0z\n" \
    "NjA5MDUwMjI0MzJaMBgxFjAUBgNVBAMMDWxvb3BiYWNrLW9ubHkwggEiMA0GCSqG\n" \
    "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDq+eTb7H0adqFTdCDrNvie0ev96Lyp8Ylq\n" \
    "dJ2Z4XsVxuwktn2HiSjwVyHy5VSaXwMcgv2Rruvi6e5Qd8vohic9+n134KKOmdF2\n" \
    "yC3WwACxncNJ7NFHnAwhxJ/Rr/v0pjzKPwlL0p4HvdlpU44C3jH9FMeO0hpWnmhd\n" \
    "9Kkdu3ddBl7EelF3Ci4JssrDfJNZeCVlmA5fvSZm4K8OGVlZ1ey8pLsvYyiUnDEp\n" \
    "Y0/9ycSnK8Qq2Wd8S4OREozjOBIyvtjEtboFGZ0ZqaNeL08bRJVAX1iN95bfMxps\n" \
    "PG4ZFYe30CGnDcmJwequYqISProAdzOh7qu0paABUqPYIDgsiY4dAgMBAAGjgYEw\n" \
    "fzAdBgNVHQ4EFgQUOhrcgGqECnVp3LH1+Lwio2kaySQwHwYDVR0jBBgwFoAUOhrc\n" \
    "gGqECnVp3LH1+Lwio2kaySQwDwYDVR0TAQH/BAUwAwEB/zAsBgNVHREEJTAjggls\n" \
    "b2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJKoZIhvcNAQELBQAD\n" \
    "ggEBADvvvKOjfrZLUneG7igz8rZgKa8a0+TxUYDr/3524zX+tlalDpB9JAhicYe+\n" \
    "gfm47kKn91UM07MT0X25iln5EfYA2gCWTF/4OTr+L+6ISIQDhbgxh5FmPworp7tT\n" \
    "eDP5CDhsutAzbTCsnEZw9pa/E2QK6CkgIwipWEnKwit0VaXVr/y+M0d6szbPBuS9\n" \
    "sMgW5tGQkTdhnsnrrOwuTrGjwqyJa25zM+a53gRi0C07h/2b+5a4oguqAQT0BkHN\n" \
    "T5quif12xKlcTs7Mlp/MpPgf4JNyiA6SVgeHqN2PFzph62mm+UIlEh8LX9MZlubo\n" \
    "suHg+PvT3ygd27X96wMZ11OhRYI=\n" \
    "-----END CERTIFICATE-----\n"

/* SPKI pin of ROOT_CA_PEM, in lowercase hexadecimal */
#define CA_PIN_HEX "6091dc3665ed5e833c8d945f93ebbf14b37020ccee77334e4497ac2ef3590aa2"

static void hex_of(const uint8_t *bytes, size_t len, char *out)
{
    size_t i;

    for (i = 0; i < len; i++) {
        snprintf(out + i * 2, 3, "%02x", bytes[i]);
    }
}

/* Write PEM text to a temporary file, since w_x509_load_pem() takes a path */
static char *write_temp_pem(const char *pem)
{
    char *path = strdup("/tmp/wazuh_test_x509_XXXXXX");
    int fd = -1;
    size_t len = strlen(pem);

    assert_non_null(path);
    fd = mkstemp(path);
    assert_true(fd >= 0);
    assert_int_equal(write(fd, pem, len), (int) len);
    assert_int_equal(close(fd), 0);

    return path;
}

static X509 *load_pem_text(const char *pem)
{
    char *path = write_temp_pem(pem);
    X509 *cert = w_x509_load_pem(path);

    unlink(path);
    free(path);

    return cert;
}

/* w_x509_load_all_pem / w_x509_certificates_pem */

void test_load_all_pem_reads_every_certificate_of_a_bundle(void **state)
{
    (void) state;

    char *bundle = (char *) calloc(strlen(LEAF_PEM) + strlen(ROOT_CA_PEM) + 1, sizeof(char));
    char *path = NULL;
    X509 **certs = NULL;
    size_t count = 0;

    assert_non_null(bundle);
    strcat(bundle, LEAF_PEM);
    strcat(bundle, ROOT_CA_PEM);
    path = write_temp_pem(bundle);

    certs = w_x509_load_all_pem(path, &count);

    /* w_x509_load_pem() would have stopped at the leaf: a signer listed second is invisible to it */
    assert_non_null(certs);
    assert_int_equal(count, 2);
    assert_true(w_x509_signed_by(certs[0], certs[1]));

    w_x509_free_all(certs, count);
    unlink(path);
    free(path);
    free(bundle);
}

void test_load_all_pem_skips_a_private_key_and_refuses_a_corrupt_block(void **state)
{
    (void) state;

    char *combined = (char *) calloc(strlen(ROOT_CA_PEM) + 256, sizeof(char));
    char *path = NULL;
    X509 **certs = NULL;
    size_t count = 0;

    /* A CA certificate followed by something that is not one: the certificate is read, the rest
     * is not part of what we would publish */
    assert_non_null(combined);
    strcat(combined, ROOT_CA_PEM);
    strcat(combined, "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQ==\n-----END PRIVATE KEY-----\n");
    path = write_temp_pem(combined);

    certs = w_x509_load_all_pem(path, &count);
    assert_non_null(certs);
    assert_int_equal(count, 1);

    w_x509_free_all(certs, count);
    unlink(path);
    free(path);

    /* A certificate block that cannot be decoded refuses the whole file, prefix included */
    strcpy(combined, ROOT_CA_PEM);
    strcat(combined, "-----BEGIN CERTIFICATE-----\nnot base64 at all!!\n-----END CERTIFICATE-----\n");
    path = write_temp_pem(combined);

    count = 12345;
    assert_null(w_x509_load_all_pem(path, &count));
    assert_int_equal(count, 0);

    unlink(path);
    free(path);
    free(combined);

    /* And a path that does not exist */
    assert_null(w_x509_load_all_pem("/nonexistent/wazuh-test-ca.pem", &count));
    assert_null(w_x509_load_all_pem(NULL, &count));
}

void test_certificates_pem_publishes_only_certificates(void **state)
{
    (void) state;

    char *combined = (char *) calloc(strlen(ROOT_CA_PEM) + 256, sizeof(char));
    char *path = NULL;
    char *published = NULL;
    X509 **certs = NULL;
    X509 **reparsed = NULL;
    size_t count = 0;
    size_t reparsed_count = 0;

    assert_non_null(combined);
    strcat(combined, ROOT_CA_PEM);
    strcat(combined, "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQ==\n-----END PRIVATE KEY-----\n");
    path = write_temp_pem(combined);

    certs = w_x509_load_all_pem(path, &count);
    assert_non_null(certs);

    published = w_x509_certificates_pem(certs, count);
    assert_non_null(published);
    assert_non_null(strstr(published, "BEGIN CERTIFICATE"));
    assert_null(strstr(published, "PRIVATE KEY"));

    /* What we emit parses back: the document is usable, not merely stripped */
    unlink(path);
    free(path);
    path = write_temp_pem(published);
    reparsed = w_x509_load_all_pem(path, &reparsed_count);
    assert_non_null(reparsed);
    assert_int_equal(reparsed_count, count);

    w_x509_free_all(reparsed, reparsed_count);
    w_x509_free_all(certs, count);
    free(published);
    unlink(path);
    free(path);
    free(combined);

    assert_null(w_x509_certificates_pem(NULL, 0));
}

/* w_x509_spki_sha256 */

void test_spki_sha256_matches_the_frozen_pin(void **state)
{
    X509 *cert = load_pem_text(ROOT_CA_PEM);
    uint8_t digest[32];
    char hex[sizeof(digest) * 2 + 1];

    (void) state;

    assert_non_null(cert);
    assert_int_equal(w_x509_spki_sha256(cert, digest), 0);
    hex_of(digest, sizeof(digest), hex);
    assert_string_equal(hex, CA_PIN_HEX);

    /* The leaf has its own key pair, so it must never pin to the same value */
    X509_free(cert);
    cert = load_pem_text(LEAF_PEM);
    assert_non_null(cert);
    assert_int_equal(w_x509_spki_sha256(cert, digest), 0);
    hex_of(digest, sizeof(digest), hex);
    assert_string_not_equal(hex, CA_PIN_HEX);
    X509_free(cert);

    assert_int_equal(w_x509_spki_sha256(NULL, digest), -1);
}

/* w_x509_load_pem */

void test_load_pem_takes_the_first_certificate_of_a_bundle(void **state)
{
    char *bundle = NULL;
    X509 *cert = NULL;
    char subject[256];

    (void) state;

    /* A leaf followed by its CA, the shape of the installed remoted.pem */
    bundle = (char *) calloc(strlen(LEAF_PEM) + strlen(ROOT_CA_PEM) + 1, sizeof(char));
    assert_non_null(bundle);
    strcpy(bundle, LEAF_PEM);
    strcat(bundle, ROOT_CA_PEM);

    cert = load_pem_text(bundle);
    free(bundle);
    assert_non_null(cert);

    assert_non_null(X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject)));
    assert_non_null(strstr(subject, "CN=wazuh-1"));
    X509_free(cert);

    assert_null(w_x509_load_pem("/this/path/does/not/exist.pem"));
    assert_null(w_x509_load_pem(NULL));
}

/* w_x509_signed_by */

void test_signed_by(void **state)
{
    X509 *ca = load_pem_text(ROOT_CA_PEM);
    X509 *leaf = load_pem_text(LEAF_PEM);
    X509 *loopback = load_pem_text(LOOPBACK_PEM);

    (void) state;

    assert_non_null(ca);
    assert_non_null(leaf);
    assert_non_null(loopback);

    assert_int_equal(w_x509_signed_by(leaf, ca), 1);
    assert_int_equal(w_x509_signed_by(ca, leaf), 0);
    assert_int_equal(w_x509_signed_by(loopback, ca), 0);
    assert_int_equal(w_x509_signed_by(NULL, ca), 0);
    assert_int_equal(w_x509_signed_by(leaf, NULL), 0);

    X509_free(loopback);
    X509_free(leaf);
    X509_free(ca);
}

/* w_x509_san_matches */

void test_san_matches(void **state)
{
    X509 *leaf = load_pem_text(LEAF_PEM);
    X509 *loopback = load_pem_text(LOOPBACK_PEM);

    (void) state;

    assert_non_null(leaf);
    assert_non_null(loopback);

    assert_int_equal(w_x509_san_matches(leaf, "wazuh-1"), 1);
    /* DNS matching is case insensitive */
    assert_int_equal(w_x509_san_matches(leaf, "WAZUH-1"), 1);
    assert_int_equal(w_x509_san_matches(leaf, "127.0.0.1"), 1);
    assert_int_equal(w_x509_san_matches(leaf, "wazuh-manager.example"), 0);
    assert_int_equal(w_x509_san_matches(leaf, "evil"), 0);
    assert_int_equal(w_x509_san_matches(leaf, "192.0.2.10"), 0);

    /* The subject common name never counts: loopback-only names itself in its CN only */
    assert_int_equal(w_x509_san_matches(loopback, "loopback-only"), 0);
    assert_int_equal(w_x509_san_matches(loopback, "localhost"), 1);

    assert_int_equal(w_x509_san_matches(NULL, "wazuh-1"), 0);
    assert_int_equal(w_x509_san_matches(leaf, NULL), 0);
    assert_int_equal(w_x509_san_matches(leaf, ""), 0);

    X509_free(loopback);
    X509_free(leaf);
}

/* w_x509_san_is_loopback_only */

void test_san_is_loopback_only(void **state)
{
    X509 *leaf = load_pem_text(LEAF_PEM);
    X509 *loopback = load_pem_text(LOOPBACK_PEM);
    X509 *ca = load_pem_text(ROOT_CA_PEM);

    (void) state;

    assert_non_null(leaf);
    assert_non_null(loopback);
    assert_non_null(ca);

    assert_int_equal(w_x509_san_is_loopback_only(loopback), 1);
    assert_int_equal(w_x509_san_is_loopback_only(leaf), 0);
    /* No subject alternative name extension at all: nothing reachable is named */
    assert_int_equal(w_x509_san_is_loopback_only(ca), 1);
    assert_int_equal(w_x509_san_is_loopback_only(NULL), 0);

    X509_free(ca);
    X509_free(loopback);
    X509_free(leaf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_load_all_pem_reads_every_certificate_of_a_bundle),
        cmocka_unit_test(test_load_all_pem_skips_a_private_key_and_refuses_a_corrupt_block),
        cmocka_unit_test(test_certificates_pem_publishes_only_certificates),
        cmocka_unit_test(test_spki_sha256_matches_the_frozen_pin),
        cmocka_unit_test(test_load_pem_takes_the_first_certificate_of_a_bundle),
        cmocka_unit_test(test_signed_by),
        cmocka_unit_test(test_san_matches),
        cmocka_unit_test(test_san_is_loopback_only)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
