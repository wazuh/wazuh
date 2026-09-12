/*
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Small X509 helpers shared by the certificate and enrollment token code paths. Every IP
 * literal goes through OpenSSL (a2i_IPADDRESS, X509_check_ip_asc) instead of the POSIX
 * resolver so that this file also builds for the Windows agent.
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "shared.h"
#include "check_cert_op.h"
#include "x509_op.h"

/* Number of bytes of an IPv4 and an IPv6 address as stored in an iPAddress SAN entry */
#define X509_OP_IPV4_LEN 4
#define X509_OP_IPV6_LEN 16

/* Whether a raw iPAddress SAN entry is a loopback address */
static int x509_ip_is_loopback(const unsigned char *raw, int raw_len)
{
    static const unsigned char ipv6_loopback[X509_OP_IPV6_LEN] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    };

    if (raw == NULL) {
        return 0;
    }

    if (raw_len == X509_OP_IPV4_LEN) {
        return raw[0] == 127;
    }

    if (raw_len == X509_OP_IPV6_LEN) {
        return memcmp(raw, ipv6_loopback, X509_OP_IPV6_LEN) == 0;
    }

    return 0;
}

X509 *w_x509_load_pem(const char *path)
{
    BIO *bio = NULL;
    X509 *cert = NULL;

    if (path == NULL) {
        return NULL;
    }

    if ((bio = BIO_new_file(path, "r")) == NULL) {
        return NULL;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    return cert;
}

X509 **w_x509_load_all_pem(const char *path, size_t *count)
{
    BIO *bio = NULL;
    X509 **certs = NULL;
    X509 *cert = NULL;
    size_t total = 0;
    int well_formed = 0;

    if (count != NULL) {
        *count = 0;
    }

    if (path == NULL) {
        return NULL;
    }

    if ((bio = BIO_new_file(path, "r")) == NULL) {
        ERR_clear_error();
        return NULL;
    }

    /* PEM_read_bio_X509() skips blocks that are not a CERTIFICATE, so a combined key+cert file or
     * a bundle yields exactly its certificates */
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        os_realloc(certs, sizeof(X509 *) * (total + 1), certs);
        certs[total++] = cert;
    }

    /* The only clean way out of the loop is end of input; anything else means a block we could not
     * decode, and then the whole file is refused (issue #39078, H01) */
    well_formed = (ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE);
    ERR_clear_error();
    BIO_free(bio);

    if (!well_formed || total == 0) {
        w_x509_free_all(certs, total);
        return NULL;
    }

    if (count != NULL) {
        *count = total;
    }

    return certs;
}

void w_x509_free_all(X509 **certs, size_t count)
{
    size_t i;

    if (certs == NULL) {
        return;
    }

    for (i = 0; i < count; i++) {
        X509_free(certs[i]);
    }

    os_free(certs);
}

char *w_x509_certificates_pem(X509 **certs, size_t count)
{
    BIO *bio = NULL;
    char *data = NULL;
    char *out = NULL;
    long length = 0;
    size_t i;

    if (certs == NULL || count == 0) {
        return NULL;
    }

    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        ERR_clear_error();
        return NULL;
    }

    for (i = 0; i < count; i++) {
        if (PEM_write_bio_X509(bio, certs[i]) != 1) {
            ERR_clear_error();
            BIO_free(bio);
            return NULL;
        }
    }

    length = BIO_get_mem_data(bio, &data);

    if (data != NULL && length > 0) {
        os_calloc((size_t)length + 1, sizeof(char), out);
        memcpy(out, data, (size_t)length);
    }

    BIO_free(bio);

    return out;
}

int w_x509_spki_sha256(X509 *cert, uint8_t out[32])
{
    X509_PUBKEY *pubkey = NULL;
    unsigned char *der = NULL;
    int der_len = 0;

    if (cert == NULL || out == NULL) {
        return -1;
    }

    if ((pubkey = X509_get_X509_PUBKEY(cert)) == NULL) {
        return -1;
    }

    if ((der_len = i2d_X509_PUBKEY(pubkey, &der)) <= 0 || der == NULL) {
        return -1;
    }

    SHA256(der, (size_t) der_len, out);
    OPENSSL_free(der);

    return 0;
}

int w_x509_signed_by(X509 *leaf, X509 *ca)
{
    EVP_PKEY *pkey = NULL;

    if (leaf == NULL || ca == NULL) {
        return 0;
    }

    if ((pkey = X509_get0_pubkey(ca)) == NULL) {
        return 0;
    }

    return (X509_verify(leaf, pkey) == 1) ? 1 : 0;
}

int w_x509_san_matches(X509 *cert, const char *host)
{
    ASN1_OCTET_STRING *ip = NULL;

    if (cert == NULL || host == NULL || *host == '\0') {
        return 0;
    }

    /* An IP literal never matches a dNSName entry, and the other way around */
    if ((ip = a2i_IPADDRESS(host)) != NULL) {
        ASN1_OCTET_STRING_free(ip);
        return (X509_check_ip_asc(cert, host, 0) == 1) ? 1 : 0;
    }

    return (X509_check_host(cert, host, 0,
                            X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS |
                            X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, NULL) == 1) ? 1 : 0;
}

int w_x509_san_is_loopback_only(X509 *cert)
{
    GENERAL_NAMES *names = NULL;
    int loopback_only = 1;
    int i = 0;

    if (cert == NULL) {
        return 0;
    }

    if ((names = (GENERAL_NAMES *) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL,
                                                    NULL)) == NULL) {
        /* No subject alternative name extension: the certificate names nothing reachable */
        return 1;
    }

    for (i = 0; i < sk_GENERAL_NAME_num(names) && loopback_only == 1; i++) {
        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

        if (name == NULL) {
            loopback_only = 0;
        } else if (name->type == GEN_DNS) {
            char *dns = asn1_to_cstr(name->d.dNSName);

            if (dns == NULL || strcasecmp(dns, "localhost") != 0) {
                loopback_only = 0;
            }

            free(dns);
        } else if (name->type == GEN_IPADD) {
            if (!x509_ip_is_loopback(ASN1_STRING_get0_data(name->d.iPAddress),
                                     ASN1_STRING_length(name->d.iPAddress))) {
                loopback_only = 0;
            }
        } else {
            loopback_only = 0;
        }
    }

    GENERAL_NAMES_free(names);

    return loopback_only;
}
