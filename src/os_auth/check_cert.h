/* Copyright (C) 2014 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 */

#ifndef _CHECK_CERT_H
#define _CHECK_CERT_H

#ifdef LIBOPENSSL_ENABLED

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define VERIFY_TRUE   1
#define VERIFY_FALSE  0
#define VERIFY_ERROR -1

#define DNS_MAX_LABELS    127
#define DNS_MAX_LABEL_LEN 63

typedef struct label_t {
    char text[DNS_MAX_LABEL_LEN + 1];
    size_t len;
}
label;

int check_x509_cert(const SSL *ssl, const char *manager);
int check_subject_alt_names(X509 *cert, const char *manager);
int check_subject_cn(X509 *cert, const char *manager);
int check_hostname(ASN1_STRING *cert_astr, const char *manager);
int check_ipaddr(const ASN1_STRING *cert_astr, const char *manager);
int label_array(const char *domain_name, label result[DNS_MAX_LABELS]);
int label_valid(const label *label);
int label_match(const label *label1, const label *label2);
char *asn1_to_cstr(ASN1_STRING *astr);

#endif /* LIBOPENSSL_ENABLED */
#endif /* _CHECK_CERT_H */

