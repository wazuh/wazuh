/* @(#) $Id: ./src/os_auth/auth.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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


#ifndef _AUTHD_H
#define _AUTHD_H

#ifndef ARGV0
   #define ARGV0 "ossec-authd"
#endif

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef USE_OPENSSL

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "os_net/os_net.h"
#include "addagent/manage_agents.h"

BIO *bio_err;
#define KEYFILE  "/etc/sslmanager.key"
#define CERTFILE  "/etc/sslmanager.cert"

#define DNS_MAX_LABELS 127
#define DNS_MAX_LABEL_LEN 63

struct label_t
{
    char text[DNS_MAX_LABEL_LEN + 1];
    int len;
};

SSL_CTX *os_ssl_keys(int is_server, char *os_dir, char *cert, char *key, char *ca_cert);
SSL_CTX *get_ssl_context();
int load_cert_and_key(SSL_CTX *ctx, char *cert, char *key);
int load_ca_cert(SSL_CTX *ctx, char *ca_cert);
int verify_callback(int ok, X509_STORE_CTX *store);

/* Verification routines */
int check_x509_cert(SSL *ssl, char *manager, int is_ip);
int check_subject_alt_names(X509 *cert, char *manager, int is_ip);
int check_subject_cn(X509 *cert, char *manager);
int check_hostname(char *cert_name, char *manager_name);
int check_ipaddr(ASN1_STRING *cstr, char *manager);
int get_domain_name_labels(const char *domain_name, struct label_t result[DNS_MAX_LABELS]);
int validate_label(const struct label_t *label);
int compare_labels(const struct label_t *label1, const struct label_t *label2);

#endif

#endif
