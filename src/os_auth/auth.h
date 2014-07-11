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

#ifdef USE_OPENSSL

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include "os_net/os_net.h"
#include "addagent/manage_agents.h"

BIO *bio_err;
#define KEYFILE  "/etc/sslmanager.key"
#define CERTFILE "/etc/sslmanager.cert"

SSL_CTX *os_ssl_keys(int is_server, char *os_dir, char *cert, char *key, char *ca_cert);
SSL_CTX *get_ssl_context();
int load_cert_and_key(SSL_CTX *ctx, char *cert, char *key);
int load_ca_cert(SSL_CTX *ctx, char *ca_cert);
int verify_callback(int ok, X509_STORE_CTX *store);

#endif /* USE_OPENSSL */
#endif /* _AUTHD_H */

