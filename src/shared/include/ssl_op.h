/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
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

#ifndef SSL_OP_H
#define SSL_OP_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define KEYFILE             "etc/sslmanager.key"
#define CERTFILE            "etc/sslmanager.cert"
#define DEFAULT_CIPHERS     "HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH"
#define MAX_SSL_PACKET_SIZE 16384

extern BIO* bio_err;

SSL_CTX* os_ssl_keys(int is_server,
                     const char* os_dir,
                     const char* ciphers,
                     const char* cert,
                     const char* key,
                     const char* ca_cert,
                     int auto_method);
SSL_CTX* get_ssl_context(const char* ciphers, int auto_method);
int load_cert_and_key(SSL_CTX* ctx, const char* cert, const char* key);
int load_ca_cert(SSL_CTX* ctx, const char* ca_cert);
int verify_callback(int ok, X509_STORE_CTX* store);
int wrap_SSL_read(SSL* ssl, void* buf, int num);

#endif // SSL_OP_H
