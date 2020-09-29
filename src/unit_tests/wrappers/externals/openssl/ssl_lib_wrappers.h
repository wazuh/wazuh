/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SSL_LIB_WRAPPERS_H
#define SSL_LIB_WRAPPERS_H

#include <openssl/ssl.h>

int __wrap_SSL_read(SSL *ssl, void *buf, int num);

int __wrap_SSL_connect(SSL *s);

int __wrap_SSL_get_error(const SSL *s, int i);

int __wrap_SSL_write(SSL *ssl, const void *buf, int num);

SSL *__wrap_SSL_new(SSL_CTX *ctx);

void __wrap_SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio);

#endif
