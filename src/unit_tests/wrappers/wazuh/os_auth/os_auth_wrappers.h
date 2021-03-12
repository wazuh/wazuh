/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef OS_AUTH_WRAPPERS_H
#define OS_AUTH_WRAPPERS_H

#include <openssl/ssl.h>
#include <headers/shared.h>
#include <headers/sec.h>

SSL_CTX *__wrap_os_ssl_keys(int is_server, const char *os_dir, const char *ciphers, const char *cert, const char *key,
                            const char *ca_cert, int auto_method);

int __wrap_check_x509_cert(const SSL *ssl, const char *manager);

void __wrap_add_remove(const keyentry *entry);

#endif
