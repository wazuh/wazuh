/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef CHECK_CERT_OP_WRAPPERS_H
#define CHECK_CERT_OP_WRAPPERS_H

#include <openssl/ssl.h>

int __wrap_check_x509_cert(const SSL *ssl, const char *manager);

#endif
