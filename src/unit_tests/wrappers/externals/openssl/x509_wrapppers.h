/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <openssl/x509.h>

int __wrap_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);

X509 *__wrap_X509_new(void);
extern X509 *__real_X509_new(void);
