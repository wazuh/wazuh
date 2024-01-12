/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>

int __wrap_PEM_write_PrivateKey(FILE *out,
                                const EVP_PKEY *x,
                                const EVP_CIPHER *enc,
                                const unsigned char *kstr,
                                int klen,
                                pem_password_cb *cb,
                                void *u);

int __wrap_PEM_write_X509(FILE *out, const X509 *x);
