/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <openssl/rsa.h>

int __wrap_RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb);

/**
 * @brief Wrapper for RSA_new.
 * If the first mock is not null, the wrapper will return a real call to RSA_new, otherwise, it will return a mock RSA *
 *
 * @return RSA* Real structure in case the first mock is not null, a mock otherwise.
 */
RSA * __wrap_RSA_new(void);

extern RSA *__real_RSA_new(void);
