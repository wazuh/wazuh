/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_crypto/blowfish Library
 * APIs for many crypto operations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/blowfish.h>
#include "bf_op.h"

typedef unsigned char uchar;


int OS_BF_Str(const char *input, char *output, const char *charkey,
              long size, short int action)
{
    BF_KEY key = {.P = {0}};
    static unsigned char cbc_iv [8] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char iv[8];

    memcpy(iv, cbc_iv, sizeof(iv));

    BF_set_key(&key, (int)strlen(charkey), (const uchar *)charkey);

    BF_cbc_encrypt((const uchar *)input, (uchar *)output, (long)size,
                   &key, iv, action);

    return (1);
}
