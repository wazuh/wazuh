/*    $OSSEC, os_crypto/blowfish_op.c, v0.2, 2005/09/17, Daniel B. Cid$  */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.2 (2005/09/17): uchar fixes
 * v0.1 (2005/01/29)
 */

/* OS_crypto/blowfish Library.
 * APIs for many crypto operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blowfish.h"

#include "bf_op.h"

typedef unsigned char uchar;

int OS_BF_Str(const char *input, char *output, const char *charkey,
                long size, short int action)
{
    BF_KEY key;
    static unsigned char cbc_iv [8]={0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    unsigned char iv[8];

    memcpy(iv,cbc_iv,sizeof(iv));

    BF_set_key(&key, (int)strlen(charkey), (uchar *)charkey);

    BF_cbc_encrypt((uchar *)input, (uchar *)output, (long)size,
            &key, iv, action);

    return(1);
}

/* EOF */
