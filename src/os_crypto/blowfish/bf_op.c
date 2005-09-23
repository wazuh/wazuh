/*    $OSSEC, os_crypto/blowfish_op.c, v0.2, 2005/09/17, Daniel B. Cid$  */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
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
 * Available at http://www.ossec.net/c/os_crypto/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blowfish.h"

#include "bf_op.h"

typedef unsigned char uchar;

char *OS_BF_Str(char *input, char *charkey, long size, 
	short int action)
{
    BF_KEY key;
    static unsigned char cbc_iv [8]={0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    unsigned char iv[8];
    char *output = NULL;

    output = calloc(size+1, sizeof(char));
    if(output == NULL)
        return(NULL);

    memcpy(iv,cbc_iv,sizeof(iv));

    BF_set_key(&key, strlen(charkey), (uchar *)charkey);

    BF_cbc_encrypt((uchar *)input, (uchar *)output, size,
            &key, iv, action);

    return(output);
}

/* EOF */
