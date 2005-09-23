/*      $OSSEC, os_crypto/bf_op.h, v0.1, 2004/08/09, Daniel B. Cid$      */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_crypto/blowfish Library.
 * APIs for many crypto operations.
 * Available at http://www.ossec.net/c/os_crypto/
 */

#ifndef __BF_OP_H

#define __BF_OP_H

#define OS_ENCRYPT      1
#define OS_DECRYPT      0


char *OS_BF_Str(char * input, char *charkey, long size,
       short int action);

#endif

/* EOF */
