/*      $OSSEC, os_crypto/md5_op.h, v0.1, 2004/08/09, Daniel B. Cid$      */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_crypto/md5 Library.
 * APIs for many crypto operations.
 * Available at http://www.ossec.net/c/os_crypto/
 */

#ifndef __MD5_OP_H

#define __MD5_OP_H

typedef char os_md5[33];

int OS_MD5_File(char *fname, char * output);

int OS_MD5_Str(char * str, char * output);

#endif

/* EOF */
