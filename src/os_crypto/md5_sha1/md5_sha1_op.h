/* @(#) $Id$ */

/* Copyright (C) 2007 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/* OS_crypto/md5 Library.
 * APIs for many crypto operations.
 */

#ifndef __MD5SHA1_OP_H
#define __MD5SHA1_OP_H


int OS_MD5_SHA1_File(char *fname, char *md5output, char *sha1output);


#endif

/* EOF */
