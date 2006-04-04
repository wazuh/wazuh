/*   $OSSEC, pthreads_op.h, v0.1, 2005/09/23, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef PTHREADS_OP_H
#define PTHREADS_OP_H

#ifndef WIN32
int CreateThread(void *function_pointer(void *data), void *data);
#endif

#endif
