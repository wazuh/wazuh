/*   $OSSEC, shared.h, v0.2, 2005/12/23, Daniel B. Cid$   */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.2 (2005/12/23): Adding 'u_int16_t' for Solaris.
 * v0.1 (2005/10/27): first version.
 */

#ifndef __SHARED_H

#define __SHARED_H

/* Global headers */
#include <sys/types.h>
#include <stdio.h>

#include "defs.h"
#include "help.h"

#include "os_err.h"

#include "debug_op.h"
#include "file_op.h"
#include "mem_op.h"
#include "mq_op.h"
#include "privsep_op.h"
#include "pthreads_op.h"
#include "regex_op.h"
#include "sig_op.h"
#include "rc.h"
#include "ar.h"

#include "error_messages/error_messages.h"


#ifdef SOLARIS
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;
#endif /* SOLARIS */


#endif /* __SHARED_H */

/* EOF */
