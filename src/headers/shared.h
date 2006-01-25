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
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/select.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <dirent.h>

/* Making Windows happy */
#ifndef WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#else
#include <winsock.h>
#endif

#include <time.h>
#include <errno.h>

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
#include "validate_op.h"

#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"

#include "error_messages/error_messages.h"

/* Global portability code */

#ifdef SOLARIS
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;
#endif /* SOLARIS */

/* For Darwin */
#ifdef Darwin
typedef int socklen_t;
#endif

/* For Windows */
#ifdef WIN32
typedef int uid_t;
typedef int gid_t;
#endif

/* For AIX */
#ifdef AIX
#define MSG_DONTWAIT MSG_NONBLOCK
#endif


/*** Global prototypes ***/
/*** These functions will exit on error. No need to check return code ***/

/* for calloc: x = calloc(4,sizeof(char)) -> os_calloc(4,sizeof(char),x) */
#define os_calloc(x,y,z) (z = calloc(x,y))?1:ErrorExit(MEM_ERROR, ARGV0) 

#define os_strdup(x,y) (y = strdup(x))?1:ErrorExit(MEM_ERROR, ARGV0)

#define os_free(x) (x)?free(x):merror("free a null")

#endif /* __SHARED_H */

/* EOF */
