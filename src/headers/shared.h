/* @(#) $Id: ./src/headers/shared.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.3 (2007/12/23): Adding SSP & FORTIFY_SOURCE <jeffschroeder@computer.org>
 * v0.2 (2005/12/23): Adding 'u_int16_t' for Solaris.
 * v0.1 (2005/10/27): first version.
 */

/*
 *  The stack smashing protector defeats some BoF via: gcc -fstack-protector
 *  Reference: http://gcc.gnu.org/onlinedocs/gcc-4.1.2/cpp.pdf
 */

#if defined(__GNUC__) && (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 1) && (__GNUC_PATCHLEVEL__ >= 2)) || \
                          ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 2)) || \
                           (__GNUC__ >= 5))

/* Heuristicly enable the stack protector on sensitive functions */
#define __SSP__ 1

/* FORTIFY_SOURCE is Redhat / Fedora specific */
#define FORTIFY_SOURCE
#endif

#ifndef __SHARED_H

#define __SHARED_H
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif


/* Global headers */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>


/* Making windows happy */
#ifndef WIN32
#include <sys/wait.h>

/* HPUX does not have select.h */
#ifndef HPUX
#include <sys/select.h>
#endif

#include <sys/utsname.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>

/* Making Windows happy */
#ifndef WIN32
#include <glob.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#endif

#include <time.h>
#include <errno.h>

#include "defs.h"
#include "help.h"

#include "os_err.h"

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif


/* Global portability code */

#ifdef SOLARIS
#include <limits.h>
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;

#ifndef va_copy
#define va_copy __va_copy
#endif

#endif /* SOLARIS */


/* For HP-UX */
#if defined HPUX
#include <limits.h>
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;

#define MSG_DONTWAIT 0
#endif


/* For Darwin */
#ifdef Darwin
typedef int sock2len_t;
#endif


#ifndef WIN32
#define CloseSocket(x) close(x)
#endif


/* For Windows */
#ifdef WIN32
typedef int uid_t;
typedef int gid_t;
typedef int socklen_t;
#define sleep(x) Sleep(x * 1000)
#define srandom(x) srand(x)
#define random(x) rand(x)
#define lstat(x,y) stat(x,y)
#define CloseSocket(x) closesocket(x)
void WinSetError();
typedef unsigned short int u_int16_t;
typedef unsigned char u_int8_t;
/* typedef closesocket close; */

#define MSG_DONTWAIT    0

#ifndef PROCESSOR_ARCHITECTURE_AMD64
 #define PROCESSOR_ARCHITECTURE_AMD64 9
#endif
#endif

/* For AIX */
#ifdef AIX
#define MSG_DONTWAIT MSG_NONBLOCK
#endif



/* Local name */
char *__local_name;


/*** Global prototypes ***/
/*** These functions will exit on error. No need to check return code ***/

/* for calloc: x = calloc(4,sizeof(char)) -> os_calloc(4,sizeof(char),x) */
#define os_calloc(x,y,z) ((z = calloc(x,y)))?(void)1:ErrorExit(MEM_ERROR, ARGV0)

#define os_strdup(x,y) ((y = strdup(x)))?(void)1:ErrorExit(MEM_ERROR, ARGV0)

#define os_malloc(x,y) ((y = malloc(x)))?(void)1:ErrorExit(MEM_ERROR, ARGV0)

#define os_free(x) (x)?free(x):merror("free a null")

#define os_realloc(x,y,z) ((z = realloc(x,y)))?(void)1:ErrorExit(MEM_ERROR, ARGV0)

#define os_clearnl(x,p) if((p = strrchr(x, '\n')))*p = '\0';

#ifdef CLIENT
    #define isAgent 1
#else
    #define isAgent 0
#endif



#include "debug_op.h"
#include "wait_op.h"
#include "agent_op.h"
#include "file_op.h"
#include "mem_op.h"
#include "math_op.h"
#include "mq_op.h"
#include "privsep_op.h"
#include "pthreads_op.h"
#include "regex_op.h"
#include "sig_op.h"
#include "list_op.h"
#include "dirtree_op.h"
#include "hash_op.h"
#include "store_op.h"
#include "rc.h"
#include "ar.h"
#include "validate_op.h"
#include "file-queue.h"
#include "read-agents.h"
#include "report_op.h"
#include "string_op.h"

#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"

#include "error_messages/error_messages.h"
#include "custom_output_search.h"


#endif /* __SHARED_H */

/* EOF */
