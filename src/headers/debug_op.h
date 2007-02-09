/* @(#) $Id$ */

/* Copyright (C) 2003-2007 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net
 */

/* Functions to generate debug/verbose/err reports.
 * Right now, we have two debug levels: 1,2,
 * a verbose mode and a error (merror) function.
 * To see these messages, use the "-d","-v" options
 * (or "-d" twice to see debug2). The merror is printed
 * by default when an important error occur.
 * */

#ifndef __DEBUG_H

#define __DEBUG_H

void debug1(const char *msg,...);

void debug2(const char *msg,...);

void merror(const char *msg,...);

void verbose(const char *msg,...);

void print_out(const char *msg,...);

void log2file(const char * msg,... );

void ErrorExit(const char *msg,...);


/* Use these three functions to set when you
 * enter in debug, chroot or daemon mode
 */
void nowDebug();

void nowChroot();

void nowDaemon();

int isChroot();

/* Debug analysisd */
#ifdef DEBUGAD 
    #define DEBUG_MSG(x,y,z) verbose(x,y,z)
#else
    #define DEBUG_MSG(x,y,z)
#endif /* end debug analysisd */

#endif
