/*      $OSSEC, debug_op.h, v0.1, 2004/08/02, Daniel B. Cid$      */

/* Copyright (C) 2003,2004 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net/hids/
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

void ErrorExit(const char *msg,...);

#endif
