/* @(#) $Id: ./src/headers/sig_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Functions to handle signal manipulation
 */

#ifndef __SIG_H

#define __SIG_H

void HandleSIG(int sig) __attribute__((noreturn));
void HandleSIGPIPE(int sig);

/* Start signal manipulation */
void StartSIG(const char *process_name);

/* Start signal manipulation -- function as an argument */
void StartSIG2(const char *process_name, void (*func)(int));

#endif
