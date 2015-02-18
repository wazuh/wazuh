/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __GETLL_H
#define __GETLL_H

#include "eventinfo.h"

/* Start the log location (need to be called before getlog) */
void OS_InitLog(void);
void OS_InitFwLog(void);

/* Get the log file based on the date/logtype
 * Returns 0 on success or -1 on error
 */
int OS_GetLogLocation(const Eventinfo *lf);

/* Global declarations */
extern FILE *_eflog;
extern FILE *_aflog;
extern FILE *_fflog;
extern FILE *_jflog;

#endif /* __GETLL_H */

