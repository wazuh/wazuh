/* @(#) $Id: ./src/analysisd/alerts/getloglocation.h, 2011/09/08 dcid Exp $
 */

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

/*
 * Start the log location (need to be called before getlog)
 *
 */
void OS_InitLog();

void OS_InitFwLog();

/*
 * Get the log file based on the date/logtype/
 *
 * @param lf        Event structure
 *
 * @retval 0        success
 *         -1       error
 */
int OS_GetLogLocation(Eventinfo *lf);


FILE *_eflog;
FILE *_aflog;
FILE *_fflog;

#endif /* GETLL_H */
