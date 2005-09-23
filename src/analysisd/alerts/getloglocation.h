/*   $OSSEC, getloglocation.h, v0.2, 2005/04/25, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
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

#define EVENTS  "/logs/archives"
#define ALERTS  "/logs/alerts"

#endif /* GETLL_H */
