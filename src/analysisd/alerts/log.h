/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Basic logging operations */

#ifndef __LOG_H
#define __LOG_H

#include "eventinfo.h"

#define FWDROP "drop"
#define FWALLOW "accept"

void OS_LogOutput(Eventinfo *lf);
void OS_Log(Eventinfo *lf);
void OS_CustomLog(Eventinfo *lf, char *format);
void OS_Store(Eventinfo *lf);
int FW_Log(Eventinfo *lf);

#endif

