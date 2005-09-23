/*   $OSSEC, response/log.h, v0.2, 2005/02/08, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
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

void OS_Log(Eventinfo *lf);
void OS_Store(Eventinfo *lf);

#endif


