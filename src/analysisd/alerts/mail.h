/*   $OSSEC, response/mail.h, v0.2, 2005/02/08, Daniel B. Cid$   */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software 
 * Foundation
 */

/* Basic e-mailing operations */

#ifndef _MAIL__H

#define _MAIL__H

#include "eventinfo.h"

void OS_Createmail(int *mailq, Eventinfo *lf);

#endif
