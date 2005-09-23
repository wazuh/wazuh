/*   $OSSEC, exec.h, v0.2, 2005/02/08, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software 
 * Foundation
 */


#ifndef _EXEC__H

#define _EXEC__H

#include "rules.h"
#include "eventinfo.h"

void OS_Exec(int *execq, short int *notify, int position, 
		Eventinfo *lf, char *msgtolog);

#endif
