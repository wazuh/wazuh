/*   $OSSEC, config.c, v0.1, 2005/09/30, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "rootcheck.h"
#include "config/config.h"



/* Read_Rootcheck_Config: Reads the rootcheck config
 */
int Read_Rootcheck_Config(char * cfgfile)
{
    int modules = 0;

    modules|= CROOTCHECK;

    if(ReadConfig(modules, cfgfile, &rootcheck, NULL) < 0)
        return(OS_INVALID);

    return(0);
}

/* EOF */
