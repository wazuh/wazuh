/* @(#) $Id$ */

/* Copyright (C) 2004-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "syscheck.h"
#include "config/config.h"

int Read_Syscheck_Config(char * cfgfile)
{
    int modules = 0;

    modules|= CSYSCHECK;

    syscheck.rootcheck = 0;
    syscheck.time = SYSCHECK_WAIT*2;

    if(ReadConfig(modules, cfgfile, &syscheck, NULL) < 0)
        return(OS_INVALID);


    return(0);
}
