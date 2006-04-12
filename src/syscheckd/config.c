/*   $OSSEC, config.c, v0.2, 2005/07/14, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"

#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"

#include "syscheck.h"
#include "config/config.h"

int Read_Syscheck_Config(char * cfgfile)
{
    int modules = 0;

    modules|= CSYSCHECK;

    syscheck.rootcheck = 0;
    syscheck.time = SYSCHECK_WAIT*2;
    syscheck.notify = SYSLOG;


    if(ReadConfig(modules, cfgfile, &syscheck, NULL) < 0)
        return(OS_INVALID);


    return(0);
}
