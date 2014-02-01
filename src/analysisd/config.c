/* @(#) $Id: ./src/analysisd/config.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


/* Functions to handle the configuration files
 */


#include "shared.h"

#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"

#include "analysisd.h"
#include "config.h"


/* GlobalConf vv0.2: 2005/03/03
 * v0.2: Changing to support the new OS_XML
 */
int GlobalConf(char * cfgfile)
{
    int modules = 0;


    /* Default values */
    Config.logall = 0;
    Config.stats = 4;
    Config.integrity = 8;
    Config.rootcheck = 8;
    Config.hostinfo = 8;
    Config.picviz = 0;
    Config.prelude = 0;
    Config.zeromq_output = 0;
    Config.zeromq_output_uri = NULL; 
    Config.memorysize = 1024;
    Config.mailnotify = -1;
    Config.keeplogdate = 0;
    Config.syscheck_alert_new = 0;
    Config.syscheck_auto_ignore = 1;
    Config.ar = 0;

    Config.syscheck_ignore = NULL;
    Config.white_list = NULL;
    Config.hostname_white_list = NULL;

    /* Default actions -- only log above level 1 */
    Config.mailbylevel = 7;
    Config.logbylevel  = 1;

    Config.custom_alert_output =0;
    Config.custom_alert_output_format = NULL;

    Config.includes = NULL;
    Config.lists = NULL;
    Config.decoders = NULL;

    modules|= CGLOBAL;
    modules|= CRULES;
    modules|= CALERTS;


    /* Reading config */
    if(ReadConfig(modules, cfgfile, &Config, NULL)< 0)
    {
        return(OS_INVALID);
    }

    /* Minimum memory size */
    if(Config.memorysize < 64)
        Config.memorysize = 64;


    return(0);
}



/* EOF */
