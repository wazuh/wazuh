/* @(#) $Id: ./src/client-agent/config.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#include "shared.h"

#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"
#include "os_net/os_net.h"

#include "agentd.h"


/* Relocated from config_op.c */

/* ClientConf v0.2, 2005/03/03
 * Read the config file (for the remote client)
 * v0.2: New OS_XML
 */
int ClientConf(char *cfgfile)
{
    int modules = 0;
    agt->port = DEFAULT_SECURE;
    agt->rip = NULL;
    agt->lip = NULL;
    agt->rip_id = 0;
    agt->execdq = 0;
    agt->profile = NULL;   /*cmoraes*/

    modules|= CCLIENT;

    if(ReadConfig(modules, cfgfile, agt, NULL) < 0)
    {
        return(OS_INVALID);
    }

    return(1);
}


/* EOF */
