/* @(#) $Id: ./src/remoted/config.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
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

#include "remoted.h"
#include "config/config.h"


/* RemotedConfig v0.4, 2006/04/10
 * Read the config file (the remote access)
 * v0.2: New OS_XML
 * v0.3: Some improvements and cleanup
 * v0.4: Move everything to the global config validator.
 */
int RemotedConfig(const char *cfgfile, remoted *cfg)
{
    int modules = 0;

    modules|= CREMOTE;

    cfg->port = NULL;
    cfg->conn = NULL;
    cfg->allowips = NULL;
    cfg->denyips = NULL;

    if(ReadConfig(modules, cfgfile, cfg, NULL) < 0)
        return(OS_INVALID);

    return(1);
}


/* EOF */
