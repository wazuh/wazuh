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


/* Read the config file (the remote access) */
int RemotedConfig(const char *cfgfile, remoted *cfg)
{
    int modules = 0;

    modules |= CREMOTE;

    cfg->port = NULL;
    cfg->conn = NULL;
    cfg->allowips = NULL;
    cfg->denyips = NULL;
    cfg->nocmerged = 0;
    cfg->queue_size = 16384;

    if (ReadConfig(modules, cfgfile, cfg, NULL) < 0) {
        return (OS_INVALID);
    }

    if (cfg->queue_size < 1) {
        merror("Queue size is invalid. Review configuration.");
        return OS_INVALID;
    }

    if (cfg->queue_size > 262144) {
        mwarn("Queue size is very high. The application may run out of memory.");
    }

    const char *(xmlf[]) = {"ossec_config", "cluster", "node_name", NULL};

    OS_XML xml;

    if (OS_ReadXML(cfgfile, &xml) < 0){
        merror_exit(XML_ERROR, cfgfile, xml.err, xml.err_line);
    }

    node_name = OS_GetOneContentforElement(&xml, xmlf);

    OS_ClearXML(&xml);

    return (1);
}
