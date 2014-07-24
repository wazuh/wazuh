/* @(#) $Id: ./src/config/config.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */



#ifndef _HCONFIG__H
#define _HCONFIG__H

#define CGLOBAL       0000001
#define CRULES        0000002
#define CSYSCHECK     0000004
#define CROOTCHECK    0000010
#define CALERTS       0000020
#define CLOCALFILE    0000040
#define CREMOTE       0000100
#define CCLIENT       0000200
#define CMAIL         0000400
#define CAR           0001000
#define CDBD          0002000
#define CSYSLOGD      0004000
#define CAGENTLESS    0020000
#define CREPORTS      0040000

#define CAGENT_CONFIG 0010000

#include "os_xml/os_xml.h"


/* Main function to read the config */
int ReadConfig(int modules, const char *cfgfile, void *d1, void *d2);

int Read_Global(XML_NODE node, void *d1, void *d2);
int Read_GlobalSK(XML_NODE node, void *configp, void *mailp);
int Read_Rules(XML_NODE node, void *d1, void *d2);
int Read_Syscheck(XML_NODE node, void *d1, void *d2);
int Read_Rootcheck(XML_NODE node, void *d1, void *d2);
int Read_Alerts(XML_NODE node, void *d1, void *d2);
int Read_EmailAlerts(XML_NODE node, void *d1, void *d2);
int Read_DB(XML_NODE node, void *config1, void *config2);
int Read_CSyslog(XML_NODE node, void *config1, void *config2);
int Read_CAgentless(XML_NODE node, void *config1, void *config2);
int Read_Localfile(XML_NODE node, void *d1, void *d2);
int Read_Remote(XML_NODE node, void *d1, void *d2);
int Read_Client(XML_NODE node, void *d1, void *d2);
int ReadActiveResponses(XML_NODE node, void *d1, void *d2);
int ReadActiveCommands(XML_NODE node, void *d1, void *d2);
int Read_CReports(XML_NODE node, void *config1, void *config2);


/* General config, for passing blobs of data. */
typedef struct _GeneralConfig
{
    void *data;
}GeneralConfig;


#endif
