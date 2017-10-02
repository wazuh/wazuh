/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _HCONFIG__H
#define _HCONFIG__H

#define CGLOBAL       00000001
#define CRULES        00000002
#define CSYSCHECK     00000004
#define CROOTCHECK    00000010
#define CALERTS       00000020
#define CLOCALFILE    00000040
#define CREMOTE       00000100
#define CCLIENT       00000200
#define CMAIL         00000400
#define CAR           00001000
#define CDBD          00002000
#define CSYSLOGD      00004000
#define CAGENT_CONFIG 00010000
#define CAGENTLESS    00020000
#define CREPORTS      00040000
#define CINTEGRATORD  00100000
#define CWMODULE      00200000
#define CLABELS       00400000
#define CAUTHD        01000000
#define CBUFFER       02000000

#define UDP_PROTO   6
#define TCP_PROTO   17

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
int Read_Integrator(XML_NODE node, void *config1, void *config2);
int Read_Remote(XML_NODE node, void *d1, void *d2);
int Read_Client(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_ClientBuffer(XML_NODE node, void *d1, void *d2);
int ReadActiveResponses(XML_NODE node, void *d1, void *d2);
int ReadActiveCommands(XML_NODE node, void *d1, void *d2);
int Read_CReports(XML_NODE node, void *config1, void *config2);
int Read_WModule(const OS_XML *xml, xml_node *node, void *d1, void *d2);
int Read_Labels(XML_NODE node, void *d1, void *d2);
int Read_Authd(XML_NODE node, void *d1, void *d2);

/* Verifies that the configuration for Syscheck is correct. Return 0 on success or -1 on error.  */
int Test_Syscheck(const char * path);

/* Verifies that the configuration for Rootcheck is correct. Return 0 on success or -1 on error.  */
int Test_Rootcheck(const char * path);

/* Verifies that the configuration for Localfile is correct. Return 0 on success or -1 on error.  */
int Test_Localfile(const char * path);

/* Verifies that the configuration for Client is correct. Return 0 on success or -1 on error.  */
int Test_Client(const char * path);

/* Verifies that the configuration for ClientBuffer is correct. Return 0 on success or -1 on error.  */
int Test_ClientBuffer(const char * path);

/* Verifies that the configuration for Wodle is correct. Return 0 on success or -1 on error. */
int Test_WModule(const char * path);

/* Verifies that the configuration for Labels is correct. Return 0 on success or -1 on error.  */
int Test_Labels(const char * path);

#endif /* _HCONFIG__H */
