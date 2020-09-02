/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef HCONFIG_H
#define HCONFIG_H

#define CGLOBAL       000000001
#define CRULES        000000002
#define CSYSCHECK     000000004
#define CROOTCHECK    000000010
#define CALERTS       000000020
#define CLOCALFILE    000000040
#define CREMOTE       000000100
#define CCLIENT       000000200
#define CMAIL         000000400
#define CAR           000001000
#define CDBD          000002000
#define CSYSLOGD      000004000
#define CAGENT_CONFIG 000010000
#define CAGENTLESS    000020000
#define CREPORTS      000040000
#define CINTEGRATORD  000100000
#define CWMODULE      000200000
#define CLABELS       000400000
#define CAUTHD        001000000
#define CBUFFER       002000000
#define CCLUSTER      004000000
#define CSOCKET       010000000

#define MAX_NEEDED_TAGS 4

typedef enum needed_tags {
    JSONOUT_OUTPUT = 0,
    ALERTS_LOG,
    LOGALL,
    LOGALL_JSON
} NeededTags;

#include "os_xml/os_xml.h"

/* Main function to read the config */
int ReadConfig(int modules, const char *cfgfile, void *d1, void *d2);

int Read_Global(XML_NODE node, void *d1, void *d2);
int Read_GlobalSK(XML_NODE node, void *configp, void *mailp);
int Read_Rules(XML_NODE node, void *d1, void *d2);
int Read_Syscheck(const OS_XML *xml, XML_NODE node, void *d1, void *d2, int modules);
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
int Read_SCA(const OS_XML *xml, xml_node *node, void *d1);
int Read_GCP(const OS_XML *xml, xml_node *node, void *d1);
#ifndef WIN32
int Read_Fluent_Forwarder(const OS_XML *xml, xml_node *node, void *d1);
#endif
int Read_Labels(XML_NODE node, void *d1, void *d2);
int Read_Authd(XML_NODE node, void *d1, void *d2);
int Read_Cluster(XML_NODE node, void *d1, void *d2);
int Read_Socket(XML_NODE node, void *d1, void *d2);
int Read_Vuln(const OS_XML *xml, xml_node **nodes, void *d1, char d2);
int Read_AgentUpgrade(const OS_XML *xml, xml_node *node, void *d1);
int Read_TaskManager(const OS_XML *xml, xml_node *node, void *d1);

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

#endif /* HCONFIG_H */
