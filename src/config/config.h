/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _HCONFIG__H
#define _HCONFIG__H

#define CGLOBAL       0000000001
#define CRULES        0000000002
#define CSYSCHECK     0000000004
#define CROOTCHECK    0000000010
#define CALERTS       0000000020
#define CLOCALFILE    0000000040
#define CREMOTE       0000000100
#define CCLIENT       0000000200
#define CMAIL         0000000400
#define CAR           0000001000
#define CDBD          0000002000
#define CSYSLOGD      0000004000
#define CAGENT_CONFIG 0000010000
#define CAGENTLESS    0000020000
#define CREPORTS      0000040000
#define CINTEGRATORD  0000100000
#define CWMODULE      0000200000
#define CLABELS       0000400000
#define CAUTHD        0001000000
#define CBUFFER       0002000000
#define CCLUSTER      0004000000
#define CSOCKET       0010000000
#define CLOGCOLLECTOR 0020000000
#define CEXEC         0040000000
#define CINTEGRATOR   0100000000
#define CWDATABASE    0200000000
#define CWDOWNLOAD    0400000000

#define UDP_PROTO   6
#define TCP_PROTO   17

#define MAX_NEEDED_TAGS 4

typedef enum needed_tags {
    JSONOUT_OUTPUT = 0,
    ALERTS_LOG,
    LOGALL,
    LOGALL_JSON
} NeededTags;

#include "os_xml/os_xml.h"
#include "shared.h"

/* Global variables */
extern int remote_conf;

/* Main function to read the config */
int ReadConfig(int modules, const char *cfgfile, void *d1, void *d2);

int Read_Global(XML_NODE node, void *d1, void *d2);
int Read_GlobalSK(XML_NODE node, void *configp, void *mailp);
int Read_Analysis(const OS_XML *xml, XML_NODE node, void *d1);
int Read_Rules(XML_NODE node, void *d1, void *d2);
int Read_Syscheck(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_Rootcheck(XML_NODE node, void *d1, void *d2);
int Read_Alerts(XML_NODE node, void *d1, void *d2);
int Read_EmailAlerts(XML_NODE node, void *d1, void *d2);
int Read_Mail(XML_NODE node, void *d1, void *d2);
int Read_DB(XML_NODE node, void *config1, void *config2);
int Read_CSyslog(XML_NODE node, void *config1, void *config2);
int Read_CAgentless(XML_NODE node, void *config1, void *config2);
int Read_Localfile(XML_NODE node, void *d1, void *d2);
int Read_Logcollector(const OS_XML *xml, XML_NODE node, void *d1);
int Read_Integrator(XML_NODE node, void *config1, void *config2);
int Read_Integrator_Options(XML_NODE node, void *config1);
int Read_Remote (const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_Client(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_ClientBuffer(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int ReadActiveResponses(XML_NODE node, void *d1, void *d2);
int ReadActiveCommands(XML_NODE node, void *d1, void *d2);
int Read_CReports(XML_NODE node, void *config1, void *config2);
int Read_WModule(const OS_XML *xml, xml_node *node, void *d1, void *d2);
int Read_SCA(const OS_XML *xml, xml_node *node, void *d1);
#ifndef WIN32
int Read_Fluent_Forwarder(const OS_XML *xml, xml_node *node, void *d1);
#endif
int Read_Labels(XML_NODE node, void *d1, void *d2);
int Read_Authd(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_Cluster(XML_NODE node, void *d1, void *d2);
int Read_Socket(XML_NODE node, void *d1, void *d2);
int Read_Exec(XML_NODE node, void *d1);
int Read_WModules_Config(XML_NODE node, void *d1);
int Read_WDatabase(const OS_XML *xml, XML_NODE node, void *d1);
int Read_WDownload(XML_NODE node, void *d1);

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

/* Set internal option value. Return 0 on success or -1 on error. */
int SetConf(const char *c_value, int *var, const option_t option, const char *name);

#endif /* _HCONFIG__H */
