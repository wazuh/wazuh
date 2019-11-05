/* Copyright (C) 2015-2019, Wazuh Inc.
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

#define CGLOBAL       00000000001
#define CRULES        00000000002
#define CSYSCHECK     00000000004
#define CROOTCHECK    00000000010
#define CALERTS       00000000020
#define CLOCALFILE    00000000040
#define CREMOTE       00000000100
#define CCLIENT       00000000200
#define CMAIL         00000000400
#define CAR           00000001000
#define CDBD          00000002000
#define CSYSLOGD      00000004000
#define CAGENT_CONFIG 00000010000
#define CAGENTLESS    00000020000
#define CREPORTS      00000040000
#define CINTEGRATORD  00000100000
#define CWMODULE      00000200000
#define CLABELS       00000400000
#define CAUTHD        00001000000
#define CBUFFER       00002000000
#define CCLUSTER      00004000000
#define CSOCKET       00010000000
#define CLOGCOLLECTOR 00020000000
#define CEXEC         00040000000
#define CINTEGRATOR   00100000000
#define CWDATABASE    00200000000
#define CWDOWNLOAD    00400000000
#define CSYSLOG_CONF  01000000000
#define CROTMONITORD  02000000000
#define CROTANALYSD   04000000000

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
int Read_Syscheck(const OS_XML *xml, XML_NODE node, void *d1, void *d2, int modules);
int Read_Rootcheck(XML_NODE node, void *d1, void *d2);
int Read_Alerts(XML_NODE node, void *d1, void *d2);
int Read_EmailAlerts(XML_NODE node, void *d1, void *d2);
int Read_Mail(XML_NODE node, void *d1, void *d2);
int Read_DB(XML_NODE node, void *config1, void *config2);
int Read_CSyslog(XML_NODE node, void *config1, void *config2);
int Read_CSyslog_Options(XML_NODE node, void *config);
int Read_CAgentless(XML_NODE node, void *config1, void *config2);
int Read_Localfile(XML_NODE node, void *d1, void *d2);
int Read_Logcollector(const OS_XML *xml, XML_NODE node, void *d1, int modules);
int Read_Integrator(XML_NODE node, void *config1, void *config2);
int Read_Integrator_Options(XML_NODE node, void *config1);
int Read_Remote (const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_Client(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_ClientBuffer(const OS_XML *xml, XML_NODE node, void *d1, void *d2, int modules);
int ReadActiveResponses(XML_NODE node, void *d1, void *d2);
int ReadActiveCommands(XML_NODE node, void *d1, void *d2);
int Read_CReports(XML_NODE node, void *config1, void *config2);
int Read_WModule(const OS_XML *xml, xml_node *node, void *d1, void *d2);
int Read_SCA(const OS_XML *xml, xml_node *node, void *d1, int modules);
#ifndef WIN32
int Read_Fluent_Forwarder(const OS_XML *xml, xml_node *node, void *d1);
#endif
int Read_Labels(XML_NODE node, void *d1, void *d2);
int Read_Authd(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_Cluster(XML_NODE node, void *d1, void *d2);
int Read_Socket(XML_NODE node, void *d1, void *d2);
int Read_Exec(XML_NODE node, void *d1);
int Read_WModules_Config(XML_NODE node, void *d1);
int Read_WDatabase(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_WDownload(XML_NODE node, void *d1);
int Read_RotationMonitord(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_RotationAnalysisd(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_Monitor(XML_NODE node, void *d1, void *d2);
int Read_Vuln(const OS_XML *xml, xml_node **nodes, void *d1, char d2);

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
