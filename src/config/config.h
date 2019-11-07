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
#define CRMOTE_CONFIG 000010000            // Since Wazuh 3.11 : CAGENT_CONFIG has been replaced with CRMOTE_CONFIG
#define CAGENTLESS    000020000
#define CREPORTS      000040000
#define CINTEGRATORD  000100000
#define CWMODULE      000200000
#define CLABELS       000400000
#define CAUTHD        001000000
#define CBUFFER       002000000
#define CCLUSTER      004000000
#define CSOCKET       010000000
#define CLOCAL_CONFIG 020000000
#define CAGENT_CGFILE 040000000

#define MAX_NEEDED_TAGS 4

typedef enum needed_tags {
    JSONOUT_OUTPUT = 0,
    ALERTS_LOG,
    LOGALL,
    LOGALL_JSON
} NeededTags;

#include "os_xml/os_xml.h"

/* Main function to read the config */
int ReadConfig(int modules, const char *cfgfile, void *d1, void *d2, char **output);

int Read_Global(XML_NODE node, void *d1, void *d2, char **output);
int Read_GlobalSK(XML_NODE node, void *configp, void *mailp, char **output);
int Read_Rules(XML_NODE node, void *d1, void *d2, char **output);
int Read_Syscheck(const OS_XML *xml, XML_NODE node, void *d1, void *d2, int modules, char **output);
int Read_Rootcheck(XML_NODE node, void *d1, void *d2, char **output);
int Read_Alerts(XML_NODE node, void *d1, void *d2, char **output);
int Read_EmailAlerts(XML_NODE node, void *d1, void *d2, char **output);
int Read_DB(XML_NODE node, void *config1, void *config2, char **output);
int Read_CSyslog(XML_NODE node, void *config1, void *config2, char **output);
int Read_CAgentless(XML_NODE node, void *config1, void *config2, char **output);
int Read_Localfile(XML_NODE node, void *d1, void *d2, char **output);
int Read_Integrator(XML_NODE node, void *config1, void *config2, char **output);
int Read_Remote(XML_NODE node, void *d1, void *d2, char **output);
int Read_Client(const OS_XML *xml, XML_NODE node, void *d1, void *d2, char **output);
int Read_ClientBuffer(XML_NODE node, void *d1, void *d2, char ** output);
int ReadActiveResponses(XML_NODE node, void *d1, void *d2, char **output);
int ReadActiveCommands(XML_NODE node, void *d1, void *d2, char **output);
int Read_CReports(XML_NODE node, void *config1, void *config2, char **output);
int Read_WModule(const OS_XML *xml, xml_node *node, void *d1, void *d2, int cfg_type, char **output);
int Read_SCA(const OS_XML *xml, xml_node *node, void *d1, char **output);
#ifndef WIN32
int Read_Fluent_Forwarder(const OS_XML *xml, xml_node *node, void *d1, char **output);
#endif
int Read_Labels(XML_NODE node, void *d1, void *d2, char **output);
int Read_Authd(XML_NODE node, void *d1, void *d2, char **output);
int Read_Cluster(const OS_XML *xml, XML_NODE node, void *d1, void *d2, char **output);
int Read_Socket(XML_NODE node, void *d1, void *d2, char **output);
int Read_Vuln(const OS_XML *xml, xml_node **nodes, void *d1, char d2);

/* Verifies that the configuration for Syscheck is correct. Return 0 on success or -1 on error.  */
int Test_Syscheck(const char *path, int type, char **output);

/* Verifies that the configuration for Rootcheck is correct. Return 0 on success or -1 on error.  */
int Test_Rootcheck(const char *path, int type, char **output);

/* Verifies that the configuration for Localfile is correct. Return 0 on success or -1 on error.  */
int Test_Localfile(const char *path, int type, char **output);

/* Verifies that the configuration for Client is correct. Return 0 on success or -1 on error.  */
int Test_Client(const char *path, int type, char **output);

/* Verifies that the configuration for ClientBuffer is correct. Return 0 on success or -1 on error.  */
int Test_ClientBuffer(const char *path, int type, char **output);

/* Verifies that the configuration for Wodle is correct. Return 0 on success or -1 on error. */
int Test_WModule(const char *path, int type, char **output);

/* Verifies that the configuration for Labels is correct. Return 0 on success or -1 on error.  */
int Test_Labels(const char *path, int type, char **output);

/* New Manager Test Components */

int Test_Analysisd(const char *path, char **output);
int Test_Authd(const char *path, char **output);
int Test_ActiveResponse(const char *path, int type, char **output);
int Test_Agent_Active_Response(const char *path, char **output);
int Test_Remoted(const char *path, char **output);
int Test_Execd(const char *path, char **output);
int Test_Integratord(const char *path, char **output);
int Test_Maild(const char *path, char **output);
int Test_Agentlessd(const char *path, char **output);
int Test_DBD(const char *path, char **output);
int Test_CSyslogd(const char *path, char **output);

#endif /* _HCONFIG__H */
