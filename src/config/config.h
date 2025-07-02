/* Copyright (C) 2015, Wazuh Inc.
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

#define CGLOBAL       0000000001
#define CRULES        0000000002 /// Deprecated module
#define CSYSCHECK     0000000004
#define CROOTCHECK    0000000010
#define CALERTS       0000000020
#define CLOCALFILE    0000000040
#define CREMOTE       0000000100
#define CCLIENT       0000000200
#define CMAIL         0000000400
#define CAR           0000001000
#define CDBD          0000002000 /// Deprecated module
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
#define CLGCSOCKET    0010000000
#define CANDSOCKET    0020000000 /// Deprecated module
#define WAZUHDB       0040000000
#define CLOGTEST      0100000000 /// Deprecated module
#define ATAMPERING    0200000000

#define MAX_NEEDED_TAGS 4

#define BITMASK(modules)   (\
                            (modules & CGLOBAL       ) | (modules & CRULES        ) | (modules & CSYSCHECK     ) |\
                            (modules & CROOTCHECK    ) | (modules & CALERTS       ) | (modules & CLOCALFILE    ) |\
                            (modules & CREMOTE       ) | (modules & CCLIENT       ) | (modules & CMAIL         ) |\
                            (modules & CAR           ) | (modules & CDBD          ) | (modules & CSYSLOGD      ) |\
                            (modules & CAGENT_CONFIG ) | (modules & CAGENTLESS    ) | (modules & CREPORTS      ) |\
                            (modules & CINTEGRATORD  ) | (modules & CWMODULE      ) | (modules & CLABELS       ) |\
                            (modules & CAUTHD        ) | (modules & CBUFFER       ) | (modules & CCLUSTER      ) |\
                            (modules & CLGCSOCKET    ) | (modules & CLOGTEST      ) | (modules & WAZUHDB       ) |\
                            (modules & CANDSOCKET    ) )

typedef enum needed_tags {
    JSONOUT_OUTPUT = 0,
    ALERTS_LOG,
    LOGALL,
    LOGALL_JSON
} NeededTags;


#include "../os_xml/os_xml.h"
#include "../config/wazuh_db-config.h"
#include "time.h"

/* Main function to read the config */
int ReadConfig(int modules, const char *cfgfile, void *d1, void *d2);
void PrintErrorAcordingToModules(int modules, const char *cfgfile);

int Read_Global(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_GlobalSK(XML_NODE node, void *configp, void *mailp);
int Read_Syscheck(const OS_XML *xml, XML_NODE node, void *d1, void *d2, int modules);
int Read_Rootcheck(XML_NODE node, void *d1, void *d2);
int Read_EmailAlerts(XML_NODE node, void *d1, void *d2);
int Read_CSyslog(XML_NODE node, void *config1, void *config2);
int Read_CAgentless(XML_NODE node, void *config1, void *config2);
int Read_Localfile(XML_NODE node, void *d1, void *d2);
int Read_Integrator(XML_NODE node, void *config1, void *config2);
int Read_Remote(const OS_XML *xml,XML_NODE node, void *d1, void *d2);
int Read_Client(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_ClientBuffer(XML_NODE node, void *d1, void *d2);
int ReadActiveResponses(XML_NODE node, void *d1, void *d2);
int ReadActiveCommands(XML_NODE node, void *d1, void *d2);
int Read_CReports(XML_NODE node, void *config1, void *config2);
int Read_WModule(const OS_XML *xml, xml_node *node, void *d1, void *d2);
int Read_SCA(const OS_XML *xml, xml_node *node, void *d1);

/**
 * @brief Read the configuration for client section with centralized configuration
 * @param node XML node to analyze
 * @param d1 Pub/Sub configuration structure
 */
int Read_Client_Shared(XML_NODE node, void *d1);

/**
 * @brief Read the configuration for Google Cloud Pub/Sub
 * @param xml XML object
 * @param node XML node to analyze
 * @param d1 Pub/Sub configuration structure
 */
int Read_GCP_pubsub(const OS_XML *xml, xml_node *node, void *d1);

/**
 * @brief Read the configuration for a Google Cloud bucket
 * @param xml XML object
 * @param node XML node to analyze
 * @param d1 Bucket configuration structure
 */
int Read_GCP_bucket(const OS_XML *xml, xml_node *node, void *d1);

#ifndef WIN32
int Read_Fluent_Forwarder(const OS_XML *xml, xml_node *node, void *d1);
int Read_Authd(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
#ifndef CLIENT
// Current key-request module
int authd_read_key_request(xml_node **nodes, void *config);
// Deprecated agent-key-polling module
int wm_key_request_read(__attribute__((unused)) xml_node **nodes, __attribute__((unused)) void *module);
#endif
#endif
int Read_Labels(XML_NODE node, void *d1, void *d2);
int Read_Cluster(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_LogCollecSocket(XML_NODE node, void *d1, void *d2);
int Read_Vuln(const OS_XML *xml, xml_node **nodes, void *d1, char d2);
int Read_Vulnerability_Detection(const OS_XML *xml, XML_NODE nodes, void *d1, const bool old_vd);
int Read_Indexer(const OS_XML *xml, XML_NODE nodes);
int Read_AgentUpgrade(const OS_XML *xml, xml_node *node, void *d1);
int Read_TaskManager(const OS_XML *xml, xml_node *node, void *d1);

#if defined(WIN32) || defined(__linux__) || defined(__MACH__)
/**
 * @brief Read the configuration for GitHub module
 * @param xml XML object
 * @param node XML node to analyze
 * @param d1 github configuration structure
 */
int Read_Github(const OS_XML *xml, xml_node *node, void *d1);

/**
 * @brief Read the configuration for Office365 module
 * @param xml XML object
 * @param node XML node to analyze
 * @param d1 office365 configuration structure
 */
int Read_Office365(const OS_XML *xml, xml_node *node, void *d1);

/**
 * @brief Read the configuration for MS Graph module
 * @param xml XML object
 * @param node XML node to analyze
 * @param d1 ms_graph configuration structure
 */
int Read_MS_Graph(const OS_XML *xml, xml_node *node, void *d1);
#endif

/**
 * @brief Read the configuration for logtest thread
 * @param node rule_test configuration
 */
int Read_Logtest(XML_NODE node);

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

/**
 * @brief Read the configuration for anti-tampering functionalities
 * @param node anti_tampering block configuration
 */
int Read_AntiTampering(XML_NODE node, void *d1);

#endif /* HCONFIG_H */
