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
#define CSYSCHECK     0000000004
#define CROOTCHECK    0000000010
#define CLOCALFILE    0000000040
#define CREMOTE       0000000100
#define CCLIENT       0000000200
#define CAGENT_CONFIG 0000010000
#define CWMODULE      0000200000
#define CAUTHD        0001000000
#define CBUFFER       0002000000
#define CLGCSOCKET    0010000000
#define WAZUHDB       0040000000
#define ATAMPERING    0200000000

#define MAX_NEEDED_TAGS 4

#define BITMASK(modules)   (\
                            (modules & CGLOBAL       ) | (modules & CSYSCHECK     ) |\
                            (modules & CROOTCHECK    ) | (modules & CLOCALFILE    ) |\
                            (modules & CREMOTE       ) | (modules & CCLIENT       ) |\
                            (modules & CAGENT_CONFIG ) | (modules & CWMODULE      ) |\
                            (modules & CAUTHD        ) | (modules & CBUFFER       ) |\
                            (modules & CLGCSOCKET    ) | (modules & WAZUHDB       ) )



#include "os_xml.h"
#include "wazuh_db-config.h"
#include "time.h"

/* Main function to read the config */
int ReadConfig(int modules, const char *cfgfile, void *d1, void *d2);
void PrintErrorAcordingToModules(int modules, const char *cfgfile);

int Read_Global(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_Syscheck(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_Rootcheck(XML_NODE node, void *d1, void *d2);
int Read_Localfile(XML_NODE node, void *d1, void *d2);
int Read_Remote(const OS_XML *xml,XML_NODE node, void *d1, void *d2);
int Read_Client(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_ClientBuffer(XML_NODE node, void *d1, void *d2);
int Read_WModule(const OS_XML *xml, xml_node *node, void *d1, void *d2);
int Read_SCA(const OS_XML *xml, xml_node *node, void *d1);
int Read_AGENT_INFO(const OS_XML* xml, xml_node* node, void* d1);

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
int Read_Authd(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
#endif
int Read_LogCollecSocket(XML_NODE node, void *d1, void *d2);
int Read_Vulnerability_Detection(const OS_XML *xml, XML_NODE nodes, void *d1, const bool old_vd);
int Read_Indexer(const char* config_file);
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

/**
 * @brief Read the configuration for anti-tampering functionalities
 * @param node anti_tampering block configuration
 */
int Read_AntiTampering(XML_NODE node, void *d1);

#endif /* HCONFIG_H */
