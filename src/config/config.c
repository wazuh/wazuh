/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Unified function to read the configuration */

#include "shared.h"
#include "os_xml/os_xml.h"
#include "config.h"


/* Read the main elements of the configuration */
static int read_main_elements(const OS_XML *xml, int modules,
                              XML_NODE node,
                              void *d1,
                              void *d2)
{
    int i = 0;
    const char *osglobal = "global";                            /* Server Config */
    const char *ossyscheck = "syscheck";                        /* Agent Config  */
    const char *osrootcheck = "rootcheck";                      /* Agent Config  */
    const char *osalerts = "alerts";                            /* Server Config */
    const char *osemailalerts = "email_alerts";                 /* Server Config */
    const char *osdbd = "database_output";                      /* Server Config */
    const char *oscsyslogd = "syslog_output";                   /* Server Config */
    const char *oscagentless = "agentless";                     /* Server Config */
    const char *oslocalfile = "localfile";                      /* Agent Config  */
    const char *osremote = "remote";                            /* Agent Config  */
    const char *osclient = "client";                            /* Agent Config  */
    const char *anti_tampering = "anti_tampering";              /* Agent anti tampering Config */
    const char *osbuffer = "client_buffer";                     /* Agent Buffer Config  */
    const char *oscommand = "command";                          /* ? Config      */
    const char *osintegratord = "integration";                  /* Server Config */
    const char *osactive_response = "active-response";          /* Agent Config  */
    const char *oswmodule = "wodle";                            /* Wodle - Wazuh Module  */
    const char *oslabels = "labels";                            /* Labels Config */
    const char *oslogging = "logging";                          /* Logging Config */
    const char *oscluster = "cluster";                          /* Cluster Config */
    const char *ossocket = "socket";                            /* Socket Config */
    const char *ossca = "sca";                                  /* Security Configuration Assessment */
    const char *osvulndetection = "vulnerability-detection";    /* Vulnerability Detection Config */
    const char *osvulndetector = "vulnerability-detector";      /* Old Vulnerability Detector Config */
    const char *osindexer = "indexer";                          /* Indexer Config */
    const char *osgcp_pub = "gcp-pubsub";                       /* Google Cloud PubSub - Wazuh Module */
    const char *osgcp_bucket = "gcp-bucket";                    /* Google Cloud Bucket - Wazuh Module */
    const char *wlogtest = "rule_test";                         /* Wazuh Logtest */
    const char *agent_upgrade = "agent-upgrade";                /* Agent Upgrade Module */
    const char *task_manager = "task-manager";                  /* Task Manager Module */
    const char *wazuh_db = "wdb";                               /* Wazuh-DB Daemon */
#ifndef WIN32
    const char *osfluent_forward = "fluent-forward";            /* Fluent forwarder */
    const char *osauthd = "auth";                               /* Authd Config */
    const char *osreports = "reports";                          /* Server Config */
#ifndef CLIENT
    const char *key_polling = "agent-key-polling";              /* Deprecated Agent Key Polling module */
#endif
#endif
#if defined(WIN32) || defined(__linux__) || defined(__MACH__)
    const char *github = "github";                      /* GitHub Module */
    const char *office365 = "office365";                /* Office365 Module */
    const char *ms_graph = "ms-graph";                  /* MS Graph Module */
#endif

    while (node[i]) {
        XML_NODE chld_node = NULL;

        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            goto fail;
        }

        chld_node = OS_GetElementsbyNode(xml, node[i]);

        if (chld_node && (strcmp(node[i]->element, osglobal) == 0)) {
            if (((modules & CGLOBAL) || (modules & CMAIL))
                    && (Read_Global(xml, chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osemailalerts) == 0)) {
            if ((modules & CMAIL) && (Read_EmailAlerts(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oscsyslogd) == 0)) {
            if ((modules & CSYSLOGD) && (Read_CSyslog(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if(chld_node && (strcmp(node[i]->element, osintegratord) == 0)) {
            if((modules & CINTEGRATORD) && (Read_Integrator(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oscagentless) == 0)) {
            if ((modules & CAGENTLESS) && (Read_CAgentless(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, ossyscheck) == 0) {
            if ((modules & CSYSCHECK) && (Read_Syscheck(xml, chld_node, d1, d2, modules) < 0)) {
                goto fail;
            }
            if ((modules & CGLOBAL) && (Read_GlobalSK(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, osrootcheck) == 0) {
            if ((modules & CROOTCHECK) && (Read_Rootcheck(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oslocalfile) == 0)) {
            if ((modules & CLOCALFILE) && (Read_Localfile(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osremote) == 0)) {
            if ((modules & CREMOTE) && (Read_Remote(xml, chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osclient) == 0)) {
            if (modules & CCLIENT) {
                if (modules & CAGENT_CONFIG) {
                    if (Read_Client_Shared(chld_node, d1) < 0){
                        goto fail;
                    }
                }
                else {
                    if (Read_Client(xml, chld_node, d1, d2) < 0){
                        goto fail;
                    }
                }
            }
#ifndef WIN32
        } else if (chld_node && (strcmp(node[i]->element, anti_tampering) == 0)) {
            if ((modules & ATAMPERING) && (Read_AntiTampering(chld_node, d1) < 0)) {
                goto fail;
            }
#endif
        } else if (strcmp(node[i]->element, osbuffer) == 0) {
            if ((modules & CBUFFER) && (Read_ClientBuffer(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oscommand) == 0)) {
            if ((modules & CAR) && (ReadActiveCommands(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osactive_response) == 0)) {
            if ((modules & CAR) && (ReadActiveResponses(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        }
#ifndef WIN32
        else if (chld_node && (strcmp(node[i]->element, osreports) == 0)) {
            if ((modules & CREPORTS) && (Read_CReports(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        }
#endif
        else if (strcmp(node[i]->element, oswmodule) == 0) {
            if ((modules & CWMODULE) && (Read_WModule(xml, node[i], d1, d2) < 0)) {
                goto fail;
            }
#ifndef CLIENT
            else if ((node[i]->attributes[0] && !strcmp(node[i]->attributes[0], "name")) &&
                     (node[i]->values[0] && !strcmp(node[i]->values[0], key_polling))) {
                if ((modules & CAUTHD) && (authd_read_key_request(chld_node, d1) < 0)) {
                    goto fail;
                }
            }
#endif
        } else if (strcmp(node[i]->element, ossca) == 0) {
            if ((modules & CWMODULE) && (Read_SCA(xml, node[i], d1) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, osvulndetection) == 0) {
#if !defined(WIN32) && !defined(CLIENT)
            if ((modules & CWMODULE) && (Read_Vulnerability_Detection(xml, chld_node, d1, false) < 0)) {
                goto fail;
            }
#else
            mwarn("%s configuration is only set in the manager.", node[i]->element);
#endif
        } else if (strcmp(node[i]->element, osvulndetector) == 0) {
#if !defined(WIN32) && !defined(CLIENT)
            if ((modules & CWMODULE)) {
                mwarn(
                    "The '%s' configuration is deprecated, please update your settings to use the new '%s' instead "
                    "(default values will be used based on your previous configurations). "
                    "See https://documentation.wazuh.com",
                    osvulndetector,
                    osvulndetection);
                if (Read_Vulnerability_Detection(xml, chld_node, d1, true) < 0) {
                    goto fail;
                }
            }
#else
            mwarn("%s configuration is only set in the manager.", node[i]->element);
#endif
        } else if (strcmp(node[i]->element, osindexer) == 0) {
#if !defined(WIN32) && !defined(CLIENT)
            if ((modules & CWMODULE) && (Read_Indexer(xml, chld_node) < 0)) {
                goto fail;
            }
#else
            mwarn("%s configuration is only set in the manager.", node[i]->element);
#endif
        } else if (strcmp(node[i]->element, osgcp_pub) == 0) {
            if ((modules & CWMODULE) && (Read_GCP_pubsub(xml, node[i], d1) < 0)) {
                goto fail;
            }

        } else if (strcmp(node[i]->element, osgcp_bucket) == 0) {
            if ((modules & CWMODULE) && (Read_GCP_bucket(xml, node[i], d1) < 0)) {
                goto fail;
            }
#ifndef WIN32
        } else if (strcmp(node[i]->element, osfluent_forward) == 0) {
            if ((modules & CWMODULE) && (Read_Fluent_Forwarder(xml, node[i], d1) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, osauthd) == 0) {
            if ((modules & CAUTHD) && (Read_Authd(xml, chld_node, d1, d2) < 0)) {
                goto fail;
            }
#endif
        } else if (chld_node && (strcmp(node[i]->element, oslabels) == 0)) {
            if ((modules & CLABELS) && (Read_Labels(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, oslogging) == 0) {
        } else if (chld_node && (strcmp(node[i]->element, oscluster) == 0)) {
            if ((modules & CCLUSTER) && (Read_Cluster(xml, chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, ossocket) == 0)) {
            if ((modules & CLGCSOCKET) && (Read_LogCollecSocket(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, agent_upgrade) == 0)) {
            if ((modules & CWMODULE) && !(modules & CAGENT_CONFIG) && (Read_AgentUpgrade(xml, node[i], d1) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, task_manager) == 0)) {
            #if !defined(WIN32) && !defined(CLIENT)
                if ((modules & CWMODULE) && (Read_TaskManager(xml, node[i], d1) < 0)) {
                    goto fail;
                }
            #else
                mwarn("%s configuration is only set in the manager.", node[i]->element);
            #endif
        }  else if (chld_node && (strcmp(node[i]->element, wazuh_db) == 0)) {
            #if !defined(CLIENT)
                if ((modules & WAZUHDB) && (Read_WazuhDB(xml, chld_node) < 0)) {
                    goto fail;
                }
            #else
                mwarn("%s configuration is only set in the manager.", node[i]->element);
            #endif
        }
#if defined(WIN32) || defined(__linux__) || defined(__MACH__)
        else if (chld_node && (strcmp(node[i]->element, github) == 0)) {
            if ((modules & CWMODULE) && (Read_Github(xml, node[i], d1) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, office365) == 0)) {
            if ((modules & CWMODULE) && (Read_Office365(xml, node[i], d1) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, ms_graph) == 0)) {
            if ((modules & CWMODULE) && (Read_MS_Graph(xml, node[i], d1) < 0)) {
                goto fail;
            }
        }
#endif
        else {
            merror(XML_INVELEM, node[i]->element);
            goto fail;
        }

        OS_ClearNode(chld_node);
        i++;

        continue;

        fail:
        OS_ClearNode(chld_node);
        return (OS_INVALID);
    }

    return (0);
}

/* Read the config files */
int ReadConfig(int modules, const char *cfgfile, void *d1, void *d2)
{
    int i;
    OS_XML xml;
    XML_NODE node;

    /** XML definitions **/
    /* Global */
    const char *xml_start_ossec = "ossec_config";
    const char *xml_start_agent = "agent_config";

    /* Attributes of the <agent_config> tag */
    const char *xml_agent_name = "name";
    const char *xml_agent_os = "os";
    const char *xml_agent_overwrite = "overwrite";
    const char *xml_agent_profile = "profile";

    if ((modules & CAGENT_CONFIG) && !getDefine_Int("agent", "remote_conf", 0, 1)) {
      return 0;
    }

    if (OS_ReadXML(cfgfile, &xml) < 0) {
        if (modules & CAGENT_CONFIG) {
#ifndef CLIENT
            merror(XML_ERROR, cfgfile, xml.err, xml.err_line);
#endif
        } else {
            merror(XML_ERROR, cfgfile, xml.err, xml.err_line);
        }
        return (OS_INVALID);
    }

    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        return (0);
    }

    /* Read the main configuration */
    i = 0;
    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            OS_ClearNode(node);
            OS_ClearXML(&xml);
            return (OS_INVALID);
        } else if (!(modules & CAGENT_CONFIG) &&
                   (strcmp(node[i]->element, xml_start_ossec) == 0)) {
            XML_NODE chld_node = NULL;
            chld_node = OS_GetElementsbyNode(&xml, node[i]);

            /* Main element does not need to have any child */
            if (chld_node) {
                if (read_main_elements(&xml, modules, chld_node, d1, d2) < 0) {
                    PrintErrorAcordingToModules(modules, cfgfile);
                    OS_ClearNode(chld_node);
                    OS_ClearNode(node);
                    OS_ClearXML(&xml);
                    return (OS_INVALID);
                }

                OS_ClearNode(chld_node);
            }
        } else if ((modules & CAGENT_CONFIG) &&
                   (strcmp(node[i]->element, xml_start_agent) == 0)) {
            int passed_agent_test = 1;
            int attrs = 0;
            XML_NODE chld_node = NULL;
            chld_node = OS_GetElementsbyNode(&xml, node[i]);

            /* Check if this is specific to any agent */
            if (node[i]->attributes && node[i]->values) {
                while (node[i]->attributes[attrs] && node[i]->values[attrs]) {
                    /* Check if there is an "name=" attribute */
                    if (strcmp(xml_agent_name, node[i]->attributes[attrs]) == 0) {
#ifdef CLIENT
                        char *agentname = os_read_agent_name();

                        if (!agentname) {
                            passed_agent_test = 0;
                            merror("Reading shared configuration. Unable to retrieve the agent name.");
                        } else if (strlen(node[i]->values[attrs]) > OS_PATTERN_MAXSIZE) {
                            int attrlen = strlen(node[i]->values[attrs]);
                            mwarn("Agent name filter (%d bytes) exceeds the limit (%d)", attrlen, OS_PATTERN_MAXSIZE);
                            passed_agent_test = 0;
                            free(agentname);
                        } else {
                            if (!OS_Match2(node[i]->values[attrs], agentname)) {
                                passed_agent_test = 0;
                            }
                            free(agentname);
                        }
#endif
                    } else if (strcmp(xml_agent_os, node[i]->attributes[attrs]) == 0) {
#ifdef CLIENT
                        const char *agentos = getuname();

                        if (!agentos) {
                            passed_agent_test = 0;
                            merror("Reading shared configuration. Unable to retrieve the agent OS.");
                        } else if (strlen(node[i]->values[attrs]) > OS_PATTERN_MAXSIZE) {
                            int attrlen = strlen(node[i]->values[attrs]);
                            mwarn("Agent OS filter (%d bytes) exceeds the limit (%d)", attrlen, OS_PATTERN_MAXSIZE);
                            passed_agent_test = 0;
                        } else if (!OS_Match2(node[i]->values[attrs], agentos)) {
                            passed_agent_test = 0;
                        }
#endif
                    } else if (strcmp(xml_agent_profile, node[i]->attributes[attrs]) == 0) {
#ifdef CLIENT
                        char *agentprofile = os_read_agent_profile();

                        if (!agentprofile) {
                            passed_agent_test = 0;
                            merror("Reading shared configuration. Unable to retrieve agent profile.");
                        } else if (strlen(node[i]->values[attrs]) > OS_PATTERN_MAXSIZE) {
                            int attrlen = strlen(node[i]->values[attrs]);
                            mwarn("Agent profile filter (%d bytes) exceeds the limit (%d)", attrlen, OS_PATTERN_MAXSIZE);
                            passed_agent_test = 0;
                            free(agentprofile);
                        } else {
                            /* match the profile name of this <agent_config> section
                             * with a comma separated list of values in agent's
                             * <config-profile> tag.
                             */
                            if (!OS_Match2(node[i]->values[attrs], agentprofile)) {
                                passed_agent_test = 0;
                                mdebug2("[%s] did not match agent config profile name [%s]",
                                       node[i]->values[attrs], agentprofile);
                            } else {
                                mdebug2("Matched agent config profile name [%s]", agentprofile);
                            }
                            free(agentprofile);
                        }
#endif
                    } else if (strcmp(xml_agent_overwrite, node[i]->attributes[attrs]) == 0) {
                    } else {
                        merror(XML_INVATTR, node[i]->attributes[attrs],
                               cfgfile);
                    }
                    attrs++;
                }
            }
#ifdef CLIENT
            else {
                char *agentprofile = os_read_agent_profile();
                mdebug2("agent_config element does not have any attributes.");

                /* if node does not have any attributes, it is a generic config block.
                 * check if agent has a profile name
                 * if agent does not have profile name, then only read this generic
                 * agent_config block
                 */

                if (!agentprofile) {
                    mdebug2("but agent has a profile name.");
                    passed_agent_test = 0;
                } else {
                    free(agentprofile);
                }
            }
#endif

            /* Main element does not need to have any child */
            if (chld_node) {
                if (passed_agent_test && read_main_elements(&xml, modules, chld_node, d1, d2) < 0) {
                    merror(CONFIG_ERROR, cfgfile);
                    OS_ClearNode(chld_node);
                    OS_ClearNode(node);
                    OS_ClearXML(&xml);
                    return (OS_INVALID);
                }

                OS_ClearNode(chld_node);
            }
        } else {
            merror(XML_INVELEM, node[i]->element);
            OS_ClearNode(node);
            OS_ClearXML(&xml);
            return (OS_INVALID);
        }
        i++;
    }

    /* Clear node and xml */
    OS_ClearNode(node);
    OS_ClearXML(&xml);
    return (0);
}

void PrintErrorAcordingToModules(int modules, const char *cfgfile) {

    switch (BITMASK(modules)) {
        case CSYSCHECK:
        case CROOTCHECK:
            mwarn(CONFIG_ERROR, cfgfile);
            break;
        default:
            merror(CONFIG_ERROR, cfgfile);
            break;
    }
}
