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
#include "os_xml.h"
#include "config.h"

#ifdef CLIENT
#define IS_AGENT_BUILD 1
#else
#define IS_AGENT_BUILD 0
#endif

/* Where an element stopped being valid */
#define OBS_ALWAYS      0   /* Everywhere it can appear */
#define OBS_SERVER_CONF 1   /* Only in the manager's own configuration file */

typedef struct obsolete_element_t {
    const char *element;
    int scope;
    const char *hint;
} obsolete_element_t;

/* Top-level elements that 4.x accepted and 5.0.0 no longer has a parser for.
 *
 * An element with no parser reaches the end of read_main_elements() and is fatal,
 * so a configuration file carried over from 4.x stops the daemon from starting at
 * all. An agent upgrade is supported and never rewrites ossec.conf, and a manager
 * still distributes agent.conf files written for 4.x, so these are accepted and
 * ignored with a warning instead of rejected. Anything not listed here is still
 * fatal: the point is to be lenient with settings that were removed on purpose,
 * not with typos.
 *
 * <active-response> is the one element whose validity depends on who is reading
 * it. It is live configuration on an agent -- execd reads it straight from the
 * file, see os_execd/src/config.c -- and the manager parses agent.conf on the
 * agent's behalf, so it is obsolete only when the manager reads its own file. */
static const obsolete_element_t OBSOLETE_ELEMENTS[] = {
    {"active-response", OBS_SERVER_CONF, "Active Response is not configured on the manager. This block only applies to agents."},
    {"agent-key-polling", OBS_ALWAYS,    "The agent key polling module was removed in 5.0.0."},
    {"agentless",       OBS_ALWAYS,      "The wazuh-agentlessd daemon was removed in 5.0.0."},
    {"alerts",          OBS_ALWAYS,      "Alert output is not configured in the configuration file."},
    {"command",         OBS_ALWAYS,      "Active Response commands are not defined in the configuration file."},
    {"database_output", OBS_ALWAYS,      "The wazuh-dbd daemon was removed in 5.0.0."},
    {"email_alerts",    OBS_ALWAYS,      "The wazuh-maild daemon was removed in 5.0.0."},
    {"fluent-forward",  OBS_ALWAYS,      "The fluent forwarder module was removed in 5.0.0."},
    {"integration",     OBS_ALWAYS,      "The wazuh-integratord daemon was removed in 5.0.0."},
    {"labels",          OBS_ALWAYS,      "Agent labels were removed in 5.0.0."},
    {"reports",         OBS_ALWAYS,      "The wazuh-reportd daemon was removed in 5.0.0."},
    {"rule_test",       OBS_ALWAYS,      "Rule testing is provided by the engine."},
    {"ruleset",         OBS_ALWAYS,      "Rules and decoders are managed by the engine."},
    {"syslog_output",   OBS_ALWAYS,      "The wazuh-csyslogd daemon was removed in 5.0.0."},
    {NULL,              0,               NULL}
};

/* Return the explanation for an element that is obsolete in this context, or NULL
 * if the element is either still valid here or not one we know about. */
static const char *get_obsolete_hint(const char *element, int modules)
{
    /* True only while reading the manager's own configuration: an agent build
     * never qualifies, and neither does a manager reading a remote agent.conf. */
    const int server_conf = !IS_AGENT_BUILD && !(modules & CAGENT_CONFIG);
    int i;

    for (i = 0; OBSOLETE_ELEMENTS[i].element != NULL; i++) {
        if (strcmp(element, OBSOLETE_ELEMENTS[i].element) != 0) {
            continue;
        }

        if (OBSOLETE_ELEMENTS[i].scope == OBS_SERVER_CONF && !server_conf) {
            return NULL;
        }

        return OBSOLETE_ELEMENTS[i].hint;
    }

    return NULL;
}

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
    const char *oslocalfile = "localfile";                      /* Agent Config  */
    const char *osremote = "remote";                            /* Agent Config  */
    const char *osclient = "client";                            /* Agent Config  */
    const char *osbuffer = "client_buffer";                     /* Removed in 5.0.0 (#38030) */
    const char *osagent = "agent";                              /* Agent Config (HTTPS endpoint) */
    const char *osactiveresponse = "active-response";           /* Agent Active Response Config  */
    const char *oswmodule = "wodle";                            /* Wodle - Wazuh Module  */
    const char *oslogging = "logging";                          /* Logging Config */
    const char *oscluster = "cluster";                          /* Cluster Config */
    const char *ossocket = "socket";                            /* Socket Config */
    const char *ossca = "sca";                                  /* Security Configuration Assessment */
    const char* osagent_info = "agent-info";                    /* Agent Info Module */
    const char *osvulndetection = "vulnerability-detection";    /* Vulnerability Detection Config */
    const char *osvulndetector = "vulnerability-detector";      /* Old Vulnerability Detector Config */
    const char *osindexer = "indexer";                          /* Indexer Config */
    const char *osgcp_pub = "gcp-pubsub";                       /* Google Cloud PubSub - Wazuh Module */
    const char *osgcp_bucket = "gcp-bucket";                    /* Google Cloud Bucket - Wazuh Module */
    const char *agent_upgrade = "agent-upgrade";                /* Agent Upgrade Module */
    const char *task_manager = "task-manager";                  /* Task Manager Module */
    const char *wazuh_db = "wdb";                               /* Wazuh-DB Daemon */
#ifndef WIN32
    const char *anti_tampering = "anti_tampering";              /* Agent anti tampering Config */
    const char *osauthd = "auth";                               /* Authd Config */
#endif
#if defined(WIN32) || defined(__linux__) || defined(__MACH__)
    const char *github = "github";                      /* GitHub Module */
    const char *office365 = "office365";                /* Office365 Module */
    const char *ms_graph = "ms-graph";                  /* MS Graph Module */
#endif

    while (node[i]) {
        XML_NODE chld_node = NULL;
        const char *obsolete_hint = NULL;

        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            goto fail;
        }

        /* Checked before anything else so a removed element is never mistaken for
         * an unknown one, which is fatal further down. */
        obsolete_hint = get_obsolete_hint(node[i]->element, modules);

        if (obsolete_hint != NULL) {
            mwarn(XML_OBSOLETE, node[i]->element, obsolete_hint);
            i++;
            continue;
        }

        chld_node = OS_GetElementsbyNode(xml, node[i]);

        if (chld_node && (strcmp(node[i]->element, osglobal) == 0)) {
            if ((modules & CGLOBAL) && (Read_Global(xml, chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, ossyscheck) == 0) {
            if ((modules & CSYSCHECK) && (Read_Syscheck(xml, chld_node, d1, d2) < 0)) {
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
        } else if (chld_node && (strcmp(node[i]->element, osagent) == 0)) {
            if (modules & CCLIENT) {
                if (modules & CAGENT_CONFIG) {
                    if (Read_Agent_Shared(xml, chld_node, d1) < 0) {
                        goto fail;
                    }
                }
                else {
                    if (Read_Agent(xml, chld_node, d1, d2) < 0) {
                        goto fail;
                    }
                }
            }
        } else if (chld_node && (strcmp(node[i]->element, osclient) == 0)) {
            /* 4.x spelled this block <client> (#38103). An upgrade never rewrites
             * ossec.conf, so the block is still accepted, but only <server><address>
             * is read from it - as the fallback for <agent><manager><address>. */
            if (modules & CCLIENT) {
                if (modules & CAGENT_CONFIG) {
                    if (Read_Agent_Shared(xml, chld_node, d1) < 0){
                        goto fail;
                    }
                }
                else {
                    if (Read_Legacy_Client_Address(xml, chld_node, d1, d2) < 0){
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
            minfo("'%s' is no longer used and will be ignored. Event batching is configured "
                  "under <agent><batch>.", node[i]->element);
        } else if (strcmp(node[i]->element, oswmodule) == 0) {
            if ((modules & CWMODULE) && (Read_WModule(xml, node[i], d1, d2) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, ossca) == 0) {
            if ((modules & CWMODULE) && (Read_SCA(xml, node[i], d1, d2) < 0)) {
                goto fail;
            }
        }
        else if (strcmp(node[i]->element, osagent_info) == 0)
        {
#ifdef CLIENT
            if ((modules & CWMODULE) && (Read_AGENT_INFO(xml, node[i], d1) < 0))
            {
                goto fail;
            }
#else
            mdebug2("Agent-info module is not supported on manager. Ignoring configuration.");
#endif
        }
        else if (strcmp(node[i]->element, osvulndetection) == 0)
        {
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
            if ((modules & CWMODULE) && (Read_Indexer(WAZUHCONF) < 0)) {
                goto fail;
            }
#else
            mwarn("%s configuration is only set in the manager.", node[i]->element);
#endif
        } else if (strcmp(node[i]->element, osgcp_pub) == 0) {
            if ((modules & CWMODULE) && (Read_GCP_pubsub(xml, node[i], d1, d2) < 0)) {
                goto fail;
            }

        } else if (strcmp(node[i]->element, osgcp_bucket) == 0) {
            if ((modules & CWMODULE) && (Read_GCP_bucket(xml, node[i], d1, d2) < 0)) {
                goto fail;
            }
#ifndef WIN32
        }  else if (strcmp(node[i]->element, osauthd) == 0) {
            if ((modules & CAUTHD) && (Read_Authd(xml, chld_node, d1, d2) < 0)) {
                goto fail;
            }
#endif
        } else if (strcmp(node[i]->element, oslogging) == 0) {
        } else if (strcmp(node[i]->element, oscluster) == 0) {
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
            if ((modules & CWMODULE) && (Read_Github(xml, node[i], d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, office365) == 0)) {
            if ((modules & CWMODULE) && (Read_Office365(xml, node[i], d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, ms_graph) == 0)) {
            if ((modules & CWMODULE) && (Read_MS_Graph(xml, node[i], d1, d2) < 0)) {
                goto fail;
            }
        }
#endif
        else if (strcmp(node[i]->element, osactiveresponse) == 0) {
            /* Agent Active Response settings. Only reached when the block is
             * valid here (see OBSOLETE_ELEMENTS): execd reads it from the file
             * itself, so there is nothing to parse at this point. */
        } else {
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
    const char *xml_start_ossec = WAZUHCONFIG;
    const char *xml_start_agent = "agent_config";

    /* Attributes of the <agent_config> tag */
    const char *xml_agent_name = "name";
    const char *xml_agent_os = "os";
    const char *xml_agent_overwrite = "overwrite";
    const char *xml_agent_profile = "profile";

    if ((modules & CAGENT_CONFIG) && !getDefine_Int_default("agent", "remote_conf", 0, 1, 1)) {
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

        /* A failed read still leaves the object holding whatever it allocated before
         * giving up, exactly like the successful path -- every other exit below
         * clears it, these two early ones were simply missed. */
        OS_ClearXML(&xml);
        return (OS_INVALID);
    }

    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        OS_ClearXML(&xml);
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
            mwarn(XML_INVELEM, cfgfile);
            break;
        default:
            merror(CONFIG_ERROR, cfgfile);
            break;
    }
}
