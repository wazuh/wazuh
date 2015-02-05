/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Unified function to read the configuration */

#include "shared.h"
#include "os_xml/os_xml.h"
#include "config.h"

/* Prototypes */
static int read_main_elements(const OS_XML *xml, int modules,
                              XML_NODE node,
                              void *d1,
                              void *d2);


/* Read the main elements of the configuration */
static int read_main_elements(const OS_XML *xml, int modules,
                              XML_NODE node,
                              void *d1,
                              void *d2)
{
    int i = 0;
    const char *osglobal = "global";                    /* Server Config */
    const char *osrules = "rules";                      /* Server Config */
    const char *ossyscheck = "syscheck";                /* Agent Config  */
    const char *osrootcheck = "rootcheck";              /* Agent Config  */
    const char *osalerts = "alerts";                    /* Server Config */
    const char *osemailalerts = "email_alerts";         /* Server Config */
    const char *osdbd = "database_output";              /* Server Config */
    const char *oscsyslogd = "syslog_output";           /* Server Config */
    const char *oscagentless = "agentless";             /* Server Config */
    const char *oslocalfile = "localfile";              /* Agent Config  */
    const char *osremote = "remote";                    /* Agent Config  */
    const char *osclient = "client";                    /* Agent Config  */
    const char *oscommand = "command";                  /* ? Config      */
    const char *osreports = "reports";                  /* Server Config */
    const char *osactive_response = "active-response";  /* Agent Config  */

    while (node[i]) {
        XML_NODE chld_node = NULL;

        chld_node = OS_GetElementsbyNode(xml, node[i]);

        if (!node[i]->element) {
            merror(XML_ELEMNULL, __local_name);
            return (OS_INVALID);
        } else if (!chld_node) {
            merror(XML_INVELEM, __local_name, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, osglobal) == 0) {
            if (((modules & CGLOBAL) || (modules & CMAIL))
                    && (Read_Global(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, osemailalerts) == 0) {
            if ((modules & CMAIL) && (Read_EmailAlerts(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, osdbd) == 0) {
            if ((modules & CDBD) && (Read_DB(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, oscsyslogd) == 0) {
            if ((modules & CSYSLOGD) && (Read_CSyslog(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, oscagentless) == 0) {
            if ((modules & CAGENTLESS) && (Read_CAgentless(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, osrules) == 0) {
            if ((modules & CRULES) && (Read_Rules(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, ossyscheck) == 0) {
            if ((modules & CSYSCHECK) && (Read_Syscheck(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
            if ((modules & CGLOBAL) && (Read_GlobalSK(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, osrootcheck) == 0) {
            if ((modules & CROOTCHECK) && (Read_Rootcheck(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, osalerts) == 0) {
            if ((modules & CALERTS) && (Read_Alerts(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, oslocalfile) == 0) {
            if ((modules & CLOCALFILE) && (Read_Localfile(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, osremote) == 0) {
            if ((modules & CREMOTE) && (Read_Remote(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, osclient) == 0) {
            if ((modules & CCLIENT) && (Read_Client(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, oscommand) == 0) {
            if ((modules & CAR) && (ReadActiveCommands(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, osactive_response) == 0) {
            if ((modules & CAR) && (ReadActiveResponses(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, osreports) == 0) {
            if ((modules & CREPORTS) && (Read_CReports(chld_node, d1, d2) < 0)) {
                return (OS_INVALID);
            }
        } else {
            merror(XML_INVELEM, __local_name, node[i]->element);
            return (OS_INVALID);
        }

        OS_ClearNode(chld_node);
        i++;
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

    if (OS_ReadXML(cfgfile, &xml) < 0) {
        if (modules & CAGENT_CONFIG) {
#ifndef CLIENT
            merror(XML_ERROR, __local_name, cfgfile, xml.err, xml.err_line);
#endif
        } else {
            merror(XML_ERROR, __local_name, cfgfile, xml.err, xml.err_line);
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
            merror(XML_ELEMNULL, __local_name);
            return (OS_INVALID);
        } else if (!(modules & CAGENT_CONFIG) &&
                   (strcmp(node[i]->element, xml_start_ossec) == 0)) {
            XML_NODE chld_node = NULL;
            chld_node = OS_GetElementsbyNode(&xml, node[i]);

            /* Main element does not need to have any child */
            if (chld_node) {
                if (read_main_elements(&xml, modules, chld_node, d1, d2) < 0) {
                    merror(CONFIG_ERROR, __local_name, cfgfile);
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
                        } else {
                            if (!OS_Match2(node[i]->values[attrs], agentname)) {
                                passed_agent_test = 0;
                            }
                            free(agentname);
                        }
#endif
                    } else if (strcmp(xml_agent_os, node[i]->attributes[attrs]) == 0) {
#ifdef CLIENT
                        char *agentos = getuname();

                        if (agentos) {
                            if (!OS_Match2(node[i]->values[attrs], agentos)) {
                                passed_agent_test = 0;
                            }
                            free(agentos);
                        } else {
                            passed_agent_test = 0;
                            merror("%s: ERROR: Unable to retrieve uname.", __local_name);
                        }
#endif
                    } else if (strcmp(xml_agent_profile, node[i]->attributes[attrs]) == 0) {
#ifdef CLIENT
                        char *agentprofile = os_read_agent_profile();
                        debug2("Read agent config profile name [%s]", agentprofile);

                        if (!agentprofile) {
                            passed_agent_test = 0;
                        } else {
                            /* match the profile name of this <agent_config> section
                             * with a comma separated list of values in agent's
                             * <config-profile> tag.
                             */
                            if (!OS_Match2(node[i]->values[attrs], agentprofile)) {
                                passed_agent_test = 0;
                                debug2("[%s] did not match agent config profile name [%s]",
                                       node[i]->values[attrs], agentprofile);
                            } else {
                                debug2("Matched agent config profile name [%s]", agentprofile);
                            }
                            free(agentprofile);
                        }
#endif
                    } else if (strcmp(xml_agent_overwrite, node[i]->attributes[attrs]) == 0) {
                    } else {
                        merror(XML_INVATTR, __local_name, node[i]->attributes[attrs],
                               cfgfile);
                    }
                    attrs++;
                }
            }
#ifdef CLIENT
            else {
                debug2("agent_config element does not have any attributes.");

                /* if node does not have any attributes, it is a generic config block.
                 * check if agent has a profile name
                 * if agent does not have profile name, then only read this generic
                 * agent_config block
                 */

                if (!os_read_agent_profile()) {
                    debug2("but agent has a profile name.");
                    passed_agent_test = 0;
                }
            }
#endif

            /* Main element does not need to have any child */
            if (chld_node) {
                if (passed_agent_test && read_main_elements(&xml, modules, chld_node, d1, d2) < 0) {
                    merror(CONFIG_ERROR, __local_name, cfgfile);
                    return (OS_INVALID);
                }

                OS_ClearNode(chld_node);
            }
        } else {
            merror(XML_INVELEM, __local_name, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

    /* Clear node and xml */
    OS_ClearNode(node);
    OS_ClearXML(&xml);
    return (0);
}

