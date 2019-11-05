/* Copyright (C) 2015-2019, Wazuh Inc.
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
#include "../config/global-config.h"

int remote_conf;

/* Read remote_conf option */
static int Read_RemoteConf(XML_NODE node, int modules)
{
    int i = 0, aux;
    static const char *xml_remote_conf = "remote_conf";

    /* Default value */
    remote_conf = options.client.remote_conf.def;

    /* Load from ossec.conf */
    for (i = 0; node[i]; i++) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_remote_conf) == 0) {
            if (modules & CAGENT_CONFIG) {
                mwarn("Trying to modify '%s' option from 'agent.conf'. This is not permitted.", xml_remote_conf);
            } else {
                SetConf(node[i]->content, &remote_conf, options.client.remote_conf, xml_remote_conf);
            }
        }
    }

    /* Load from internal options */
    if ((aux = getDefine_Int("agent", "remote_conf", options.client.remote_conf.min, options.client.remote_conf.max) != INT_OPT_NDEF))
        remote_conf = aux;

    return 0;
}

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
    const char *osrules = "ruleset";                    /* Server Config */
    const char *ossyscheck = "syscheck";                /* Agent Config  */
    const char *osrootcheck = "rootcheck";              /* Agent Config  */
    const char *osalerts = "alerts";                    /* Server Config */
    const char *osemailalerts = "email_alerts";         /* Server Config */
    const char *osdbd = "database_output";              /* Server Config */
    const char *oscsyslogd = "syslog_output";           /* Server Config */
    const char *oscsyslogd_config = "csyslog";          /* Server Config */
    const char *oscagentless = "agentless";             /* Server Config */
    const char *oslocalfile = "localfile";              /* Agent Config  */
    const char *osremote = "remote";                    /* Agent Config  */
    const char *osclient = "client";                    /* Agent Config  */
    const char *osbuffer = "client_buffer";             /* Agent Buffer Config  */
    const char *oscommand = "command";                  /* ? Config      */
    const char *osreports = "reports";                  /* Server Config */
    const char *osintegratord = "integration";          /* Server Config */
    const char *osactive_response = "active-response";  /* Agent Config  */
    const char *oswmodule = "wodle";                    /* Wodle - Wazuh Module  */
    const char *oslabels = "labels";                    /* Labels Config */
    const char *osauthd = "auth";                       /* Authd Config */
    const char *oslogging = "logging";                  /* Logging Config */
    const char *osmonitor = "monitor";                  /* Monitor Config */
    const char *oscluster = "cluster";                  /* Cluster Config */
    const char *ossocket = "socket";                    /* Socket Config */
    const char *ossca = "sca";                          /* Security Configuration Assessment */
    const char *osmail = "mail";                        /* Mail Config */
    const char *oslogcollector = "logcollector";        /* Logcollector Config */
    const char *osexec = "exec";                        /* Exec Config */
    const char *osintegrator = "integrator";            /* Integrator Config */
    const char *osanalysis = "analysis";                /* Analysis Config */
    const char *osvulndet = "vulnerability-detector";   /* Vulnerability Detector Config */
#ifndef WIN32
    const char *osfluent_forward = "fluent-forward";    /* Fluent forwarder */
#endif
    const char *oswmodules_config = "modules";    /* Wazuh Modules Config */
    const char *oswdatabase = "database";               /* Wazuh Database Config */
    const char *oswdownload = "download";               /* Wazuh Download Config */

    while (node[i]) {
        XML_NODE chld_node = NULL;

        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            goto fail;
        }

        chld_node = OS_GetElementsbyNode(xml, node[i]);

        if (chld_node && (strcmp(node[i]->element, osglobal) == 0)) {
            if (((modules & CGLOBAL) || (modules & CMAIL))
                    && (Read_Global(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osanalysis) == 0)) {
            if ((modules & CGLOBAL) && (Read_Analysis(xml, chld_node, d1) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osemailalerts) == 0)) {
            if ((modules & CMAIL) && (Read_EmailAlerts(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osmail) == 0)) {
            if ((modules & CMAIL) && (Read_Mail(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osdbd) == 0)) {
            if ((modules & CDBD) && (Read_DB(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oscsyslogd) == 0)) {
            if ((modules & CSYSLOGD) && (Read_CSyslog(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oscsyslogd_config) == 0)) {
            if ((modules & CSYSLOG_CONF) && (Read_CSyslog_Options(chld_node, d1) < 0)) {
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
        } else if (chld_node && (strcmp(node[i]->element, osrules) == 0)) {
            if ((modules & CRULES) && (Read_Rules(chld_node, d1, d2) < 0)) {
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
        } else if (chld_node && (strcmp(node[i]->element, osalerts) == 0)) {
            if ((modules & CALERTS) && (Read_Alerts(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oslocalfile) == 0)) {
            if ((modules & CLOCALFILE) && (Read_Localfile(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oslogcollector) == 0)) {
            if ((modules & CLOGCOLLECTOR) && (Read_Logcollector(xml, chld_node, d1, modules) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osremote) == 0)) {
            if ((modules & CREMOTE) && (Read_Remote(xml, chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osclient) == 0)) {
            if (Read_RemoteConf(chld_node, modules) < 0) {
                goto fail;
            }
            if ((modules & CCLIENT) && (Read_Client(xml, chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, osbuffer) == 0) {
            if ((modules & CBUFFER) && (Read_ClientBuffer(xml, chld_node, d1, d2, modules) < 0)) {
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
        } else if (chld_node && (strcmp(node[i]->element, osreports) == 0)) {
            if ((modules & CREPORTS) && (Read_CReports(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, oswmodule) == 0) {
            if ((modules & CWMODULE) && (Read_WModule(xml, node[i], d1, d2) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, ossca) == 0) {
            if ((modules & CWMODULE) && (Read_SCA(xml, node[i], d1, modules) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, osvulndet) == 0) {
#if !defined(WIN32) && !defined(CLIENT)
            if ((modules & CWMODULE) && (Read_Vuln(xml, chld_node, d1, 1) < 0)) {
                goto fail;
            }
#else
            mwarn("%s configuration is only set in the manager.", node[i]->element);
#endif
        }
#ifndef WIN32
        else if (strcmp(node[i]->element, osfluent_forward) == 0) {
            if ((modules & CWMODULE) && (Read_Fluent_Forwarder(xml, node[i], d1) < 0)) {
                goto fail;
            }
        }
#endif
        else if (strcmp(node[i]->element, oswmodules_config) == 0) {
            if ((modules & CWMODULE) && (Read_WModules_Config(chld_node, d1) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, oswdatabase) == 0) {
            if ((modules & CWDATABASE) && (Read_WDatabase(xml, chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oslabels) == 0)) {
            if ((modules & CLABELS) && (Read_Labels(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (strcmp(node[i]->element, osauthd) == 0) {
            if ((modules & CAUTHD) && (Read_Authd(xml, chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && strcmp(node[i]->element, oslogging) == 0) {
            if ((modules & CROTMONITORD) && (Read_RotationMonitord(xml, chld_node, d1, d2) < 0)) {
                goto fail;
            }
            if ((modules & CROTANALYSD) && (Read_RotationAnalysisd(xml, chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && strcmp(node[i]->element, osmonitor) == 0) {
#ifndef CLIENT
            if ((modules & CROTMONITORD) && (Read_Monitor(chld_node, d1, d2) < 0)) {
                goto fail;
            }
#else
            merror(XML_INVELEM, node[i]->element);
            goto fail;
#endif
        } else if (chld_node && (strcmp(node[i]->element, oscluster) == 0)) {
            if ((modules & CCLUSTER) && (Read_Cluster(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, ossocket) == 0)) {
            if ((modules & CSOCKET) && (Read_Socket(chld_node, d1, d2) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osexec) == 0)) {
            if ((modules & CEXEC) && (Read_Exec(chld_node, d1) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, osintegrator) == 0)) {
            if ((modules & CINTEGRATOR) && (Read_Integrator_Options(chld_node, d1) < 0)) {
                goto fail;
            }
        } else if (chld_node && (strcmp(node[i]->element, oswdownload) == 0)) {
            if ((modules & CWDOWNLOAD) && (Read_WDownload(chld_node, d1) < 0)) {
                goto fail;
            }
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
    const char *xml_start_ossec = "ossec_config";
    const char *xml_start_agent = "agent_config";

    /* Attributes of the <agent_config> tag */
    const char *xml_agent_name = "name";
    const char *xml_agent_os = "os";
    const char *xml_agent_overwrite = "overwrite";
    const char *xml_agent_profile = "profile";

    if ((modules & CAGENT_CONFIG) && !remote_conf) {
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
                    merror(CONFIG_ERROR, cfgfile);
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

/* Set the value of a configuration option
 *
 * Arguments:
 *
 * c_value: the value (string) that is going to be set
 * var: the configuration variable that it's going to be set
 * option: settings that this options has (default value, minimum value, maximum value)
 * name: the name of the option
 *
 * Returns 0 on success and -1 on error
 *
 */
int SetConf(const char *c_value, int *var, const option_t option, const char *name)
{
    /* Check if the value set is numeric */
    if ((strspn(c_value, "0123456789-") == strlen(c_value))) {
        int value = atoi(c_value);

        if ((value < option.min) || (value > option.max)) {
            /* This is an invalid value */
            merror_exit("'%s' option is being set to a value beyond or below the acceptable limits.", name);
            return -1;
        }
        *var = value;
        return 0;
    } else {
        /* This is an invalid value */
        merror_exit("'%s' option is being set with an invalid value.", name);
        return -1;
    }
    return 0;
}
int Read_RotationAnalysisd(const OS_XML *xml, XML_NODE node, void *config, __attribute__((unused)) void *config2) {
    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int k = 0;

    /* XML definitions */
    const char *xml_alerts_config = "alerts";
    const char *xml_archives_config = "archives";
    const char *xml_enabled = "enabled";
    const char *xml_format = "format";
    const char *xml_rotation = "rotation";
    const char *xml_max_size = "max_size";
    const char *xml_min_size = "min_size";
    const char *xml_schedule = "schedule";
    const char *xml_rotate = "rotate";
    const char *xml_compress = "compress";
    const char *xml_maxage = "maxage";

    XML_NODE children = NULL;
    XML_NODE rotation_children = NULL;

    _Config *Config = (_Config *)config;

    /* Zero the elements */
    Config->alerts_enabled = 0;
    Config->alerts_max_size = 0;
    Config->alerts_min_size = 0;
    Config->alerts_interval = 24;
    Config->alerts_interval_units = 'h';
    Config->alerts_rotate = -1;
    Config->alerts_rotation_enabled = 1;
    Config->alerts_compress_rotation = 1;
    Config->alerts_maxage = 31;
    Config->alerts_log_plain = 0;
    Config->alerts_log_json = 0;

    Config->archives_enabled = 0;
    Config->archives_max_size = 0;
    Config->archives_min_size = 0;
    Config->archives_interval = 24;
    Config->archives_interval_units = 'h';
    Config->archives_rotate = -1;
    Config->archives_rotation_enabled = 1;
    Config->archives_compress_rotation = 1;
    Config->archives_maxage = 31;
    Config->archives_log_plain = 0;
    Config->archives_log_json = 0;

    /* Reading the XML */
    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_alerts_config) == 0) {
            // Get children
            if (!(children = OS_GetElementsbyNode(xml, node[i]))) {
                mdebug1("Empty configuration for module '%s'.", node[i]->element);
                return(OS_INVALID);
            }
            /* Read the configuration inside alerts tag */
            for (j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, xml_enabled) == 0) {
                    if(strcmp(children[j]->content, "yes") == 0) {
                        Config->alerts_enabled = 1;
                    } else if(strcmp(children[j]->content, "no") == 0) {
                        Config->alerts_enabled = 0;
                    } else {
                        merror(XML_VALUEERR,children[j]->element,children[j]->content);
                        OS_ClearNode(children);
                        return(OS_INVALID);
                    }
                } else if (strcmp(children[j]->element, xml_format) == 0) {
                    const char *delim = ",";
                    char *format = NULL;
                    int format_it = 0;
                    format = strtok(children[j]->content, delim);

                    while (format) {
                        if (*format && !strncmp(format, "json", strlen(format))) {
                            Config->alerts_log_json = 1;
                            format = strtok(NULL, delim);
                            format_it++;
                        } else if (*format && !strncmp(format, "plain", strlen(format))) {
                            Config->alerts_log_plain = 1;
                            format = strtok(NULL, delim);
                            format_it++;
                        } else {
                            merror(XML_VALUEERR,children[j]->element,format);
                            OS_ClearNode(children);
                            return(OS_INVALID);
                        }
                    }
                }
                else if (strcmp(children[j]->element, xml_rotation) == 0) {
                    if (!(rotation_children = OS_GetElementsbyNode(xml, children[j]))) {
                        mdebug1("Empty configuration for module '%s'.", children[j]->element);
                        continue;
                    }
                    /* Read the configuration inside rotation tag */
                    for (k = 0; rotation_children[k]; k++) {
                        if (strcmp(rotation_children[k]->element, xml_max_size) == 0) {
                            char * end;
                            char c;
                            Config->alerts_size_rotate = strtol(rotation_children[k]->content, &end, 10);
                            switch (sscanf(rotation_children[k]->content, "%ld%c", &Config->alerts_max_size, &c)) {
                                case 1:
                                    break;
                                case 2:
                                    switch (c) {
                                        case 'G':
                                        case 'g':
                                            Config->alerts_max_size *= 1073741824;
                                            break;
                                        case 'M':
                                        case 'm':
                                            Config->alerts_max_size *= 1048576;
                                            break;
                                        case 'K':
                                        case 'k':
                                            Config->alerts_max_size *= 1024;
                                            break;
                                        case 'B':
                                        case 'b':
                                            break;
                                        default:
                                            merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                            OS_ClearNode(rotation_children);
                                            OS_ClearNode(children);
                                            return (OS_INVALID);
                                    }
                                    break;
                                default:
                                    merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                    OS_ClearNode(rotation_children);
                                    OS_ClearNode(children);
                                    return (OS_INVALID);
                            }
                            Config->alerts_size_units = c;
                            if (Config->alerts_max_size < 1048576) {
                                merror("The minimum allowed value for '%s' is 1 MB.", rotation_children[k]->element);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return (OS_INVALID);
                            }
                        } else if (strcmp(rotation_children[k]->element, xml_min_size) == 0) {
                            char *end;
                            char c;
                            Config->alerts_min_size_rotate = strtol(rotation_children[k]->content, &end, 10);
                            switch (sscanf(rotation_children[k]->content, "%ld%c", &Config->alerts_min_size, &c)) {
                                case 1:
                                    break;
                                case 2:
                                    switch (c) {
                                        case 'G':
                                        case 'g':
                                            Config->alerts_min_size *= 1073741824;
                                            break;
                                        case 'M':
                                        case 'm':
                                            Config->alerts_min_size *= 1048576;
                                            break;
                                        case 'K':
                                        case 'k':
                                            Config->alerts_min_size *= 1024;
                                            break;
                                        case 'B':
                                        case 'b':
                                            break;
                                        default:
                                            merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                            OS_ClearNode(rotation_children);
                                            OS_ClearNode(children);
                                            return (OS_INVALID);
                                    }
                                    break;
                                default:
                                    merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                    OS_ClearNode(rotation_children);
                                    OS_ClearNode(children);
                                    return (OS_INVALID);
                            }
                            Config->alerts_min_size_units = c;
                            if (Config->alerts_min_size < 1048576) {
                                merror("The minimum allowed value for '%s' is 1 MB.", rotation_children[k]->element);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return (OS_INVALID);
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_schedule) == 0) {
                            char c;
                            char *end;
                            Config->alerts_interval = strtol(rotation_children[k]->content, &end, 10);
                            switch (sscanf(rotation_children[k]->content, "%ld%c", &Config->alerts_interval, &c)) {
                                case 0:
                                    if (Config->alerts_interval =  day_to_int(rotation_children[k]->content), Config->alerts_interval) {
                                        Config->alerts_interval_units = 'w';
                                    } else {
                                        merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                        OS_ClearNode(rotation_children);
                                        OS_ClearNode(children);
                                        return (OS_INVALID);
                                    }
                                    break;
                                case 2:
                                    switch (c) {
                                        case 'm':
                                            Config->alerts_interval_units = 'm';
                                            break;
                                        case 'h':
                                            Config->alerts_interval_units = 'h';
                                            break;
                                        default:
                                            merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                            OS_ClearNode(rotation_children);
                                            OS_ClearNode(children);
                                            return (OS_INVALID);
                                    }
                                    break;
                                default:
                                    merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                    OS_ClearNode(rotation_children);
                                    OS_ClearNode(children);
                                    return (OS_INVALID);
                            }
                            if ((24 % Config->alerts_interval != 0 && !strcmp(&Config->alerts_interval_units, "h"))
                                || (Config->alerts_interval > 60 || Config->alerts_interval < 1) ||
                                (24*60 % Config->alerts_interval != 0 && !strcmp(&Config->alerts_interval_units, "m"))) {
                                merror("Value for 'schedule' in <alerts> not allowed. Allowed values: [1h, 2h, 3h, 4h, 6h, "
                                       "8h, 12h, monday, tuesday, wednesday, thursday, friday, saturday, sunday].");
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return (OS_INVALID);
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_rotate) == 0) {
                            char *end;
                            Config->alerts_rotate = strtol(rotation_children[k]->content, &end, 10);
                            if(Config->alerts_rotate < 2 && Config->alerts_rotate != -1) {
                                mwarn("Minimum value for 'rotate' in <alerts> not allowed. It will be set to 2.");
                                Config->alerts_rotate = 2;
                            }
                            if (*end != '\0') {
                                merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return OS_INVALID;
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_enabled) == 0) {
                            if(strcmp(rotation_children[k]->content, "yes") == 0) {
                                Config->alerts_rotation_enabled = 1;
                            } else if(strcmp(rotation_children[k]->content, "no") == 0) {
                                Config->alerts_rotation_enabled = 0;
                            } else {
                                merror(XML_VALUEERR,rotation_children[k]->element, rotation_children[k]->content);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return(OS_INVALID);
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_compress) == 0) {
                            if(strcmp(rotation_children[k]->content, "yes") == 0) {
                                Config->alerts_compress_rotation = 1;
                            } else if(strcmp(rotation_children[k]->content, "no") == 0) {
                                Config->alerts_compress_rotation = 0;
                            } else {
                                merror(XML_VALUEERR,rotation_children[k]->element, rotation_children[k]->content);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return(OS_INVALID);
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_maxage) == 0) {
                            char *end;
                            Config->alerts_maxage = strtol(rotation_children[k]->content, &end, 10);
                            if(Config->alerts_maxage < 0 || Config->alerts_maxage > 500) {
                                mwarn("Value for 'maxage' in <alerts> out of bounds [0-500]. It will be set to 31 days.");
                                Config->alerts_maxage = 31;
                            }
                            if (*end != '\0') {
                                merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return OS_INVALID;
                            }
                        } else {
                            merror(XML_ELEMNULL);
                            OS_ClearNode(rotation_children);
                            OS_ClearNode(children);
                            return OS_INVALID;
                        }
                    }
                    OS_ClearNode(rotation_children);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        } else if (strcmp(node[i]->element, xml_archives_config) == 0) {
            // Get children
            if (!(children = OS_GetElementsbyNode(xml, node[i]))) {
                mdebug1("Empty configuration for module '%s'.", node[i]->element);
                return OS_INVALID;
            }
            /* Read the configuration inside archives tag */
            for (j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, xml_enabled) == 0) {
                    if(strcmp(children[j]->content, "yes") == 0) {
                        Config->archives_enabled = 1;
                    } else if(strcmp(children[j]->content, "no") == 0) {
                        Config->archives_enabled = 0;
                    } else {
                        merror(XML_VALUEERR,children[j]->element,children[j]->content);
                        OS_ClearNode(children);
                        return(OS_INVALID);
                    }
                } else if (strcmp(children[j]->element, xml_format) == 0) {
                    const char *delim = ",";
                    char *format = NULL;
                    int format_it = 0;
                    format = strtok(children[j]->content, delim);

                    while (format) {
                        if (*format && !strncmp(format, "json", strlen(format))) {
                            Config->archives_log_json = 1;
                            format = strtok(NULL, delim);
                            format_it++;
                        } else if (*format && !strncmp(format, "plain", strlen(format))) {
                            Config->archives_log_plain = 1;
                            format = strtok(NULL, delim);
                            format_it++;
                        } else {
                            merror(XML_VALUEERR,children[j]->element,format);
                            OS_ClearNode(children);
                            return(OS_INVALID);
                        }
                    }
                }
                else if (strcmp(children[j]->element, xml_rotation) == 0) {
                    if (!(rotation_children = OS_GetElementsbyNode(xml, children[j]))) {
                        mdebug1("Empty configuration for module '%s'.", children[j]->element);
                        continue;
                    }
                    /* Read the configuration inside rotation tag */
                    for (k = 0; rotation_children[k]; k++) {
                        if (strcmp(rotation_children[k]->element, xml_max_size) == 0) {
                            char *end;
                            char c;
                            Config->archives_size_rotate = strtol(rotation_children[k]->content, &end, 10);
                            switch (sscanf(rotation_children[k]->content, "%ld%c", &Config->archives_max_size, &c)) {
                                case 1:
                                    break;
                                case 2:
                                    switch (c) {
                                        case 'G':
                                        case 'g':
                                            Config->archives_max_size *= 1073741824;
                                            break;
                                        case 'M':
                                        case 'm':
                                            Config->archives_max_size *= 1048576;
                                            break;
                                        case 'K':
                                        case 'k':
                                            Config->archives_max_size *= 1024;
                                            break;
                                        case 'B':
                                        case 'b':
                                            break;
                                        default:
                                            merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                            OS_ClearNode(rotation_children);
                                            OS_ClearNode(children);
                                            return (OS_INVALID);
                                    }
                                    break;
                                default:
                                    merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                    OS_ClearNode(rotation_children);
                                    OS_ClearNode(children);
                                    return (OS_INVALID);
                            }
                            Config->archives_size_units = c;
                            if (Config->archives_max_size < 1048576) {
                                merror("The minimum allowed value for '%s' is 1 MB.", rotation_children[k]->element);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return (OS_INVALID);
                            }
                        } else if (strcmp(rotation_children[k]->element, xml_min_size) == 0) {
                            char *end;
                            char c;
                            Config->archives_min_size_rotate = strtol(rotation_children[k]->content, &end, 10);
                            switch (sscanf(rotation_children[k]->content, "%ld%c", &Config->archives_min_size, &c)) {
                                case 1:
                                    break;
                                case 2:
                                    switch (c) {
                                        case 'G':
                                        case 'g':
                                            Config->archives_min_size *= 1073741824;
                                            break;
                                        case 'M':
                                        case 'm':
                                            Config->archives_min_size *= 1048576;
                                            break;
                                        case 'K':
                                        case 'k':
                                            Config->archives_min_size *= 1024;
                                            break;
                                        case 'B':
                                        case 'b':
                                            break;
                                        default:
                                            merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                            OS_ClearNode(rotation_children);
                                            OS_ClearNode(children);
                                            return (OS_INVALID);
                                    }
                                    break;
                                default:
                                    merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                    OS_ClearNode(rotation_children);
                                    OS_ClearNode(children);
                                    return (OS_INVALID);
                            }
                            Config->archives_min_size_units = c;
                            if (Config->archives_min_size < 1048576) {
                                merror("The minimum allowed value for '%s' is 1 MB.", rotation_children[k]->element);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return (OS_INVALID);
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_schedule) == 0) {
                            char c;
                            char *end;
                            Config->archives_interval = strtol(rotation_children[k]->content, &end, 10);
                            switch (sscanf(rotation_children[k]->content, "%ld%c", &Config->archives_interval, &c)) {
                                case 0:
                                    if (Config->archives_interval =  day_to_int(rotation_children[k]->content), Config->archives_interval) {
                                        Config->archives_interval_units = 'w';
                                    } else {
                                        merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                        OS_ClearNode(rotation_children);
                                        OS_ClearNode(children);
                                        return (OS_INVALID);
                                    }
                                    break;
                                case 2:
                                    switch (c) {
                                        case 'm':
                                            Config->archives_interval_units = 'm';
                                            break;
                                        case 'h':
                                            Config->archives_interval_units = 'h';
                                            break;
                                        default:
                                            merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                            OS_ClearNode(rotation_children);
                                            OS_ClearNode(children);
                                            return (OS_INVALID);
                                    }
                                    break;
                                default:
                                    merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                    OS_ClearNode(rotation_children);
                                    OS_ClearNode(children);
                                    return (OS_INVALID);
                            }
                            if ((24 % Config->archives_interval != 0 && !strcmp(&Config->archives_interval_units, "h"))
                                || (Config->archives_interval > 24 || Config->archives_interval < 1) ||
                                (24*60 % Config->archives_interval != 0 && !strcmp(&Config->archives_interval_units, "m"))) {
                                merror("Value for 'schedule' in <archives> not allowed. Allowed values: [1h, 2h, 3h, 4h, 6h, "
                                       "8h, 12h, monday, tuesday, wednesday, thursday, friday, saturday, sunday].");
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return (OS_INVALID);
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_rotate) == 0) {
                            char *end;
                            Config->archives_rotate = strtol(rotation_children[k]->content, &end, 10);
                            if(Config->archives_rotate < 2 && Config->archives_rotate != -1) {
                                mwarn("Minimum value for 'rotate' in <archives> not allowed. It will be set to 2.");
                                Config->archives_rotate = 2;
                            }
                            if (*end != '\0') {
                                merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return OS_INVALID;
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_enabled) == 0) {
                            if(strcmp(rotation_children[k]->content, "yes") == 0) {
                                Config->archives_rotation_enabled = 1;
                            } else if(strcmp(rotation_children[k]->content, "no") == 0) {
                                Config->archives_rotation_enabled = 0;
                            } else {
                                merror(XML_VALUEERR,rotation_children[k]->element, rotation_children[k]->content);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return(OS_INVALID);
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_compress) == 0) {
                            if(strcmp(rotation_children[k]->content, "yes") == 0) {
                                Config->archives_compress_rotation = 1;
                            } else if(strcmp(rotation_children[k]->content, "no") == 0) {
                                Config->archives_compress_rotation = 0;
                            } else {
                                merror(XML_VALUEERR,rotation_children[k]->element, rotation_children[k]->content);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return(OS_INVALID);
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_maxage) == 0) {
                            char *end;
                            Config->archives_maxage = strtol(rotation_children[k]->content, &end, 10);
                            if(Config->archives_maxage < 0 || Config->archives_maxage > 500) {
                                mwarn("Value for 'maxage' in <archives> out of bounds [0-500]. It will be set to 31 days.");
                                Config->archives_maxage = 31;
                            }
                            if (*end != '\0') {
                                merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return OS_INVALID;
                            }
                        } else {
                            merror(XML_ELEMNULL);
                            OS_ClearNode(rotation_children);
                            OS_ClearNode(children);
                            return OS_INVALID;
                        }
                    }
                    OS_ClearNode(rotation_children);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        }
        i++;
    }

    if (!Config->alerts_enabled) {
        Config->alerts_log_json = 0;
        Config->alerts_log_plain = 0;
    }

    if (!Config->archives_enabled) {
        Config->archives_log_json = 0;
        Config->archives_log_plain = 0;
    }

    if ((Config->archives_min_size > 0 && Config->archives_max_size > 0) || (Config->alerts_min_size > 0 && Config->alerts_max_size > 0)) {
        merror("'max_size' and 'min_size' options cannot be used together for log rotation.");
        return OS_INVALID;
    }

    return (0);
}
