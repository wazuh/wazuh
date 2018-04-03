/*
 * Wazuh Module Configuration
 * Copyright (C) 2018 Wazuh Inc.
 * January, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLIENT
#ifndef WIN32
#include "wazuh_modules/wmodules.h"

//Options
static const char *XML_DISABLED = "disabled";
static const char *XML_INTERVAL = "interval";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_UPDATE_UBUNTU_OVAL = "update_ubuntu_oval";
static const char *XML_UPDATE_REDHAT_OVAL = "update_redhat_oval";
static const char *XML_VERSION = "version";
// Upcoming parameters
//static const char *XML_TARGET_GROUPS = "target_groups";
//static const char *XML_MIN_CVSS = "min_cvss";
//static const char *XML_ANTIQUITY_LIMIT = "antiquity_limit";
//static const char *XML_UPDATE_NVD = "update_nvd";
//static const char *XML_IGNORED_AGENTS = "ignored_agents";


agent_software * skip_agent(agent_software *agents, agent_software **agents_list) {
    agent_software *next = NULL;
    if (agents->prev && agents->next) {
        next = agents->next;
        agents->prev->next = next;
        next->prev = agents->prev;
    } else if (agents->prev) {
        agents->prev->next = NULL;
    } else if (agents->next) {
        *agents_list = next = agents->next;
        next->prev = NULL;
    } else {
        *agents_list = NULL;
    }
    free(agents->agent_id);
    free(agents->agent_name);
    free(agents->agent_ip);
    free(agents);

    return next;
}

int get_interval(char *source, unsigned long *interval) {
    char *endptr;
    *interval = strtoul(source, &endptr, 0);

    if ((!*interval && endptr == source) || *interval == ULONG_MAX) {
        return OS_INVALID;
    }

    switch (*endptr) {
    case 'd':
        *interval *= 86400;
        break;
    case 'h':
        *interval *= 3600;
        break;
    case 'm':
        *interval *= 60;
        break;
    case 's':
    case '\0':
        break;
    default:
        return OS_INVALID;
    }

    return 0;
}

int wm_vulnerability_detector_read(xml_node **nodes, wmodule *module) {
    unsigned int i, j;
    //agent_software *agents;
    wm_vulnerability_detector_t * vulnerability_detector;

    os_calloc(1, sizeof(wm_vulnerability_detector_t), vulnerability_detector);
    vulnerability_detector->flags.run_on_start = 1;
    vulnerability_detector->flags.enabled = 1;
    vulnerability_detector->flags.u_flags.update = 0;
    vulnerability_detector->flags.u_flags.update_nvd = 0;
    vulnerability_detector->flags.u_flags.update_ubuntu = 0;
    vulnerability_detector->flags.u_flags.update_redhat = 0;
    vulnerability_detector->flags.u_flags.precise = 0;
    vulnerability_detector->flags.u_flags.trusty = 0;
    vulnerability_detector->flags.u_flags.xenial = 0;
    vulnerability_detector->flags.u_flags.rh5 = 0;
    vulnerability_detector->flags.u_flags.rh6 = 0;
    vulnerability_detector->flags.u_flags.rh7 = 0;
    vulnerability_detector->intervals.detect = WM_VULNDETECTOR_DEFAULT_INTERVAL;
    vulnerability_detector->intervals.ubuntu = 0;
    vulnerability_detector->intervals.redhat = 0;
    vulnerability_detector->agents_software = NULL;
    module->context = &WM_VULNDETECTOR_CONTEXT;
    module->data = vulnerability_detector;


    for (i = 0; nodes[i]; i++) {
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                vulnerability_detector->flags.enabled = 0;
            else if (!strcmp(nodes[i]->content, "no")) {
                vulnerability_detector->flags.enabled = 1;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            if (get_interval(nodes[i]->content, &vulnerability_detector->intervals.detect)) {
                merror("Invalid interval at module '%s'", WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_RUN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes")) {
                vulnerability_detector->flags.run_on_start = 1;
            } else if (!strcmp(nodes[i]->content, "no")) {
                vulnerability_detector->flags.run_on_start = 0;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_RUN_ON_START, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } /*else if (!strcmp(nodes[i]->element, XML_MIN_CVSS)) {

        } else if (!strcmp(nodes[i]->element, XML_ANTIQUITY_LIMIT)) {

        } else if (!strcmp(nodes[i]->element, XML_UPDATE_NVD)) {
            if (!strcmp(nodes[i]->content, "yes")) {
                vulnerability_detector->flags.u_flags.update_nvd = 1;
            } else if (!strcmp(nodes[i]->content, "no")) {
                vulnerability_detector->flags.u_flags.update_nvd = 0;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_RUN_ON_START, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        }*/ else if (!strcmp(nodes[i]->element, XML_UPDATE_UBUNTU_OVAL)) {
            if (!strcmp(nodes[i]->content, "yes")) {
                vulnerability_detector->flags.u_flags.update_ubuntu = 1;
                if (nodes[i]->attributes) {
                    for (j = 0; nodes[i]->attributes[j]; j++) {
                        if (!strcmp(nodes[i]->attributes[j], XML_VERSION)) {
                            int k;
                            char * version = nodes[i]->values[j];
                            for (k = 0;; k++) {
                                int out = (version[k] == '\0');
                                if (version[k] == ',' || out) {
                                    version[k] = '\0';
                                    if (!strcmp(version, "12")) {
                                        vulnerability_detector->flags.u_flags.precise = 1;
                                    } else if (!strcmp(version, "14")) {
                                        vulnerability_detector->flags.u_flags.trusty = 1;
                                    } else if (!strcmp(version, "16")) {
                                        vulnerability_detector->flags.u_flags.xenial = 1;
                                    } else {
                                        merror("Invalid Ubuntu version '%s'.", version);
                                    }
                                    version = &version[k] + 1;
                                    k = 0;
                                }
                                if (out)
                                    break;
                            }
                        } else if (!strcmp(nodes[i]->attributes[j], XML_INTERVAL)) {
                            if (get_interval(nodes[i]->values[j], &vulnerability_detector->intervals.ubuntu)) {
                                merror("Invalid interval at module '%s'", WM_VULNDETECTOR_CONTEXT.name);
                                return OS_INVALID;
                            }
                        } else {
                            merror("Invalid attribute '%s' for '%s'", nodes[i]->attributes[j], XML_UPDATE_UBUNTU_OVAL);
                        }
                    }
                }
            } else if (!strcmp(nodes[i]->content, "no")) {
                vulnerability_detector->flags.u_flags.update_ubuntu = 0;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_RUN_ON_START, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_UPDATE_REDHAT_OVAL)) {
            if (!strcmp(nodes[i]->content, "yes")) {
                vulnerability_detector->flags.u_flags.update_redhat = 1;
                if (nodes[i]->attributes) {
                    for (j = 0; nodes[i]->attributes[j]; j++) {
                        if (!strcmp(nodes[i]->attributes[j], XML_VERSION)) {
                            int k;
                            char * version = nodes[i]->values[j];
                            for (k = 0;; k++) {
                                int out = (version[k] == '\0');
                                if (version[k] == ',' || out) {
                                    version[k] = '\0';
                                    if (!strcmp(version, "5")) {
                                        mwarn("Vulnerability detection is not available for agents with CentOS/RedHat 5");
                                        //vulnerability_detector->flags.u_flags.rh5 = 1;
                                    } else if (!strcmp(version, "6")) {
                                        vulnerability_detector->flags.u_flags.rh6 = 1;
                                    } else if (!strcmp(version, "7")) {
                                        vulnerability_detector->flags.u_flags.rh7 = 1;
                                    } else {
                                        merror("Invalid Redhat version '%s'.", version);
                                    }
                                    version = &version[k] + 1;
                                    k = 0;
                                }
                                if (out)
                                    break;
                            }
                        } else if (!strcmp(nodes[i]->attributes[j], XML_INTERVAL)) {
                            if (get_interval(nodes[i]->values[j], &vulnerability_detector->intervals.redhat)) {
                                merror("Invalid interval at module '%s'", WM_VULNDETECTOR_CONTEXT.name);
                                return OS_INVALID;
                            }
                        } else {
                            merror("Invalid attribute '%s' for '%s'", nodes[i]->attributes[j], XML_UPDATE_REDHAT_OVAL);
                        }
                    }
                }
            } else if (!strcmp(nodes[i]->content, "no")) {
                vulnerability_detector->flags.u_flags.update_redhat = 0;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_RUN_ON_START, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } /*else if (!strcmp(nodes[i]->element, XML_TARGET_GROUPS)) {

        } else if (!strcmp(nodes[i]->element, XML_IGNORED_AGENTS)) {

        }*/ else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name);
            return OS_INVALID;
        }
    }

    if (vulnerability_detector->flags.u_flags.update_nvd || vulnerability_detector->flags.u_flags.update_ubuntu || vulnerability_detector->flags.u_flags.update_redhat) {
        vulnerability_detector->flags.u_flags.update = 1;
    }

    return 0;
}

#endif
#endif
