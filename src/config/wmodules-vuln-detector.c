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

#ifndef WIN32
#include "wazuh_modules/wmodules.h"

//Options
static const char *XML_DISABLED = "disabled";
static const char *XML_INTERVAL = "interval";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_MIN_CVSS = "min_cvss";
static const char *XML_SOURCE = "source";
static const char *XML_ANTIQUITY_LIMIT = "antiquity_limit";
static const char *XML_UPDATE_NVD = "update_nvd";
static const char *XML_UPDATE_UBUNTU_OVAL = "update_ubuntu_oval";
static const char *XML_UPDATE_REDHAT_OVAL = "update_redhat_oval";
static const char *XML_TARGET_GROUPS = "target_groups";
static const char *XML_TARGET_AGENTS = "target_agents";
static const char *XML_IGNORED_AGENTS = "ignored_agents";
static const char *XML_VERSION = "version";

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

int wm_vulnerability_detector_read(xml_node **nodes, wmodule *module)
{
    int i, j;
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
        } else if (!strcmp(nodes[i]->element, XML_MIN_CVSS)) {

        } else if (!strcmp(nodes[i]->element, XML_SOURCE)) {

        } else if (!strcmp(nodes[i]->element, XML_ANTIQUITY_LIMIT)) {

        } else if (!strcmp(nodes[i]->element, XML_TARGET_AGENTS)) {
            int k;
            int agent_id;
            agent_software *agents;
            char * ids = nodes[i]->content;

            if (!vulnerability_detector->agents_software) {
                os_calloc(1, sizeof(agent_software), vulnerability_detector->agents_software);
                vulnerability_detector->agents_software->agent_id = NULL;
                vulnerability_detector->agents_software->next = NULL;
                vulnerability_detector->agents_software->agent_name = NULL;
                vulnerability_detector->agents_software->agent_ip = NULL;
                vulnerability_detector->agents_software->prev = NULL;
                vulnerability_detector->agents_software->OS = NULL;
                //vulnerability_detector->agents_software->packages = NULL;
            }
            agents = vulnerability_detector->agents_software;

            for (;agents->next;) {
                agents = agents->next;
            }

            for (k = 0;; k++) {
                int out = (ids[k] == '\0');
                if (ids[k] == ',' || out) {
                    ids[k] = '\0';
                    if (agent_id = atoi(ids), !agent_id) {
                        merror("Invalid agent ID ('%s') at module '%s'.", ids, WM_VULNDETECTOR_CONTEXT.name);
                        return OS_INVALID;
                    }
                    if (agents->agent_id) {
                        os_calloc(1, sizeof(wm_vulnerability_detector_t), agents->next);
                        agents->next->prev = agents;
                        agents = agents->next;
                        agents->next = NULL;
                        agents->OS = NULL;
                        agents->agent_name = NULL;
                        agents->agent_ip = NULL;
                        //agents->packages = NULL;
                    }
                    os_calloc(1, 5, agents->agent_id);
                    if (agent_id < 10) {
                        snprintf(agents->agent_id, 5, "00%i", agent_id);
                    } else if (agent_id < 1000) {
                        snprintf(agents->agent_id, 5, "0%i", agent_id);
                    } else {
                        snprintf(agents->agent_id, 5, "%i", agent_id);
                    }

                    ids = &ids[k] + 1;
                    k = 0;
                }
                if (out)
                    break;
            }
        } else if (!strcmp(nodes[i]->element, XML_UPDATE_NVD)) {
            if (!strcmp(nodes[i]->content, "yes")) {
                vulnerability_detector->flags.u_flags.update_nvd = 1;
            } else if (!strcmp(nodes[i]->content, "no")) {
                vulnerability_detector->flags.u_flags.update_nvd = 0;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_RUN_ON_START, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_UPDATE_UBUNTU_OVAL)) {
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
                                        vulnerability_detector->flags.u_flags.rh5 = 1;
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
        } else if (!strcmp(nodes[i]->element, XML_TARGET_GROUPS)) {

        } else if (!strcmp(nodes[i]->element, XML_IGNORED_AGENTS)) {

        } else {
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
