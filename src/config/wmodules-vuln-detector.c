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
#include "addagent/manage_agents.h"

//Options
static const char *XML_DISABLED = "disabled";
static const char *XML_INTERVAL = "interval";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_MIN_CVSS = "min_cvss";
static const char *XML_ANTIQUITY_LIMIT = "antiquity_limit";
static const char *XML_UPDATE_NVD = "update_nvd";
static const char *XML_UPDATE_UBUNTU_OVAL = "update_ubuntu_oval";
static const char *XML_UPDATE_REDHAT_OVAL = "update_redhat_oval";
static const char *XML_TARGET_GROUPS = "target_groups";
static const char *XML_TARGET_AGENTS = "target_agents";
static const char *XML_IGNORED_AGENTS = "ignored_agents";
static const char *XML_VERSION = "version";

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
    FILE *fp;
    unsigned int i, j;
    size_t size;
    char agent_info[OS_MAXSTR];
    agent_software *agents;
    keystore keys = KEYSTORE_INITIALIZER;
    keyentry *entry;
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

        } else if (!strcmp(nodes[i]->element, XML_ANTIQUITY_LIMIT)) {

        } else if (!strcmp(nodes[i]->element, XML_TARGET_AGENTS)) {
            int k;
            int agent_id;
            char * ids = nodes[i]->content;

            if (!vulnerability_detector->agents_software) {
                os_calloc(1, sizeof(agent_software), vulnerability_detector->agents_software);
                vulnerability_detector->agents_software->agent_id = NULL;
                vulnerability_detector->agents_software->next = NULL;
                vulnerability_detector->agents_software->agent_name = NULL;
                vulnerability_detector->agents_software->agent_ip = NULL;
                vulnerability_detector->agents_software->prev = NULL;
                vulnerability_detector->agents_software->OS = NULL;
                vulnerability_detector->agents_software->info = 0;
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
                        agents->info = 0;
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

    if (vulnerability_detector->agents_software) {
        OS_PassEmptyKeyfile();
        OS_ReadKeys(&keys, 0, 0, 0);
        if (!keys.keysize) {
            mterror(WM_VULNDETECTOR_LOGTAG, VU_NO_AGENT_REGISTERED);
            vulnerability_detector->flags.enabled = 0;
            return 0;
        }

        for (agents = vulnerability_detector->agents_software; agents; agents = agents->next) {
            for (i = 0; i < keys.keysize; i++) {
                entry = keys.keyentries[i];
                if (!strcmp(agents->agent_id, entry->id)) {
                    os_strdup(entry->name, agents->agent_name);
                    os_strdup(entry->ip->ip, agents->agent_ip);
                    agents->OS = NULL;
                    break;
                }
            }
            if (i == keys.keysize) {
                mterror(WM_VULNDETECTOR_LOGTAG, "Agent %s does not exist.", agents->agent_id);
                return OS_INVALID;
            }
        }
    } else {
        OS_PassEmptyKeyfile();
        OS_ReadKeys(&keys, 0, 0, 0);
        if (!keys.keysize) {
            mterror(WM_VULNDETECTOR_LOGTAG, VU_NO_AGENT_REGISTERED);
            vulnerability_detector->flags.enabled = 0;
            return 0;
        }
        agents = NULL;

        for (i = 0; i < keys.keysize; i++) {
            entry = keys.keyentries[i];
            if (agents) {
                os_calloc(1, sizeof(agent_software), agents->next);
                agents->next->prev = agents;
                agents = agents->next;
            } else {
                os_calloc(1, sizeof(agent_software), vulnerability_detector->agents_software);
                agents = vulnerability_detector->agents_software;
                agents->prev = NULL;
            }

            os_strdup(entry->id, agents->agent_id);
            os_strdup(entry->name, agents->agent_name);
            os_strdup(entry->ip->ip, agents->agent_ip);
            agents->OS = NULL;
            agents->info = 0;
            agents->next = NULL;
        }
    }

    // Extracts the operating system of the agents
    for (agents = vulnerability_detector->agents_software; agents;) {
        size = snprintf(agent_info, OS_MAXSTR, AGENT_INFO_FILEF, agents->agent_name, agents->agent_ip);
        agent_info[size] = '\0';
        // The agent has never been connected
        if (fp = fopen(agent_info, "r" ), !fp) {
            mterror(WM_VULNDETECTOR_LOGTAG, VU_AGENT_INFO_ERROR, agents->agent_name);
            if (agents = skip_agent(agents, &vulnerability_detector->agents_software), !agents) {
                break;
            } else {
                continue;
            }
        } else {
            char *buffer = agent_info;
            size_t max = OS_MAXSTR;

            // Agent connected or disconnected
            if (size = getline(&buffer, &max, fp), (int) size > 0) {
                buffer[size] = '\0';
                if (buffer = strchr(buffer, '['), buffer) {
                    buffer++;
                    *strchr(agent_info, ']') = '\0';
                    if (strcasestr(buffer, VU_UBUNTU)) {
                        if (strstr(buffer, " 16")) {
                            os_strdup(VU_XENIAL, agents->OS);
                        } else if (strstr(buffer, " 14")) {
                            os_strdup(VU_TRUSTY, agents->OS);
                        } else if (strstr(buffer, " 12")) {
                            os_strdup(VU_PRECISE, agents->OS);
                        } else {
                            mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UNS_OS_VERSION, VU_UBUNTU, agents->agent_name);
                            if (agents = skip_agent(agents, &vulnerability_detector->agents_software), !agents) {
                                break;
                            } else {
                                continue;
                            }
                        }
                    } else if (strcasestr(buffer, VU_RHEL)) {
                        if (strstr(buffer, " 7")) {
                            os_strdup(VU_RHEL7, agents->OS);
                        } else if (strstr(buffer, " 6")) {
                            os_strdup(VU_RHEL6, agents->OS);
                        } else if (strstr(VU_RHEL5, " 5")) {
                            os_strdup(VU_PRECISE, agents->OS);
                        } else {
                            mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UNS_OS_VERSION, VU_RHEL, agents->agent_name);
                            if (agents = skip_agent(agents, &vulnerability_detector->agents_software), !agents) {
                                break;
                            } else {
                                continue;
                            }
                        }
                    } else if (strcasestr(buffer, VU_CENTOS)) {
                        if (strstr(buffer, " 7")) {
                            os_strdup(VU_RHEL7, agents->OS);
                        } else if (strstr(buffer, " 6")) {
                            os_strdup(VU_RHEL6, agents->OS);
                        } else if (strstr(buffer, " 5")) {
                            os_strdup(VU_RHEL5, agents->OS);
                        } else {
                            mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UNS_OS_VERSION, VU_CENTOS, agents->agent_name);
                            if (agents = skip_agent(agents, &vulnerability_detector->agents_software), !agents) {
                                break;
                            } else {
                                continue;
                            }
                        }
                    } else {
                        mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UNS_OS, agents->agent_name);
                        if (agents = skip_agent(agents, &vulnerability_detector->agents_software), !agents) {
                            break;
                        }
                    }
                } else { // Operating system not supported in any of its versions
                    mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_AGENT_UNSOPPORTED, agents->agent_name);
                    if (agents = skip_agent(agents, &vulnerability_detector->agents_software), !agents) {
                        break;
                    } else {
                        continue;
                    }
                }
            } else { // Agent in pending state
                mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_AGENT_PENDING, agents->agent_name);
                if (agents = skip_agent(agents, &vulnerability_detector->agents_software), !agents) {
                    break;
                } else {
                    continue;
                }
            }
            agents = agents->next;
        }
        fclose(fp);
        fp = NULL;
    }
    if (fp) {
        fclose(fp);
    }

    if (!vulnerability_detector->agents_software) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_NO_AGENT_REGISTERED);
        vulnerability_detector->flags.enabled = 0;
    }

    return 0;
}

#endif
