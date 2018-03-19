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
static const char *XML_FEED = "feed";
static const char *XML_NAME = "name";
static const char *XML_UPDATE_INTERVAL = "update_interval";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_IGNORE_TIME = "ignore_time";
static const char *XML_URL = "url";
static const char *XML_PATH = "path";
static const char *XML_PORT = "port";
static const char *XML_ALLOW = "allow";
// Deprecated
static const char *XML_UPDATE_UBUNTU_OVAL = "update_ubuntu_oval";
static const char *XML_UPDATE_REDHAT_OVAL = "update_redhat_oval";

char *format_os_version(char *OS) {
    char *OS_format = NULL;
    char distr[OS_SIZE_128];
    char vers[OS_SIZE_128];
    char subvers[OS_SIZE_128];
    int size;
    int elements;

    elements = sscanf(OS, "%s %s %s", distr, vers, subvers);
    size = strlen(distr) + strlen(vers) + strlen(subvers);
    os_calloc(size, sizeof(char), OS_format);
    if (strcasestr(distr, vu_dist_tag[DIS_WINDOWS])) {
        if (elements == 3) {
            snprintf(OS_format, OS_SIZE_256, "%s %s %s", distr, vers, subvers);
        } else {
            snprintf(OS_format, OS_SIZE_256, "%s %s", distr, vers);
        }
    } else {
        snprintf(OS_format, OS_SIZE_256, "%s: %s", distr, vers);
    }

    return OS_format;
}

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

int wm_vulnerability_detector_read(const OS_XML *xml, xml_node **nodes, wmodule *module) {
    unsigned int i, j;
    wm_vulnerability_detector_t * vulnerability_detector;
    XML_NODE chld_node = NULL;

    os_calloc(1, sizeof(wm_vulnerability_detector_t), vulnerability_detector);
    vulnerability_detector->flags.run_on_start = 1;
    vulnerability_detector->flags.enabled = 1;
    vulnerability_detector->flags.u_flags.update = 0;
    vulnerability_detector->flags.u_flags.update_ubuntu = 0;
    vulnerability_detector->flags.u_flags.update_debian = 0;
    vulnerability_detector->flags.u_flags.update_redhat = 0;
    vulnerability_detector->flags.u_flags.update_windows = 0;
    vulnerability_detector->flags.u_flags.update_macos = 0;
    vulnerability_detector->ignore_time = VU_DEF_IGNORE_TIME;
    vulnerability_detector->detection_interval = WM_VULNDETECTOR_DEFAULT_INTERVAL;
    vulnerability_detector->agents_software = NULL;
    module->context = &WM_VULNDETECTOR_CONTEXT;
    module->data = vulnerability_detector;

    for (i = 0; i < OS_SUPP_SIZE; i++) {
        vulnerability_detector->updates[i] = NULL;
    }

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
            if (get_interval(nodes[i]->content, &vulnerability_detector->detection_interval)) {
                merror("Invalid interval at module '%s'", WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_FEED)) {
            char *feed;
            char *version;
            cve_db os_index;
            update_node *upd;

            if (!nodes[i]->attributes || strcmp(*nodes[i]->attributes, XML_NAME)) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_FEED, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
            for (j = 0; *(feed = &nodes[i]->values[0][j]) != '\0'; j++) {
                if (isalpha(*feed)) {
                    *feed = toupper(*feed);
                }
            }
            feed = nodes[i]->values[0];
            if (version = strchr(feed, '-'), version) {
                *version = '\0';
                version++;
            } else {
                merror("Invalid OS for tag '%s' at module '%s'.", XML_FEED, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }

            os_calloc(1, sizeof(update_node), upd);
            upd->allowed_list = NULL;

            // Check OS
            if (!strcmp(feed, vu_dist_tag[DIS_UBUNTU])) {
                if (!strcmp(version, "12") || !strcmp(version, vu_dist_tag[DIS_PRECISE])) {
                    os_index = CVE_PRECISE;
                    os_strdup(vu_dist_tag[DIS_PRECISE], upd->version);
                    upd->dist_tag = vu_dist_tag[DIS_PRECISE];
                    upd->dist_ext = vu_dist_ext[DIS_PRECISE];
                    upd->dist_ref = DIS_UBUNTU;
                } else if (!strcmp(version, "14") || !strcmp(version, vu_dist_tag[DIS_TRUSTY])) {
                    os_index = CVE_TRUSTY;
                    os_strdup(vu_dist_tag[DIS_TRUSTY], upd->version);
                    upd->dist_tag = vu_dist_tag[DIS_TRUSTY];
                    upd->dist_ext = vu_dist_ext[DIS_TRUSTY];
                    upd->dist_ref = DIS_UBUNTU;
                } else if (!strcmp(version, "16") || !strcmp(version, vu_dist_tag[DIS_XENIAL])) {
                    os_index = CVE_XENIAL;
                    os_strdup(vu_dist_tag[DIS_XENIAL], upd->version);
                    upd->dist_tag = vu_dist_tag[DIS_XENIAL];
                    upd->dist_ext = vu_dist_ext[DIS_XENIAL];
                    upd->dist_ref = DIS_UBUNTU;
                } else {
                    merror("Invalid Ubuntu version '%s'.", version);
                    return OS_INVALID;
                }
            } else  if (!strcmp(feed, vu_dist_tag[DIS_DEBIAN])) {
                if (!strcmp(version, "9") || !strcmp(version, vu_dist_tag[DIS_STRETCH])) {
                    os_index = CVE_STRETCH;
                    os_strdup(vu_dist_tag[DIS_STRETCH], upd->version);
                    upd->dist_tag = vu_dist_tag[DIS_STRETCH];
                    upd->dist_ext = vu_dist_ext[DIS_STRETCH];
                    upd->dist_ref = DIS_DEBIAN;
                } else if (!strcmp(version, "8") || !strcmp(version, vu_dist_tag[DIS_JESSIE])) {
                    os_index = CVE_JESSIE;
                    os_strdup(vu_dist_tag[DIS_JESSIE], upd->version);
                    upd->dist_tag = vu_dist_tag[DIS_JESSIE];
                    upd->dist_ext = vu_dist_ext[DIS_JESSIE];
                    upd->dist_ref = DIS_DEBIAN;
                } else if (!strcmp(version, "7") || !strcmp(version, vu_dist_tag[DIS_WHEEZY])) {
                    os_index = CVE_WHEEZY;
                    os_strdup(vu_dist_tag[DIS_WHEEZY], upd->version);
                    upd->dist_tag = vu_dist_tag[DIS_WHEEZY];
                    upd->dist_ext = vu_dist_ext[DIS_WHEEZY];
                    upd->dist_ref = DIS_DEBIAN;
                } else {
                    merror("Invalid Debian version '%s'.", version);
                    return OS_INVALID;
                }
            } else if (!strcmp(feed, vu_dist_tag[DIS_REDHAT])) {
                if (!strcmp(version, "5")) {
                    os_index = CVE_RHEL5;
                    upd->dist_tag = vu_dist_tag[DIS_RHEL5];
                    upd->dist_ext = vu_dist_ext[DIS_RHEL5];
                    upd->dist_ref = DIS_REDHAT;
                } else if (!strcmp(version, "6")) {
                    os_index = CVE_RHEL6;
                    upd->dist_tag = vu_dist_tag[DIS_RHEL6];
                    upd->dist_ext = vu_dist_ext[DIS_RHEL6];
                    upd->dist_ref = DIS_REDHAT;
                } else if (!strcmp(version, "7")) {
                    os_index = CVE_RHEL7;
                    upd->dist_tag = vu_dist_tag[DIS_RHEL7];
                    upd->dist_ext = vu_dist_ext[DIS_RHEL7];
                    upd->dist_ref = DIS_REDHAT;
                } else {
                    merror("Invalid Redhat version '%s'.", version);
                    return OS_INVALID;
                }
            } else if (!strcmp(feed, vu_dist_tag[DIS_WINDOWS])) {
                if (!strcmp(version, "S2016")) {
                    os_index = CVE_WS2016;
                    os_strdup("server_2016", upd->version);
                    upd->dist_tag = vu_dist_tag[DIS_WS2016];
                    upd->dist_ext = vu_dist_ext[DIS_WS2016];
                    upd->dist_ref = DIS_WINDOWS;
                } else {
                    merror("Invalid Windows version '%s'.", version);
                    return OS_INVALID;
                }
            } else if (!strcmp(feed, vu_dist_tag[DIS_MACOS])) {
                if (!strcmp(version, "X")) {
                    os_index = CVE_MACOSX;
                    os_strdup("x", upd->version);
                    upd->dist_tag = vu_dist_tag[DIS_MACOSX];
                    upd->dist_ext = vu_dist_ext[DIS_MACOSX];
                    upd->dist_ref = DIS_MACOS;
                } else {
                    merror("Invalid Mac version '%s'.", version);
                    return OS_INVALID;
                }
            } else {
                merror("Invalid OS for tag '%s' at module '%s'.", XML_FEED, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }

            if (chld_node = OS_GetElementsbyNode(xml, nodes[i]), !chld_node) {
                merror(XML_INVELEM, nodes[i]->element);
                return OS_INVALID;
            }

            vulnerability_detector->updates[os_index] = upd;
            os_strdup(feed, upd->dist);
            if (!upd->version) {
                os_strdup(version, upd->version);
            }
            upd->url = NULL;
            upd->path = NULL;
            upd->port = 0;

            for (j = 0; chld_node[j]; j++) {
                if (!strcmp(chld_node[j]->element, XML_DISABLED)) {
                    if (!strcmp(chld_node[j]->content, "yes")) {
                        free(upd->dist);
                        free(upd->version);
                        if (upd->url) {
                            free(upd->url);
                        }
                        if (upd->path) {
                            free(upd->path);
                        }
                        free(upd);
                        vulnerability_detector->updates[os_index] = NULL;
                        break;
                    } else if (!strcmp(chld_node[j]->content, "no")) {
                        if (!strcmp(upd->dist, vu_dist_tag[DIS_REDHAT])) {
                            vulnerability_detector->flags.u_flags.update_redhat = 1;
                        } else if (!strcmp(upd->dist, vu_dist_tag[DIS_UBUNTU])) {
                            vulnerability_detector->flags.u_flags.update_ubuntu = 1;
                        } else if (!strcmp(upd->dist, vu_dist_tag[DIS_DEBIAN])) {
                            vulnerability_detector->flags.u_flags.update_debian = 1;
                        } else if (!strcmp(upd->dist, vu_dist_tag[DIS_WINDOWS])) {
                            vulnerability_detector->flags.u_flags.update_windows = 1;
                        } else if (!strcmp(upd->dist, vu_dist_tag[DIS_MACOS])) {
                            vulnerability_detector->flags.u_flags.update_macos = 1;
                        }
                    } else {
                        merror("Invalid content for '%s' option at module '%s'", XML_DISABLED, WM_VULNDETECTOR_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else if (!strcmp(chld_node[j]->element, XML_UPDATE_INTERVAL)) {
                    if (get_interval(chld_node[j]->content, &upd->interval)) {
                        merror("Invalid content for '%s' option at module '%s'", XML_UPDATE_INTERVAL, WM_VULNDETECTOR_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else if (!strcmp(chld_node[j]->element, XML_ALLOW)) {
                    int size;
                    char *found;
                    char *OS = chld_node[j]->content;

                    os_calloc(1, sizeof(char *), upd->allowed_list);

                    for (size = 0; (found = strchr(OS, ',')); size++) {
                        *(found++) = '\0';
                        os_realloc(upd->allowed_list, (size + 2)*sizeof(char *), upd->allowed_list);
                        upd->allowed_list[size] = format_os_version(OS);
                        upd->allowed_list[size + 1] = NULL;
                        OS = found;
                    }
                    os_realloc(upd->allowed_list, (size + 2)*sizeof(char *), upd->allowed_list);
                    upd->allowed_list[size] = format_os_version(OS);
                    upd->allowed_list[size + 1] = NULL;
                } else if (!strcmp(chld_node[j]->element, XML_URL)) {
                    os_strdup(chld_node[j]->content, upd->url);
                    if (*chld_node[j]->attributes && !strcmp(*chld_node[j]->attributes, XML_PORT)) {
                        upd->port = strtol(*chld_node[j]->values, NULL, 10);
                    }
                } else if (!strcmp(chld_node[j]->element, XML_PATH)) {
                    os_strdup(chld_node[j]->content, upd->path);
                } else {
                    merror("Invalid option '%s' for tag '%s' at module '%s'.", chld_node[j]->element, XML_FEED , WM_VULNDETECTOR_CONTEXT.name);
                    return OS_INVALID;
                }
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
        } else if (!strcmp(nodes[i]->element, XML_IGNORE_TIME)) {
            if (get_interval(nodes[i]->content, &vulnerability_detector->ignore_time)) {
                merror("Invalid ignore_time at module '%s'", WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_UPDATE_UBUNTU_OVAL) || !strcmp(nodes[i]->element, XML_UPDATE_REDHAT_OVAL)) {
            merror("'%s' option at module '%s' is deprecated. Use '%s' instead.", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name, XML_FEED);
            return OS_INVALID;
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name);
            return OS_INVALID;
        }
    }

    if (vulnerability_detector->flags.u_flags.update_ubuntu    ||
        vulnerability_detector->flags.u_flags.update_debian    ||
        vulnerability_detector->flags.u_flags.update_redhat    ||
        vulnerability_detector->flags.u_flags.update_windows   ||
        vulnerability_detector->flags.u_flags.update_macos) {
        vulnerability_detector->flags.u_flags.update = 1;
    }

    return 0;
}

#endif
#endif
