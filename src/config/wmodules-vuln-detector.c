/*
 * Wazuh Module Configuration
 * Copyright (C) 2015-2019, Wazuh Inc.
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

static int get_interval(char *source, unsigned long *interval);
static int is_valid_year(char *source, int *date);
static int set_oval_version(char *feed, char *version, update_node **upd_list, update_node *upd);

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
static const char *XML_UPDATE_FROM_YEAR = "update_from_year";
// Deprecated
static const char *XML_UPDATE_UBUNTU_OVAL = "update_ubuntu_oval";
static const char *XML_UPDATE_REDHAT_OVAL = "update_redhat_oval";
static const char *XML_VERSION = "version";

int format_os_version(char *OS, char **os_name, char **os_ver) {
    char OS_cpy[OS_SIZE_1024];
    char distr[OS_SIZE_128];
    char sec_distr[OS_SIZE_128];
    char thi_distr[OS_SIZE_128];
    char inv_distr[OS_SIZE_128];
    char *ver;
    char *ver_end;
    int size;
    int elements;

    snprintf(OS_cpy, OS_SIZE_1024, "%s", OS);
    if (!(ver = strchr(OS_cpy, '-')) || *(ver + 1) == '\0') {
        return OS_INVALID;
    }
    *(ver++) = '\0';

    // Get distribution
    elements = sscanf(OS_cpy, "%s %s %s %s", distr, sec_distr, thi_distr, inv_distr);
    size = strlen(distr) + strlen(sec_distr) + strlen(thi_distr) + 3;
    os_calloc(size, sizeof(char), *os_name);

    // More than 3 words are considered invalid
    if (elements == 3) {
        snprintf(*os_name, size, "%s %s %s", distr, sec_distr, thi_distr);
    } else if (elements == 2) {
        snprintf(*os_name, size, "%s %s", distr, sec_distr);
    } else if (elements == 1) {
        snprintf(*os_name, size, "%s", distr);
    } else {
        free(*os_name);
        return OS_INVALID;
    }

    // Get version
    for (; *ver == ' '; ver++);
    if (ver_end = strchr(ver, ' '), ver_end) {
        *ver_end = '\0';
    }
    if (size = strlen(ver), size >= 20) {
        free(*os_name);
        return OS_INVALID;
    }
    os_strdup(ver, *os_ver);

    return 0;
}

int set_oval_version(char *feed, char *version, update_node **upd_list, update_node *upd) {
    cve_db os_index;

    if (!strcmp(feed, vu_dist_tag[DIS_UBUNTU])) {
        if (!strcmp(version, "12") || strcasestr(version, vu_dist_tag[DIS_PRECISE])) {
            os_index = CVE_PRECISE;
            os_strdup(vu_dist_tag[DIS_PRECISE], upd->version);
            upd->dist_tag = vu_dist_tag[DIS_PRECISE];
            upd->dist_ext = vu_dist_ext[DIS_PRECISE];
        } else if (!strcmp(version, "14") || strcasestr(version, vu_dist_tag[DIS_TRUSTY])) {
            os_index = CVE_TRUSTY;
            os_strdup(vu_dist_tag[DIS_TRUSTY], upd->version);
            upd->dist_tag = vu_dist_tag[DIS_TRUSTY];
            upd->dist_ext = vu_dist_ext[DIS_TRUSTY];
        } else if (!strcmp(version, "16") || strcasestr(version, vu_dist_tag[DIS_XENIAL])) {
            os_index = CVE_XENIAL;
            os_strdup(vu_dist_tag[DIS_XENIAL], upd->version);
            upd->dist_tag = vu_dist_tag[DIS_XENIAL];
            upd->dist_ext = vu_dist_ext[DIS_XENIAL];
        } else if (!strcmp(version, "18") || !strcmp(version, vu_dist_tag[DIS_BIONIC])) {
            os_index = CVE_BIONIC;
            os_strdup(vu_dist_tag[DIS_BIONIC], upd->version);
            upd->dist_tag = vu_dist_tag[DIS_BIONIC];
            upd->dist_ext = vu_dist_ext[DIS_BIONIC];
        } else {
            merror("Invalid Ubuntu version '%s'.", version);
            return OS_INVALID;
        }
        upd->dist_ref = DIS_UBUNTU;
    } else  if (!strcmp(feed, vu_dist_tag[DIS_DEBIAN])) {
        if (!strcmp(version, "9") || !strcmp(version, vu_dist_tag[DIS_STRETCH])) {
            os_index = CVE_STRETCH;
            os_strdup(vu_dist_tag[DIS_STRETCH], upd->version);
            upd->dist_tag = vu_dist_tag[DIS_STRETCH];
            upd->dist_ext = vu_dist_ext[DIS_STRETCH];
        } else if (!strcmp(version, "8") || !strcmp(version, vu_dist_tag[DIS_JESSIE])) {
            os_index = CVE_JESSIE;
            os_strdup(vu_dist_tag[DIS_JESSIE], upd->version);
            upd->dist_tag = vu_dist_tag[DIS_JESSIE];
            upd->dist_ext = vu_dist_ext[DIS_JESSIE];
        } else if (!strcmp(version, "7") || !strcmp(version, vu_dist_tag[DIS_WHEEZY])) {
            os_index = CVE_WHEEZY;
            os_strdup(vu_dist_tag[DIS_WHEEZY], upd->version);
            upd->dist_tag = vu_dist_tag[DIS_WHEEZY];
            upd->dist_ext = vu_dist_ext[DIS_WHEEZY];
        } else {
            merror("Invalid Debian version '%s'.", version);
            return OS_INVALID;
        }
        upd->dist_ref = DIS_DEBIAN;
    } else if (!strcmp(feed, vu_dist_tag[DIS_REDHAT])) {
        if (version) {
            mwarn("The specific definition of the Red Hat feeds is deprecated. Use only redhat instead.");
        }
        os_index = CVE_REDHAT;
        upd->dist_tag = vu_dist_tag[DIS_REDHAT];
        upd->dist_ext = vu_dist_ext[DIS_REDHAT];
        upd->dist_ref = DIS_REDHAT;
    } else {
        merror("Invalid OS for tag '%s' at module '%s'.", XML_FEED, WM_VULNDETECTOR_CONTEXT.name);
        return OS_INVALID;
    }

    os_strdup(feed, upd->dist);

    if (upd_list[os_index]) {
        mwarn("Duplicate OVAL configuration for '%s %s'.", upd->dist, upd->version);
        free(upd->dist);
        free(upd->version);
        free(upd);
        return OS_SUPP_SIZE;
    }

    upd_list[os_index] = upd;

    upd->url = NULL;
    upd->path = NULL;
    upd->port = 0;

    return os_index;
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

int is_valid_year(char *source, int *date) {
    time_t n_date;
    struct tm *t_date;

    *date = strtol(source, NULL, 10);
    n_date = time (NULL);
    t_date = gmtime(&n_date);

    if ((!*date) || *date < RED_HAT_REPO_MIN_YEAR || *date > (t_date->tm_year + 1900)) {
        return 0;
    }

    return 1;
}

int wm_vuldet_read(const OS_XML *xml, xml_node **nodes, wmodule *module) {
    unsigned int i, j;
    wm_vuldet_t * vulnerability_detector;
    XML_NODE chld_node = NULL;

    os_calloc(1, sizeof(wm_vuldet_t), vulnerability_detector);
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
    module->tag = strdup(module->context->name);
    module->data = vulnerability_detector;

    for (i = 0; i < OS_SUPP_SIZE; i++) {
        vulnerability_detector->updates[i] = NULL;
    }

    if (!nodes)
        return 0;

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
            int os_index;
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
            } else if (strcmp(feed, vu_dist_tag[DIS_REDHAT])) {
                merror("Invalid OS for tag '%s' at module '%s'.", XML_FEED, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }

            os_calloc(1, sizeof(update_node), upd);
            upd->allowed_OS_list = NULL;
            upd->allowed_ver_list = NULL;
            upd->interval = WM_VULNDETECTOR_DEFAULT_UPDATE_INTERVAL;
            upd->attempted = 0;
            upd->json_format = 0;
            upd->update_from_year = RED_HAT_REPO_DEFAULT_MIN_YEAR;
            

            if (os_index = set_oval_version(feed, version, vulnerability_detector->updates, upd), os_index == OS_INVALID) {
                return OS_INVALID;
            } else if (os_index == OS_SUPP_SIZE) {
                continue;
            }

            if (chld_node = OS_GetElementsbyNode(xml, nodes[i]), !chld_node) {
                merror(XML_INVELEM, nodes[i]->element);
                return OS_INVALID;
            }

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
                        OS_ClearNode(chld_node);
                        return OS_INVALID;
                    }
                } else if (!strcmp(chld_node[j]->element, XML_UPDATE_INTERVAL)) {
                    if (get_interval(chld_node[j]->content, &upd->interval)) {
                        merror("Invalid content for '%s' option at module '%s'", XML_UPDATE_INTERVAL, WM_VULNDETECTOR_CONTEXT.name);
                        OS_ClearNode(chld_node);
                        return OS_INVALID;
                    }
                } else if (!strcmp(chld_node[j]->element, XML_UPDATE_FROM_YEAR)) {
                    if (!is_valid_year(chld_node[j]->content, &upd->update_from_year)) {
                        merror("Invalid content for '%s' option at module '%s'", XML_UPDATE_FROM_YEAR, WM_VULNDETECTOR_CONTEXT.name);
                        OS_ClearNode(chld_node);
                        return OS_INVALID;
                    }
                } else if (!strcmp(chld_node[j]->element, XML_ALLOW)) {
                    int size;
                    char *found;
                    char *OS = chld_node[j]->content;

                    os_calloc(1, sizeof(char *), upd->allowed_OS_list);
                    os_calloc(1, sizeof(char *), upd->allowed_ver_list);

                    for (size = 0; (found = strchr(OS, ',')); size++) {
                        *(found++) = '\0';
                        os_realloc(upd->allowed_OS_list, (size + 2)*sizeof(char *), upd->allowed_OS_list);
                        os_realloc(upd->allowed_ver_list, (size + 2)*sizeof(char *), upd->allowed_ver_list);
                        if (format_os_version(OS, &upd->allowed_OS_list[size], &upd->allowed_ver_list[size])) {
                            merror("Invalid OS entered in %s: %s", WM_VULNDETECTOR_CONTEXT.name, OS);
                            OS_ClearNode(chld_node);
                            return OS_INVALID;
                        }
                        upd->allowed_OS_list[size + 1] = NULL;
                        OS = found;
                    }
                    os_realloc(upd->allowed_OS_list, (size + 2)*sizeof(char *), upd->allowed_OS_list);
                    if (format_os_version(OS, &upd->allowed_OS_list[size], &upd->allowed_ver_list[size])) {
                        merror("Invalid OS entered in %s: %s", WM_VULNDETECTOR_CONTEXT.name, OS);
                        OS_ClearNode(chld_node);
                        return OS_INVALID;
                    }
                    upd->allowed_OS_list[size + 1] = NULL;
                } else if (!strcmp(chld_node[j]->element, XML_URL)) {
                    os_strdup(chld_node[j]->content, upd->url);
                    if (chld_node[j]->attributes && !strcmp(*chld_node[j]->attributes, XML_PORT)) {
                        upd->port = strtol(*chld_node[j]->values, NULL, 10);
                    }
                } else if (!strcmp(chld_node[j]->element, XML_PATH)) {
                    os_strdup(chld_node[j]->content, upd->path);
                } else {
                    merror("Invalid option '%s' for tag '%s' at module '%s'.", chld_node[j]->element, XML_FEED , WM_VULNDETECTOR_CONTEXT.name);
                    OS_ClearNode(chld_node);
                    return OS_INVALID;
                }
            }

            OS_ClearNode(chld_node);
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
        } else if (!strcmp(nodes[i]->element, XML_UPDATE_UBUNTU_OVAL)) {
            int enabled = 0;
            long unsigned int interval = 0;
            int precise = 0, trusty = 0, xenial = 0;
            mwarn("'%s' option at module '%s' is deprecated. Use '%s' instead.", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name, XML_FEED);

            if (!strcmp(nodes[i]->content, "yes")) {
                enabled = 1;
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
                                        precise = 1;
                                    } else if (!strcmp(version, "14")) {
                                        trusty = 1;
                                    } else if (!strcmp(version, "16")) {
                                        xenial = 1;
                                    } else {
                                        merror("Invalid Ubuntu version '%s'.", version);
                                    }
                                    if(precise || trusty || xenial)
                                        vulnerability_detector->flags.u_flags.update_ubuntu = 1;
                                    version = &version[k] + 1;
                                    k = 0;
                                }
                                if (out)
                                    break;
                            }
                        } else if (!strcmp(nodes[i]->attributes[j], XML_INTERVAL)) {
                            if (get_interval(nodes[i]->values[j], &interval)) {
                                merror("Invalid interval at module '%s'", WM_VULNDETECTOR_CONTEXT.name);
                                return OS_INVALID;
                            }
                        } else {
                            merror("Invalid attribute '%s' for '%s'", nodes[i]->attributes[j], XML_UPDATE_UBUNTU_OVAL);
                        }
                    }
                }
            } else if (!strcmp(nodes[i]->content, "no")) {
                enabled = 0;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_RUN_ON_START, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }

            if (enabled) {
                int os_index;
                update_node *upd;

                if (precise) {
                    os_calloc(1, sizeof(update_node), upd);
                    if (os_index = set_oval_version("UBUNTU", "12", vulnerability_detector->updates, upd), os_index == OS_INVALID) {
                        return OS_INVALID;
                    } else if (os_index == OS_SUPP_SIZE) {
                        continue;
                    }
                    upd->interval = interval;
                    upd->attempted = 0;
                }
                if (trusty) {
                    os_calloc(1, sizeof(update_node), upd);
                    if (os_index = set_oval_version("UBUNTU", "14", vulnerability_detector->updates, upd), os_index == OS_INVALID) {
                        return OS_INVALID;
                    } else if (os_index == OS_SUPP_SIZE) {
                        continue;
                    }
                    upd->interval = interval;
                    upd->attempted = 0;
                }
                if (xenial) {
                    os_calloc(1, sizeof(update_node), upd);
                    if (os_index = set_oval_version("UBUNTU", "16", vulnerability_detector->updates, upd), os_index == OS_INVALID) {
                        return OS_INVALID;
                    } else if (os_index == OS_SUPP_SIZE) {
                        continue;
                    }
                    upd->interval = interval;
                    upd->attempted = 0;
                }
            }
        } else if (!strcmp(nodes[i]->element, XML_UPDATE_REDHAT_OVAL)) {
            int enabled = 0;
            long unsigned int interval = 0;
            int rhel5 = 0, rhel6 = 0, rhel7 = 0;
            mwarn("'%s' option at module '%s' is deprecated. Use '%s' instead.", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name, XML_FEED);

            if (!strcmp(nodes[i]->content, "yes")) {
                enabled = 1;
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
                                        rhel5 = 1;
                                    } else if (!strcmp(version, "6")) {
                                        rhel6 = 1;
                                    } else if (!strcmp(version, "7")) {
                                        rhel7 = 1;
                                    } else {
                                        merror("Invalid RedHat version '%s'.", version);
                                    }
                                    if(rhel5 || rhel6 || rhel7)
                                        vulnerability_detector->flags.u_flags.update_redhat = 1;
                                    version = &version[k] + 1;
                                    k = 0;
                                }
                                if (out)
                                    break;
                            }
                        } else if (!strcmp(nodes[i]->attributes[j], XML_INTERVAL)) {
                            if (get_interval(nodes[i]->values[j], &interval)) {
                                merror("Invalid interval at module '%s'", WM_VULNDETECTOR_CONTEXT.name);
                                return OS_INVALID;
                            }
                        } else {
                            merror("Invalid attribute '%s' for '%s'", nodes[i]->attributes[j], XML_UPDATE_REDHAT_OVAL);
                        }
                    }
                }
            } else if (!strcmp(nodes[i]->content, "no")) {
                enabled = 0;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_RUN_ON_START, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }

            if (enabled) {
                int os_index;
                update_node *upd;

                if (rhel5) {
                    os_calloc(1, sizeof(update_node), upd);
                    if (os_index = set_oval_version("REDHAT", "5", vulnerability_detector->updates, upd), os_index == OS_INVALID) {
                        return OS_INVALID;
                    } else if (os_index == OS_SUPP_SIZE) {
                        continue;
                    }
                    upd->interval = interval;
                    upd->attempted = 0;
                }
                if (rhel6) {
                    os_calloc(1, sizeof(update_node), upd);
                    if (os_index = set_oval_version("REDHAT", "6", vulnerability_detector->updates, upd), os_index == OS_INVALID) {
                        return OS_INVALID;
                    } else if (os_index == OS_SUPP_SIZE) {
                        continue;
                    }
                    upd->interval = interval;
                    upd->attempted = 0;
                }
                if (rhel7) {
                    os_calloc(1, sizeof(update_node), upd);
                    if (os_index = set_oval_version("REDHAT", "7", vulnerability_detector->updates, upd), os_index == OS_INVALID) {
                        return OS_INVALID;
                    } else if (os_index == OS_SUPP_SIZE) {
                        continue;
                    }
                    upd->interval = interval;
                    upd->attempted = 0;
                }
            }
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
