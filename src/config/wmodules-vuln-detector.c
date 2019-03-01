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
static int set_feed_version(char *feed, char *version, update_node **upd_list);
static void free_update_node(update_node *node);

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
//static const char *XML_UPDATE_CPE_INTERVAL = "update_cpe_interval";
// Deprecated
static const char *XML_UPDATE_UBUNTU_OVAL = "update_ubuntu_oval";
static const char *XML_UPDATE_REDHAT_OVAL = "update_redhat_oval";
static const char *XML_VERSION = "version";

void free_update_node(update_node *node) {
    free(node->dist);
    free(node->version);
    free(node->url);
    free(node->path);
    if (node->allowed_OS_list) {
        w_FreeArray(node->allowed_OS_list);
    }
    if (node->allowed_ver_list) {
        w_FreeArray(node->allowed_ver_list);
    }
    free(node);
}

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

int set_feed_version(char *feed, char *version, update_node **upd_list) {
    cve_db os_index;
    update_node *upd;
    int retval;

    os_calloc(1, sizeof(update_node), upd);
    upd->interval = WM_VULNDETECTOR_DEFAULT_UPDATE_INTERVAL;

    if (!strcmp(feed, vu_feed_tag[FEED_UBUNTU])) {
        if (!strcmp(version, "12") || strcasestr(version, vu_feed_tag[FEED_PRECISE])) {
            os_index = CVE_PRECISE;
            os_strdup(vu_feed_tag[FEED_PRECISE], upd->version);
            upd->dist_tag = vu_feed_tag[FEED_PRECISE];
            upd->dist_ext = vu_feed_ext[FEED_PRECISE];
        } else if (!strcmp(version, "14") || strcasestr(version, vu_feed_tag[FEED_TRUSTY])) {
            os_index = CVE_TRUSTY;
            os_strdup(vu_feed_tag[FEED_TRUSTY], upd->version);
            upd->dist_tag = vu_feed_tag[FEED_TRUSTY];
            upd->dist_ext = vu_feed_ext[FEED_TRUSTY];
        } else if (!strcmp(version, "16") || strcasestr(version, vu_feed_tag[FEED_XENIAL])) {
            os_index = CVE_XENIAL;
            os_strdup(vu_feed_tag[FEED_XENIAL], upd->version);
            upd->dist_tag = vu_feed_tag[FEED_XENIAL];
            upd->dist_ext = vu_feed_ext[FEED_XENIAL];
        } else if (!strcmp(version, "18") || !strcmp(version, vu_feed_tag[FEED_BIONIC])) {
            os_index = CVE_BIONIC;
            os_strdup(vu_feed_tag[FEED_BIONIC], upd->version);
            upd->dist_tag = vu_feed_tag[FEED_BIONIC];
            upd->dist_ext = vu_feed_ext[FEED_BIONIC];
        } else {
            merror("Invalid Ubuntu version '%s'.", version);
            retval = OS_INVALID;
            goto end;
        }
        upd->dist_ref = FEED_UBUNTU;
    } else  if (!strcmp(feed, vu_feed_tag[FEED_DEBIAN])) {
        if (!strcmp(version, "9") || !strcmp(version, vu_feed_tag[FEED_STRETCH])) {
            os_index = CVE_STRETCH;
            os_strdup(vu_feed_tag[FEED_STRETCH], upd->version);
            upd->dist_tag = vu_feed_tag[FEED_STRETCH];
            upd->dist_ext = vu_feed_ext[FEED_STRETCH];
        } else if (!strcmp(version, "8") || !strcmp(version, vu_feed_tag[FEED_JESSIE])) {
            os_index = CVE_JESSIE;
            os_strdup(vu_feed_tag[FEED_JESSIE], upd->version);
            upd->dist_tag = vu_feed_tag[FEED_JESSIE];
            upd->dist_ext = vu_feed_ext[FEED_JESSIE];
        } else if (!strcmp(version, "7") || !strcmp(version, vu_feed_tag[FEED_WHEEZY])) {
            os_index = CVE_WHEEZY;
            os_strdup(vu_feed_tag[FEED_WHEEZY], upd->version);
            upd->dist_tag = vu_feed_tag[FEED_WHEEZY];
            upd->dist_ext = vu_feed_ext[FEED_WHEEZY];
        } else {
            merror("Invalid Debian version '%s'.", version);
            retval = OS_INVALID;
            goto end;
        }
        upd->dist_ref = FEED_DEBIAN;
    } else if (!strcmp(feed, vu_feed_tag[FEED_REDHAT])) {
        if (version) {
            mwarn("The specific definition of the Red Hat feeds (redhat-%s) is deprecated. Use only redhat instead.", version);
        }
        os_index = CVE_REDHAT;
        upd->dist_tag = vu_feed_tag[FEED_REDHAT];
        upd->dist_ext = vu_feed_ext[FEED_REDHAT];
        upd->update_from_year = RED_HAT_REPO_DEFAULT_MIN_YEAR;
        upd->dist_ref = FEED_REDHAT;
        upd->json_format = 1;
    } else if (!strcmp(feed, vu_feed_tag[FEED_NVD])) {
        os_index = CVE_NVD;
        upd->dist_tag = vu_feed_tag[FEED_NVD];
        upd->dist_ext = vu_feed_ext[FEED_NVD];
        upd->dist_ref = FEED_NVD;
        upd->json_format = 1;
        // Set the CPE feed (from NVD)
        /*
        os_calloc(1, sizeof(update_node), upd_list[CPE_NDIC]);
        upd_list[CPE_NDIC]->dist_tag = vu_feed_tag[FEED_CPED];
        upd_list[CPE_NDIC]->interval = WM_VULNDETECTOR_DEFAULT_CPE_UPDATE_INTERVAL;
        upd_list[CPE_NDIC]->dist_ext = vu_feed_ext[FEED_CPED];
        upd_list[CPE_NDIC]->dist_ref = FEED_CPED;
        */
        // Set the Wazuh CPE dictionary
        os_calloc(1, sizeof(update_node), upd_list[CPE_WDIC]);
        upd_list[CPE_WDIC]->dist_tag = vu_feed_tag[FEED_CPEW];
        upd_list[CPE_WDIC]->interval = WM_VULNDETECTOR_ONLY_ONE_UPD;
        upd_list[CPE_WDIC]->dist_ext = vu_feed_ext[FEED_CPEW];
        upd_list[CPE_WDIC]->dist_ref = FEED_CPEW;
        upd_list[CPE_WDIC]->json_format = 1;
    } else if (!strcmp(feed, vu_feed_tag[FEED_MSB])) {
        os_index = CVE_MSB;
        os_strdup(vu_feed_tag[FEED_MSB], upd->version);
        upd->dist_tag = vu_feed_tag[FEED_MSB];
        upd->dist_ext = vu_feed_ext[FEED_MSB];
        upd->dist_ref = FEED_MSB;
    } else {
        merror("Invalid feed '%s' at module '%s'.", feed, WM_VULNDETECTOR_CONTEXT.name);
        retval = OS_INVALID;
        goto end;
    }

    os_strdup(feed, upd->dist);

    if (upd_list[os_index]) {
        mwarn("Duplicate OVAL configuration for '%s %s'.", upd->dist, upd->version);
        free(upd->dist);
        free(upd->version);
        free(upd);
        retval = OS_SUPP_SIZE;
        goto end;
    }

    upd_list[os_index] = upd;

    upd->url = NULL;
    upd->path = NULL;
    upd->port = 0;

    retval = os_index;
end:
    if (retval == OS_SUPP_SIZE || retval == OS_INVALID) {
        free_update_node(upd);
    }

    return retval;
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
    wm_vuldet_t *vulnerability_detector;
    update_node **updates;

    XML_NODE chld_node = NULL;

    os_calloc(1, sizeof(wm_vuldet_t), vulnerability_detector);
    vulnerability_detector->flags.run_on_start = 1;
    vulnerability_detector->flags.enabled = 1;
    vulnerability_detector->ignore_time = VU_DEF_IGNORE_TIME;
    vulnerability_detector->detection_interval = WM_VULNDETECTOR_DEFAULT_INTERVAL;
    vulnerability_detector->agents_software = NULL;
    module->context = &WM_VULNDETECTOR_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = vulnerability_detector;

    updates = vulnerability_detector->updates;

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

            if (!nodes[i]->attributes || strcmp(*nodes[i]->attributes, XML_NAME)) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_FEED, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
            str_uppercase(nodes[i]->values[0]);
            feed = nodes[i]->values[0];
            if (version = strchr(feed, '-'), version) {
                *version = '\0';
                version++;
            } else if (strcmp(feed, vu_feed_tag[FEED_REDHAT]) &&
                       strcmp(feed, vu_feed_tag[FEED_NVD])    &&
                       strcmp(feed, vu_feed_tag[FEED_MSB])) {
                merror("Invalid feed '%s' at module '%s'.", feed, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }

            if (os_index = set_feed_version(feed, version, updates), os_index == OS_INVALID) {
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
                        free_update_node(updates[os_index]);
                        updates[os_index] = NULL;
                        if (os_index == CVE_NVD) {
                            //free_update_node(updates[CPE_NDIC]);
                            updates[CPE_NDIC] = NULL;
                        }
                        break;
                    } else if (!strcmp(chld_node[j]->content, "no")) {
                        if (!strcmp(updates[os_index]->dist, vu_feed_tag[FEED_REDHAT])) {
                            vulnerability_detector->flags.u_flags.update_redhat = 1;
                        } else if (!strcmp(updates[os_index]->dist, vu_feed_tag[FEED_UBUNTU])) {
                            vulnerability_detector->flags.u_flags.update_ubuntu = 1;
                        } else if (!strcmp(updates[os_index]->dist, vu_feed_tag[FEED_DEBIAN])) {
                            vulnerability_detector->flags.u_flags.update_debian = 1;
                        } else if (!strcmp(updates[os_index]->dist, vu_feed_tag[FEED_NVD])) {
                            vulnerability_detector->flags.u_flags.update_nvd = 1;
                        }
                    } else {
                        merror("Invalid content for '%s' option at module '%s'", XML_DISABLED, WM_VULNDETECTOR_CONTEXT.name);
                        OS_ClearNode(chld_node);
                        return OS_INVALID;
                    }
                } else if (!strcmp(chld_node[j]->element, XML_UPDATE_INTERVAL)) {
                    if (get_interval(chld_node[j]->content, &updates[os_index]->interval)) {
                        merror("Invalid content for '%s' option at module '%s'", XML_UPDATE_INTERVAL, WM_VULNDETECTOR_CONTEXT.name);
                        OS_ClearNode(chld_node);
                        return OS_INVALID;
                    }
                } /*else if (!strcmp(chld_node[j]->element, XML_UPDATE_CPE_INTERVAL)) {
                    if (updates[os_index]->dist_ref == FEED_NVD) {
                        if (get_interval(chld_node[j]->content, &updates[CPE_NDIC]->interval)) {
                            merror("Invalid content for '%s' option at module '%s'", XML_UPDATE_CPE_INTERVAL, WM_VULNDETECTOR_CONTEXT.name);
                            OS_ClearNode(chld_node);
                            return OS_INVALID;
                        }
                    } else {
                        mwarn("'%s' only can be used with %s feed.", XML_UPDATE_CPE_INTERVAL, updates[os_index]->dist_tag);
                    }
                }*/ else if (!strcmp(chld_node[j]->element, XML_UPDATE_FROM_YEAR)) {
                    if (!is_valid_year(chld_node[j]->content, &updates[os_index]->update_from_year)) {
                        merror("Invalid content for '%s' option at module '%s'", XML_UPDATE_FROM_YEAR, WM_VULNDETECTOR_CONTEXT.name);
                        OS_ClearNode(chld_node);
                        return OS_INVALID;
                    }
                } else if (!strcmp(chld_node[j]->element, XML_ALLOW)) {
                    int size;
                    char *found;
                    char *OS = chld_node[j]->content;

                    os_calloc(1, sizeof(char *), updates[os_index]->allowed_OS_list);
                    os_calloc(1, sizeof(char *), updates[os_index]->allowed_ver_list);

                    for (size = 0; (found = strchr(OS, ',')); size++) {
                        *(found++) = '\0';
                        os_realloc(updates[os_index]->allowed_OS_list, (size + 2)*sizeof(char *), updates[os_index]->allowed_OS_list);
                        os_realloc(updates[os_index]->allowed_ver_list, (size + 2)*sizeof(char *), updates[os_index]->allowed_ver_list);
                        if (format_os_version(OS, &updates[os_index]->allowed_OS_list[size], &updates[os_index]->allowed_ver_list[size])) {
                            merror("Invalid OS entered in %s: %s", WM_VULNDETECTOR_CONTEXT.name, OS);
                            OS_ClearNode(chld_node);
                            return OS_INVALID;
                        }
                        updates[os_index]->allowed_OS_list[size + 1] = NULL;
                        OS = found;
                    }
                    os_realloc(updates[os_index]->allowed_OS_list, (size + 2)*sizeof(char *), updates[os_index]->allowed_OS_list);
                    if (format_os_version(OS, &updates[os_index]->allowed_OS_list[size], &updates[os_index]->allowed_ver_list[size])) {
                        merror("Invalid OS entered in %s: %s", WM_VULNDETECTOR_CONTEXT.name, OS);
                        OS_ClearNode(chld_node);
                        return OS_INVALID;
                    }
                    updates[os_index]->allowed_OS_list[size + 1] = NULL;
                } else if (!strcmp(chld_node[j]->element, XML_URL)) {
                    os_strdup(chld_node[j]->content, updates[os_index]->url);
                    if (chld_node[j]->attributes && !strcmp(*chld_node[j]->attributes, XML_PORT)) {
                        updates[os_index]->port = strtol(*chld_node[j]->values, NULL, 10);
                    }
                } else if (!strcmp(chld_node[j]->element, XML_PATH)) {
                    os_strdup(chld_node[j]->content, updates[os_index]->path);
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

                if (precise) {
                    if (os_index = set_feed_version("UBUNTU", "12", updates), os_index == OS_INVALID) {
                        return OS_INVALID;
                    } else if (os_index == OS_SUPP_SIZE) {
                        continue;
                    }
                    updates[os_index]->interval = interval;
                    updates[os_index]->attempted = 0;
                }
                if (trusty) {
                    if (os_index = set_feed_version("UBUNTU", "14", updates), os_index == OS_INVALID) {
                        return OS_INVALID;
                    } else if (os_index == OS_SUPP_SIZE) {
                        continue;
                    }
                    updates[os_index]->interval = interval;
                    updates[os_index]->attempted = 0;
                }
                if (xenial) {
                    if (os_index = set_feed_version("UBUNTU", "16", updates), os_index == OS_INVALID) {
                        return OS_INVALID;
                    } else if (os_index == OS_SUPP_SIZE) {
                        continue;
                    }
                    updates[os_index]->interval = interval;
                    updates[os_index]->attempted = 0;
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

                if (rhel5) {
                    if (os_index = set_feed_version("REDHAT", "5", updates), os_index == OS_INVALID) {
                        return OS_INVALID;
                    } else if (os_index == OS_SUPP_SIZE) {
                        continue;
                    }
                    updates[os_index]->interval = interval;
                    updates[os_index]->attempted = 0;
                }
                if (rhel6) {
                    if (os_index = set_feed_version("REDHAT", "6", updates), os_index == OS_INVALID) {
                        return OS_INVALID;
                    } else if (os_index == OS_SUPP_SIZE) {
                        continue;
                    }
                    updates[os_index]->interval = interval;
                    updates[os_index]->attempted = 0;
                }
                if (rhel7) {
                    if (os_index = set_feed_version("REDHAT", "7", updates), os_index == OS_INVALID) {
                        return OS_INVALID;
                    } else if (os_index == OS_SUPP_SIZE) {
                        continue;
                    }
                    updates[os_index]->interval = interval;
                    updates[os_index]->attempted = 0;
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
        vulnerability_detector->flags.u_flags.update_nvd) {
        vulnerability_detector->flags.u_flags.update = 1;
    }

    return 0;
}

#endif
#endif
