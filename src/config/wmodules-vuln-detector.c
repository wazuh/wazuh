/*
 * Wazuh Module Configuration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * January, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLIENT
#ifndef WIN32
#include "wazuh_modules/wmodules.h"

typedef struct vu_os_feed {
    char *version;
    time_t interval;
    char *url;
    char *path;
    char *allow;
    int port;
    struct vu_os_feed *next;
} vu_os_feed;

typedef struct provider_options {
    char *multi_path;
    char *multi_url;
    int multi_url_start;
    int multi_url_end;
    char **multi_allowed_os_name;
    char **multi_allowed_os_ver;
    int port;
    time_t update_interval;
    int update_since;
} provider_options;

static int wm_vuldet_get_interval(char *source, time_t *interval);
static int wm_vuldet_is_valid_year(char *source, int *date, int max);
static int wm_vuldet_set_feed_version(char *feed, char *version, update_node **upd_list);
static int wm_vuldet_read_deprecated_config(const OS_XML *xml, xml_node *node, update_node **updates, long unsigned int *update);
static int wm_vuldet_read_deprecated_feed_tag(const OS_XML *xml, xml_node *node, update_node **updates, long unsigned int *update);
static int wm_vuldet_read_deprecated_multifeed_tag(xml_node *node, update_node **updates, long unsigned int *update);
static int wm_vuldet_read_provider(const OS_XML *xml, xml_node *node, update_node **updates, wm_vuldet_flags *flags);
static int wm_vuldet_provider_enable(xml_node **node);
static char *wm_vuldet_provider_name(xml_node *node);
static int wm_vuldet_provider_os_list(xml_node **node, vu_os_feed **feeds);
static void wm_vuldet_set_port_to_url(char **url, int port);
static int wm_vuldet_add_allow_os(update_node *update, char *os_tags, char old_config);
static int wm_vuldet_add_multi_allow_os(update_node *update, char **src_os, char **dst_os);
static int wm_vuldet_read_provider_content(xml_node **node, char *name, char multi_provider, provider_options *options);
static char wm_vuldet_provider_type(char *pr_name);
static void wm_vuldet_remove_os_feed(vu_os_feed *feed, char full_r);
static void wm_vuldet_remove_os_feed_list(vu_os_feed *feeds);
static void wm_vuldet_init_provider_options(provider_options *options);
static void wm_vuldet_clear_provider_options(provider_options options);

// Options
static const char *XML_DISABLED = "disabled";
static const char *XML_ENABLED = "enabled";
static const char *XML_INTERVAL = "interval";
static const char *XML_NAME = "name";
static const char *XML_OS = "os";
static const char *XML_UPDATE_INTERVAL = "update_interval";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_IGNORE_TIME = "ignore_time";
static const char *XML_URL = "url";
static const char *XML_PATH = "path";
static const char *XML_PORT = "port";
static const char *XML_ALLOW = "allow";
static const char *XML_UPDATE_FROM_YEAR = "update_from_year";
static const char *XML_PROVIDER = "provider";
static const char *XML_REPLACED_OS = "replaced_os";

static const char *XML_START = "start";
static const char *XML_END = "end";

// Deprecated
static const char *XML_FEED = "feed";
static const char *XML_UPDATE_UBUNTU_OVAL = "update_ubuntu_oval";
static const char *XML_UPDATE_REDHAT_OVAL = "update_redhat_oval";
static const char *XML_VERSION = "version";

int format_os_version(char *OS, char **os_name, char **os_ver) {
    char OS_cpy[OS_SIZE_1024] = {'\0'};
    char distr[OS_SIZE_128] = {'\0'};
    char sec_distr[OS_SIZE_128] = {'\0'};
    char thi_distr[OS_SIZE_128] = {'\0'};
    char inv_distr[OS_SIZE_128] = {'\0'};
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

int wm_vuldet_set_feed_version(char *feed, char *version, update_node **upd_list) {
    cve_db os_index;
    update_node *upd;
    int retval;

    os_calloc(1, sizeof(update_node), upd);
    upd->interval = WM_VULNDETECTOR_DEFAULT_UPDATE_INTERVAL;

    if ((strcasestr(feed, vu_feed_tag[FEED_CANONICAL]) || strcasestr(feed, vu_feed_tag[FEED_UBUNTU])) && version) {
        if (!strcmp(version, "12") || strcasestr(version, vu_feed_tag[FEED_PRECISE])) {
            os_index = CVE_PRECISE;
            os_strdup(vu_feed_tag[FEED_PRECISE], upd->version);
            upd->dist_tag_ref = FEED_PRECISE;
            upd->dist_ext = vu_feed_ext[FEED_PRECISE];
        } else if (!strcmp(version, "14") || strcasestr(version, vu_feed_tag[FEED_TRUSTY])) {
            os_index = CVE_TRUSTY;
            os_strdup(vu_feed_tag[FEED_TRUSTY], upd->version);
            upd->dist_tag_ref = FEED_TRUSTY;
            upd->dist_ext = vu_feed_ext[FEED_TRUSTY];
        } else if (!strcmp(version, "16") || strcasestr(version, vu_feed_tag[FEED_XENIAL])) {
            os_index = CVE_XENIAL;
            os_strdup(vu_feed_tag[FEED_XENIAL], upd->version);
            upd->dist_tag_ref = FEED_XENIAL;
            upd->dist_ext = vu_feed_ext[FEED_XENIAL];
        } else if (!strcmp(version, "18") || strcasestr(version, vu_feed_tag[FEED_BIONIC])) {
            os_index = CVE_BIONIC;
            os_strdup(vu_feed_tag[FEED_BIONIC], upd->version);
            upd->dist_tag_ref = FEED_BIONIC;
            upd->dist_ext = vu_feed_ext[FEED_BIONIC];
        } else {
            merror("Invalid Ubuntu version '%s'.", version);
            retval = OS_INVALID;
            goto end;
        }
        upd->dist_ref = FEED_UBUNTU;
    } else  if (strcasestr(feed, vu_feed_tag[FEED_DEBIAN]) && version) {
        if (!strcmp(version, "10") || strcasestr(version, vu_feed_tag[FEED_BUSTER])) {
            os_index = CVE_BUSTER;
            os_strdup(vu_feed_tag[FEED_BUSTER], upd->version);
            upd->dist_tag_ref = FEED_BUSTER;
            upd->dist_ext = vu_feed_ext[FEED_BUSTER];
        } else if (!strcmp(version, "9") || strcasestr(version, vu_feed_tag[FEED_STRETCH])) {
            os_index = CVE_STRETCH;
            os_strdup(vu_feed_tag[FEED_STRETCH], upd->version);
            upd->dist_tag_ref = FEED_STRETCH;
            upd->dist_ext = vu_feed_ext[FEED_STRETCH];
        } else if (!strcmp(version, "8") || strcasestr(version, vu_feed_tag[FEED_JESSIE])) {
            os_index = CVE_JESSIE;
            os_strdup(vu_feed_tag[FEED_JESSIE], upd->version);
            upd->dist_tag_ref = FEED_JESSIE;
            upd->dist_ext = vu_feed_ext[FEED_JESSIE];
        } else if (!strcmp(version, "7") || strcasestr(version, vu_feed_tag[FEED_WHEEZY])) {
            os_index = CVE_WHEEZY;
            os_strdup(vu_feed_tag[FEED_WHEEZY], upd->version);
            upd->dist_tag_ref = FEED_WHEEZY;
            upd->dist_ext = vu_feed_ext[FEED_WHEEZY];
        } else {
            merror("Invalid Debian version '%s'.", version);
            retval = OS_INVALID;
            goto end;
        }
        upd->dist_ref = FEED_DEBIAN;
    } else if (strcasestr(feed, vu_feed_tag[FEED_REDHAT])) {
        static char rh_dep_adv = 0;

        if (version && !rh_dep_adv) {
            mwarn("The specific definition of the Red Hat feeds is deprecated. Use only redhat instead.");
            rh_dep_adv = 1;
        }

        os_index = CVE_REDHAT;
        upd->dist_tag_ref = FEED_REDHAT;
        upd->dist_ext = vu_feed_ext[FEED_REDHAT];
        upd->update_from_year = RED_HAT_REPO_DEFAULT_MIN_YEAR;
        upd->dist_ref = FEED_REDHAT;
        upd->json_format = 1;
    } else if (strcasestr(feed, vu_feed_tag[FEED_NVD])) {
        os_index = CVE_NVD;
        upd->dist_tag_ref = FEED_NVD;
        upd->dist_ext = vu_feed_ext[FEED_NVD];
        upd->dist_ref = FEED_NVD;
        upd->update_from_year = NVD_REPO_DEFAULT_MIN_YEAR;
        upd->json_format = 1;
        upd->interval = WM_VULNDETECTOR_NVD_UPDATE_INTERVAL;
        // Set the Wazuh CPE dictionary
        os_calloc(1, sizeof(update_node), upd_list[CPE_WDIC]);
        upd_list[CPE_WDIC]->dist_tag_ref = FEED_CPEW;
        upd_list[CPE_WDIC]->interval = WM_VULNDETECTOR_ONLY_ONE_UPD;
        upd_list[CPE_WDIC]->dist_ext = vu_feed_ext[FEED_CPEW];
        upd_list[CPE_WDIC]->dist_ref = FEED_CPEW;
        upd_list[CPE_WDIC]->json_format = 1;
        // Set the MSU update node
        os_calloc(1, sizeof(update_node), upd_list[CVE_MSU]);
        upd_list[CVE_MSU]->dist_tag_ref = FEED_MSU;
        upd_list[CVE_MSU]->interval = WM_VULNDETECTOR_ONLY_ONE_UPD;
        upd_list[CVE_MSU]->dist_ext = vu_feed_ext[FEED_MSU];
        upd_list[CVE_MSU]->dist_ref = FEED_MSU;
        upd_list[CVE_MSU]->json_format = 1;
    } else {
        merror("Invalid feed '%s' at module '%s'.", feed, WM_VULNDETECTOR_CONTEXT.name);
        retval = OS_INVALID;
        goto end;
    }

    os_strdup(feed, upd->dist);

    if (upd_list[os_index]) {
        mwarn("Duplicate OVAL configuration for '%s%s%s'.", upd->dist,  upd->version ? " " : "", upd->version ? upd->version : "");
        retval = OS_SUPP_SIZE;
        goto end;
    }

    upd_list[os_index] = upd;

    retval = os_index;
end:
    if (retval == OS_SUPP_SIZE || retval == OS_INVALID) {
        wm_vuldet_free_update_node(upd);
        free(upd);
    }

    return retval;
}

int wm_vuldet_get_interval(char *source, time_t *interval) {
    char *endptr;
    *interval = strtoul(source, &endptr, 0);

    if ((!*interval && endptr == source) || *interval < 0) {
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

int wm_vuldet_is_valid_year(char *source, int *date, int max) {
    time_t n_date;
    struct tm tm_result = { .tm_sec = 0 };

    *date = strtol(source, NULL, 10);
    n_date = time (NULL);
    gmtime_r(&n_date, &tm_result);

    if ((!*date) || *date <  max || *date > (tm_result.tm_year + 1900)) {
        return 0;
    }

    return 1;
}

int Read_Vuln(const OS_XML *xml, xml_node **nodes, void *d1, char d2) {
    unsigned int i;
    wm_vuldet_t *vuldet;
    update_node **updates;
    long unsigned int run_update = 0;
    wmodule *cur_wmodule;

    if ((char) d2 == 1) {
        wmodule **wmodules = (wmodule**)d1;

        // Allocate memory
        if ((cur_wmodule = *wmodules)) {
            while (cur_wmodule->next)
                cur_wmodule = cur_wmodule->next;

            os_calloc(1, sizeof(wmodule), cur_wmodule->next);
            cur_wmodule = cur_wmodule->next;
        } else
            *wmodules = cur_wmodule = calloc(1, sizeof(wmodule));

        if (!cur_wmodule) {
            merror(MEM_ERROR, errno, strerror(errno));
            return (OS_INVALID);
        }
    } else {
        cur_wmodule = (wmodule *) d1;
    }

    os_calloc(1, sizeof(wm_vuldet_t), vuldet);
    vuldet->flags.run_on_start = 1;
    vuldet->flags.patch_scan = 1;
    vuldet->flags.permissive_patch_scan = 0;
    vuldet->flags.enabled = 1;
    vuldet->ignore_time = VU_DEF_IGNORE_TIME;
    vuldet->detection_interval = WM_VULNDETECTOR_DEFAULT_INTERVAL;
    vuldet->agents_software = NULL;
    cur_wmodule->context = &WM_VULNDETECTOR_CONTEXT;
    cur_wmodule->tag = strdup(cur_wmodule->context->name);
    cur_wmodule->data = vuldet;

    updates = vuldet->updates;

    if (!nodes)
        return 0;

    for (i = 0; nodes[i]; i++) {
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_ENABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                vuldet->flags.enabled = 1;
            else if (!strcmp(nodes[i]->content, "no")) {
                vuldet->flags.enabled = 0;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            mwarn("'%s' option at module '%s' is deprecated. Use '%s' instead.", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name, XML_ENABLED);
            if (!strcmp(nodes[i]->content, "yes"))
                vuldet->flags.enabled = 0;
            else if (!strcmp(nodes[i]->content, "no")) {
                vuldet->flags.enabled = 1;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            if (wm_vuldet_get_interval(nodes[i]->content, &vuldet->detection_interval)) {
                merror("Invalid interval at module '%s'.", WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_PROVIDER)) {
            if (wm_vuldet_read_provider(xml, nodes[i], updates, &vuldet->flags)) {
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_FEED) ||
                   !strcmp(nodes[i]->element, XML_UPDATE_UBUNTU_OVAL) ||
                   !strcmp(nodes[i]->element, XML_UPDATE_REDHAT_OVAL)) {
            if (wm_vuldet_read_deprecated_config(xml, nodes[i], updates, &run_update)) {
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_RUN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes")) {
                vuldet->flags.run_on_start = 1;
            } else if (!strcmp(nodes[i]->content, "no")) {
                vuldet->flags.run_on_start = 0;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_RUN_ON_START, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_IGNORE_TIME)) {
            if (wm_vuldet_get_interval(nodes[i]->content, &vuldet->ignore_time)) {
                merror("Invalid ignore_time at module '%s'.", WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name);
            return OS_INVALID;
        }
    }

    vuldet->flags.update = vuldet->flags.update | run_update;

    return 0;
}

int wm_vuldet_read_deprecated_config(const OS_XML *xml, xml_node *node, update_node **updates, long unsigned int *update) {
    mwarn("'%s' option at module '%s' is deprecated. Use '%s' instead.", node->element, WM_VULNDETECTOR_CONTEXT.name, XML_PROVIDER);

    if (!strcmp(node->element, XML_FEED)) {
        return wm_vuldet_read_deprecated_feed_tag(xml, node, updates, update);
    }  else {
        return wm_vuldet_read_deprecated_multifeed_tag(node, updates, update);
    }
}

static int wm_vuldet_read_deprecated_multifeed_tag(xml_node *node, update_node **updates, long unsigned int *update) {
    int j, k;
    int enabled = 0;
    time_t interval = 0;
    int os1 = 0, os2 = 0, os3 = 0;
    char is_ubuntu = !strcmp(node->element, XML_UPDATE_UBUNTU_OVAL);
    char *os_tag = is_ubuntu ? "UBUNTU" : "REDHAT";

    if (!strcmp(node->content, "yes")) {
        enabled = 1;
        if (node->attributes) {
            for (j = 0; node->attributes[j]; j++) {
                if (!strcmp(node->attributes[j], XML_VERSION)) {
                    char * version = node->values[j];
                    for (k = 0;; k++) {
                        int out = (version[k] == '\0');
                        if (version[k] == ',' || out) {
                            version[k] = '\0';
                            if ((is_ubuntu && !strcmp(version, "12")) || (!is_ubuntu && !strcmp(version, "5"))) {
                                os1 = 1;
                            } else if ((is_ubuntu && !strcmp(version, "14")) || (!is_ubuntu && !strcmp(version, "6"))) {
                                os2 = 1;
                            } else if ((is_ubuntu && !strcmp(version, "16")) || (!is_ubuntu && !strcmp(version, "7"))) {
                                os3 = 1;
                            } else {
                                merror("Invalid %s version '%s'.", os_tag, version);
                            }

                            version = &version[k] + 1;
                            k = 0;
                        }
                        if (out)
                            break;
                    }
                } else if (!strcmp(node->attributes[j], XML_INTERVAL)) {
                    if (wm_vuldet_get_interval(node->values[j], &interval)) {
                        merror("Invalid interval at module '%s'.", WM_VULNDETECTOR_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else {
                    merror("Invalid attribute '%s' for '%s'.", node->attributes[j], XML_UPDATE_UBUNTU_OVAL);
                    return OS_INVALID;
                }
            }
        }
    } else if (!strcmp(node->content, "no")) {
        enabled = 0;
    } else {
        merror("Invalid content '%s' for tag '%s' at module '%s'.", node->content, node->element, WM_VULNDETECTOR_CONTEXT.name);
        return OS_INVALID;
    }

    if(os1 || os2 || os3) {
        *update = 1;
    }

    if (enabled) {
        int os_index;
        int i;
        char *ver_tag;

        for (i = 0; i < 3; i++) {
            switch (i) {
                case 0:
                    if (!os1) continue;
                    ver_tag = is_ubuntu ? "12" : "5";
                break;
                case 1:
                    if (!os2) continue;
                    ver_tag = is_ubuntu ? "14" : "6";
                break;
                case 2:
                    if (!os3) continue;
                    ver_tag = is_ubuntu ? "16" : "7";
                break;
            }
            if (os_index = wm_vuldet_set_feed_version(os_tag, ver_tag, updates), os_index == OS_INVALID) {
                return OS_INVALID;
            } else if (os_index == OS_SUPP_SIZE) {
                return 0;
            }
            updates[os_index]->interval = interval;
            updates[os_index]->attempted = 0;
            updates[os_index]->old_config = 1;
        }
    }

    return 0;
}

static int wm_vuldet_read_deprecated_feed_tag(const OS_XML *xml, xml_node *node, update_node **updates, long unsigned int *update) {
    char *feed;
    char *version;
    int os_index;
    int j;
    XML_NODE chld_node = NULL;

    if (!node->attributes || strcmp(*node->attributes, XML_NAME)) {
        merror("Invalid content for tag '%s' at module '%s'.", XML_FEED, WM_VULNDETECTOR_CONTEXT.name);
        return OS_INVALID;
    }
    str_uppercase(node->values[0]);
    feed = node->values[0];
    if (version = strchr(feed, '-'), version) {
        *version = '\0';
        version++;
    } else if (strcmp(feed, vu_feed_tag[FEED_REDHAT])) {
        merror("Invalid feed '%s' at module '%s'.", feed, WM_VULNDETECTOR_CONTEXT.name);
        return OS_INVALID;
    }

    if (os_index = wm_vuldet_set_feed_version(feed, version, updates), os_index == OS_INVALID) {
        return OS_INVALID;
    } else if (os_index == OS_SUPP_SIZE) {
        return 0;
    }

    updates[os_index]->old_config = 1;

    if (chld_node = OS_GetElementsbyNode(xml, node), !chld_node) {
        merror(XML_INVELEM, node->element);
        return OS_INVALID;
    }

    for (j = 0; chld_node[j]; j++) {
        if (!strcmp(chld_node[j]->element, XML_DISABLED)) {
            if (!strcmp(chld_node[j]->content, "yes")) {
                wm_vuldet_release_update_node(updates, os_index);
                if (os_index == CVE_NVD) {
                    wm_vuldet_release_update_node(updates, CPE_WDIC);
                    wm_vuldet_release_update_node(updates, CVE_MSU);
                }
                break;
            } else if (!strcmp(chld_node[j]->content, "no")) {
                *update = 1;
            } else {
                merror("Invalid content for '%s' option at module '%s'.", XML_DISABLED, WM_VULNDETECTOR_CONTEXT.name);
                OS_ClearNode(chld_node);
                return OS_INVALID;
            }
        } else if (!strcmp(chld_node[j]->element, XML_UPDATE_INTERVAL)) {
            if (wm_vuldet_get_interval(chld_node[j]->content, &updates[os_index]->interval)) {
                merror("Invalid content for '%s' option at module '%s'.", XML_UPDATE_INTERVAL, WM_VULNDETECTOR_CONTEXT.name);
                OS_ClearNode(chld_node);
                return OS_INVALID;
            }
        } else if (!strcmp(chld_node[j]->element, XML_UPDATE_FROM_YEAR)) {
            if (!wm_vuldet_is_valid_year(chld_node[j]->content, &updates[os_index]->update_from_year, RED_HAT_REPO_MIN_YEAR)) {
                merror("Invalid content for '%s' option at module '%s'.", XML_UPDATE_FROM_YEAR, WM_VULNDETECTOR_CONTEXT.name);
                OS_ClearNode(chld_node);
                return OS_INVALID;
            }
        } else if (!strcmp(chld_node[j]->element, XML_ALLOW)) {
            if (wm_vuldet_add_allow_os(updates[os_index], chld_node[j]->content, 1)) {
                OS_ClearNode(chld_node);
                return OS_INVALID;
            }
        } else if (!strcmp(chld_node[j]->element, XML_URL)) {
            os_free(updates[os_index]->url);
            os_strdup(chld_node[j]->content, updates[os_index]->url);
            if (chld_node[j]->attributes && !strcmp(*chld_node[j]->attributes, XML_PORT)) {
                updates[os_index]->port = strtol(*chld_node[j]->values, NULL, 10);
            }
        } else if (!strcmp(chld_node[j]->element, XML_PATH)) {
            os_free(updates[os_index]->path);
            os_strdup(chld_node[j]->content, updates[os_index]->path);
        } else {
            merror("Invalid option '%s' for tag '%s' at module '%s'.", chld_node[j]->element, XML_FEED , WM_VULNDETECTOR_CONTEXT.name);
            OS_ClearNode(chld_node);
            return OS_INVALID;
        }
    }

    OS_ClearNode(chld_node);

    return 0;
}

int wm_vuldet_read_provider(const OS_XML *xml, xml_node *node, update_node **updates, wm_vuldet_flags *flags) {
    int os_index = OS_SUPP_SIZE;
    XML_NODE chld_node = NULL;
    char *pr_name = NULL;
    vu_os_feed *os_list = NULL;
    int result;
    char multi_provider;
    provider_options p_options = { .multi_path = 0 };
    int retval = OS_INVALID;

    wm_vuldet_init_provider_options(&p_options);

    if (pr_name = wm_vuldet_provider_name(node), !pr_name) {
        mwarn("Empty %s name.", XML_PROVIDER);
        return 0;
    }

    if (multi_provider = wm_vuldet_provider_type(pr_name), multi_provider < 0) {
        mwarn("Invalid provider name: %s.", pr_name);
        return 0;
    }

    if (chld_node = OS_GetElementsbyNode(xml, node), !chld_node) {
        merror(XML_INVELEM, node->element);
        goto end;
    }

    if (result = wm_vuldet_provider_enable(chld_node), !result) {
        retval = 0;
        goto end;
    } else if (result == OS_INVALID) {
        goto end;
    }

    if (!multi_provider) {
        if(wm_vuldet_provider_os_list(chld_node, &os_list)) {
            goto end;
        }
    }

    if (wm_vuldet_read_provider_content(chld_node, pr_name, multi_provider, &p_options)) {
        goto end;
    }

    if (!multi_provider) {
        while (os_list) {
            vu_os_feed *rem = os_list;

            if (os_index = wm_vuldet_set_feed_version(pr_name, os_list->version, updates), os_index == OS_INVALID || os_index == OS_SUPP_SIZE) {
                goto end;
            }

            if (os_list->interval) {
                updates[os_index]->interval = os_list->interval;
            } else if (p_options.update_interval) {
                updates[os_index]->interval = p_options.update_interval;
            }

            updates[os_index]->url = os_list->url;
            updates[os_index]->path = os_list->path;
            updates[os_index]->port = os_list->port;
            if (os_list->allow && wm_vuldet_add_allow_os(updates[os_index], os_list->allow, 0)) {
                return OS_INVALID;
            }

            mdebug1("Added %s (%s) feed. Interval: %lus | Path: '%s' | Url: '%s'.",
                        pr_name,
                        os_list->version,
                        updates[os_index]->interval,
                        updates[os_index]->path ? updates[os_index]->path : "none",
                        updates[os_index]->url ? updates[os_index]->url : "none");
            flags->update = 1;

            os_list = os_list->next;
            wm_vuldet_remove_os_feed(rem, 0);
        }
    } else {
        if (os_index = wm_vuldet_set_feed_version(pr_name, NULL, updates), os_index == OS_INVALID || os_index == OS_SUPP_SIZE) {
            goto end;
        }

        if (p_options.update_interval) {
            updates[os_index]->interval = p_options.update_interval;
        }

        if (p_options.update_since) {
            updates[os_index]->update_from_year = p_options.update_since;
        }

        updates[os_index]->multi_path = p_options.multi_path;
        updates[os_index]->multi_url = p_options.multi_url;
        updates[os_index]->multi_url_start = p_options.multi_url_start;
        updates[os_index]->multi_url_end = p_options.multi_url_end;
        updates[os_index]->port = p_options.port;

        if (p_options.multi_allowed_os_name) {
            if (wm_vuldet_add_multi_allow_os(updates[os_index], p_options.multi_allowed_os_name, p_options.multi_allowed_os_ver)) {
                goto end;
            }
        }

        p_options.multi_path = NULL;
        p_options.multi_url = NULL;

        if (os_index == CVE_NVD && !flags->patch_scan) {
            wm_vuldet_release_update_node(updates, CVE_MSU);
        }

        mdebug1("Added %s feed. Interval: %lus | Multi path: '%s' | Multi url: '%s' | Update since: %d.",
            pr_name,
            updates[os_index]->interval,
            updates[os_index]->multi_path ? updates[os_index]->multi_path : "none",
            updates[os_index]->multi_url ? updates[os_index]->multi_url : "none",
            updates[os_index]->update_from_year);
        flags->update = 1;
    }

    if (os_index != OS_SUPP_SIZE) {
        if (updates[os_index]->multi_path && updates[os_index]->multi_url) {
            os_free(updates[os_index]->multi_url);
        } else if (updates[os_index]->path && updates[os_index]->url) {
            os_free(updates[os_index]->url);
        }
    }

    retval = 0;
end:
    if (chld_node) {
        OS_ClearNode(chld_node);
    }

    wm_vuldet_clear_provider_options(p_options);
    if (retval) {
        wm_vuldet_remove_os_feed_list(os_list);
    }

    return retval;
}

int wm_vuldet_provider_enable(xml_node **node) {
    int i;

    for (i = 0; node[i]; i++) {
        if (!strcmp(node[i]->element, XML_ENABLED)) {
            if (!strcmp(node[i]->content, "yes")) {
                return 1;
            } else if (!strcmp(node[i]->content, "no")) {
                return 0;
            } else {
                merror("Invalid content '%s' for tag '%s' at module '%s'.", node[i]->content, XML_ENABLED, WM_VULNDETECTOR_CONTEXT.name);
                break;
            }
        } else if (!strcmp(node[i]->element, XML_DISABLED)) {
            merror("Invalid option in %s section for module %s: %s.", XML_PROVIDER, WM_VULNDETECTOR_CONTEXT.name, node[i]->element);
            return OS_INVALID;
        }
    }

    return 0;
}

char *wm_vuldet_provider_name(xml_node *node) {
    int i;

    for (i = 0; node->attributes && node->attributes[i]; i++) {
        if (!strcmp(node->attributes[i], XML_NAME)) {
            return node->values[i];
        }
    }

    return NULL;
}

int wm_vuldet_provider_os_list(xml_node **node, vu_os_feed **feeds) {
    int i;
    int j;
    vu_os_feed *feeds_it = *feeds;

    for (i = 0; node[i]; i++) {
        if (!strcmp(node[i]->element, XML_OS)) {
            if (!feeds_it) {
                os_calloc(1, sizeof(vu_os_feed), *feeds);
                feeds_it = *feeds;
            } else {
                os_calloc(1, sizeof(vu_os_feed), feeds_it->next);
                feeds_it = feeds_it->next;
            }

            os_strdup(node[i]->content, feeds_it->version);

            for (j = 0; node[i]->attributes && node[i]->attributes[j]; j++) {
                if (!strcmp(node[i]->attributes[j], XML_UPDATE_INTERVAL)) {
                    if (wm_vuldet_get_interval(node[i]->values[j], &feeds_it->interval)) {
                        merror("Invalid content for '%s' option at module '%s'.", node[i]->attributes[j], WM_VULNDETECTOR_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else if (!strcmp(node[i]->attributes[j], XML_PATH)) {
                    free(feeds_it->path);
                    os_strdup(node[i]->values[j], feeds_it->path);
                } else if (!strcmp(node[i]->attributes[j], XML_URL)) {
                    free(feeds_it->url);
                    os_strdup(node[i]->values[j], feeds_it->url);
                } else if (!strcmp(node[i]->attributes[j],  XML_PORT)) {
                    feeds_it->port = strtol(node[i]->values[j], NULL, 10);
                } else if (!strcmp(node[i]->attributes[j],  XML_ALLOW)) {
                    free(feeds_it->allow);
                    os_strdup(node[i]->values[j], feeds_it->allow);
                } else {
                    merror("Invalid attribute '%s' in '%s' option for %s.", node[i]->attributes[j], XML_OS, WM_VULNDETECTOR_CONTEXT.name);
                    return OS_INVALID;
                }
            }
            if (feeds_it->url) {
                wm_vuldet_set_port_to_url(&feeds_it->url, feeds_it->port);
            }

        }
    }

    return 0;
}

void wm_vuldet_release_update_node(update_node **updates, cve_db node) {
    wm_vuldet_free_update_node(updates[node]);
    os_free(updates[node]);
}

void wm_vuldet_free_update_node(update_node *update) {
    free(update->dist);
    free(update->version);
    free(update->path);
    free(update->multi_path);
    free(update->url);
    free(update->multi_url);
    if (wm_vuldet_is_single_provider(update->dist_ref)) {
        w_FreeArray(update->allowed_os_name);
        free(update->allowed_os_name);
        w_FreeArray(update->allowed_os_ver);
        free(update->allowed_os_ver);
    } else if (update->dist_ref == FEED_REDHAT) {
        int section, i;

        for (section = 0; section < 2; section++) {
            char ***multios_src = !section ? update->allowed_multios_src_name : update->allowed_multios_src_ver;
            char **multios_dst = !section ? update->allowed_multios_dst_name : update->allowed_multios_dst_ver;
            for (i = 0; multios_src && multios_src[i]; i++) {
                w_FreeArray(multios_src[i]);
                free(multios_src[i]);
            }
            w_FreeArray(multios_dst);
            free(multios_dst);
        }
    }
}

void wm_vuldet_set_port_to_url(char **url, int port) {
    char *https_tag = "https://";
    char *http_tag = "http://";
    char *url_it;
    char *new_url;
    char *file;
    char port_str[21];

    if (!port) {
        return;
    }

    snprintf(port_str, 20, ":%d", port);

    if (url_it = strstr(*url, https_tag), url_it) {
        url_it += strlen(https_tag);
    } else if (url_it = strstr(*url, http_tag), url_it) {
        url_it += strlen(http_tag);
    } else {
        url_it = *url;
    }

    if (file = strchr(url_it, '/'), file) {
        size_t size;

        *(file++) = '\0';
        size = strlen(*url) + strlen(file) + strlen(port_str) + 2;

        os_calloc(size + 1, sizeof(char), new_url);
        snprintf(new_url, size, "%s%s/%s", *url, port_str, file);

        free(*url);
        *url = new_url;
    } else {
        wm_strcat(url, port_str, 0);
    }
}

int wm_vuldet_add_allow_os(update_node *update, char *os_tags, char old_config) {
    char *found;
    size_t size;

    if (wm_vuldet_is_single_provider(update->dist_ref) || old_config) {
        os_calloc(1, sizeof(char *), update->allowed_os_name);
        os_calloc(1, sizeof(char *), update->allowed_os_ver);

        for (size = 0; (found = strchr(os_tags, ',')); size++) {
            *(found++) = '\0';
            os_realloc(update->allowed_os_name, (size + 2)*sizeof(char *), update->allowed_os_name);
            os_realloc(update->allowed_os_ver, (size + 2)*sizeof(char *), update->allowed_os_ver);
            if (format_os_version(os_tags, &update->allowed_os_name[size], &update->allowed_os_ver[size])) {
                merror("Invalid OS entered in %s: %s", WM_VULNDETECTOR_CONTEXT.name, os_tags);
                return OS_INVALID;
            }
            update->allowed_os_name[size + 1] = NULL;
            os_tags = found;
        }
        os_realloc(update->allowed_os_name, (size + 2)*sizeof(char *), update->allowed_os_name);
        if (format_os_version(os_tags, &update->allowed_os_name[size], &update->allowed_os_ver[size])) {
            merror("Invalid OS entered in %s: %s", WM_VULNDETECTOR_CONTEXT.name, os_tags);
            return OS_INVALID;
        }
        update->allowed_os_name[size + 1] = NULL;
    } else {
        merror("The 'allow' option can only be used with single-providers.");
        return OS_INVALID;
    }

    return 0;
}

int wm_vuldet_add_multi_allow_os(update_node *update, char **src_os, char **dst_os) {
    int i, j;
    char *version;

    for (i = 0; src_os[i]; i++) {
        os_realloc(update->allowed_multios_src_name, (i + 2) * sizeof(char **), update->allowed_multios_src_name);
        memset(&update->allowed_multios_src_name[i], '\0', 2 * sizeof(char **));
        os_realloc(update->allowed_multios_src_ver, (i + 2) * sizeof(char **), update->allowed_multios_src_ver);
        memset(&update->allowed_multios_src_ver[i], '\0', 2 * sizeof(char **));

        os_realloc(update->allowed_multios_dst_name, (i + 2) * sizeof(char *), update->allowed_multios_dst_name);
        memset(&update->allowed_multios_dst_name[i], '\0', 2 * sizeof(char *));
        os_realloc(update->allowed_multios_dst_ver, (i + 2) * sizeof(char *), update->allowed_multios_dst_ver);
        memset(&update->allowed_multios_dst_ver[i], '\0', 2 * sizeof(char *));

        // Set the allowed names
        wstr_split(src_os[i], ",", NULL, 1, &update->allowed_multios_src_name[i]);
        os_strdup(dst_os[i], update->allowed_multios_dst_name[i]);

        // Set the allowed versions
        for (j = 0; update->allowed_multios_src_name[i][j]; j++) {
            if (version = strchr(update->allowed_multios_src_name[i][j], '-'), !version) {
                merror("Invalid '%s' content. Use: 'OS-version'.", XML_ALLOW);
                return OS_INVALID;
            }
            *(version++) = '\0';
            os_realloc(update->allowed_multios_src_ver[i], (j + 2) * sizeof(char *), update->allowed_multios_src_ver[i]);
            os_strdup(version, update->allowed_multios_src_ver[i][j]);
        }
        if (version = strchr(update->allowed_multios_dst_name[i], '-'), !version) {
            merror("Invalid '%s' content. Use: 'OS-version'.", XML_REPLACED_OS);
            return OS_INVALID;
        }
        *(version++) = '\0';
        os_strdup(version, update->allowed_multios_dst_ver[i]);
    }

    return 0;
}

int wm_vuldet_read_provider_content(xml_node **node, char *name, char multi_provider, provider_options *options) {
    int i, j;
    int elements;

    memset(options, '\0', sizeof(provider_options));
    for (i = 0; node[i]; i++) {
        if (!strcmp(node[i]->element, XML_UPDATE_FROM_YEAR)) {
            if (multi_provider) {
                int min_year = !strcmp(name, vu_feed_tag[FEED_REDHAT]) ? RED_HAT_REPO_MIN_YEAR : NVD_REPO_MIN_YEAR;
                if (!wm_vuldet_is_valid_year(node[i]->content, &options->update_since, min_year)) {
                    merror("Invalid content for '%s' option at module '%s'.", XML_UPDATE_FROM_YEAR, WM_VULNDETECTOR_CONTEXT.name);
                    return OS_INVALID;
                }
            } else {
                mwarn("'%s' option can only be used in a multi-provider.", node[i]->element);
            }
        } else if (!strcmp(node[i]->element, XML_UPDATE_INTERVAL)) {
            if (wm_vuldet_get_interval(node[i]->content, &options->update_interval)) {
                merror("Invalid content for '%s' option at module '%s'.", XML_UPDATE_INTERVAL, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_PATH)) {
            if (multi_provider) {
                os_free(options->multi_path);
                os_strdup(node[i]->content, options->multi_path);
            } else {
                mwarn("'%s' option can only be used in a multi-provider.", node[i]->element);
            }
        } else if (!strcmp(node[i]->element, XML_URL)) {
            if (multi_provider) {
                os_free(options->multi_url);
                os_strdup(node[i]->content, options->multi_url);
                for (j = 0; node[i]->attributes && node[i]->attributes[j]; j++) {
                    if (!strcmp(node[i]->attributes[j], XML_START)) {
                        options->multi_url_start = atoi(node[i]->values[j]);
                    } else if (!strcmp(node[i]->attributes[j], XML_END)) {
                        options->multi_url_end = atoi(node[i]->values[j]);
                    }  else if (!strcmp(node[i]->attributes[j], XML_PORT)) {
                        options->port = strtol(node[i]->values[j], NULL, 10);
                        wm_vuldet_set_port_to_url(&options->multi_url, options->port);
                    } else {
                        mwarn("Invalid tag '%s' for '%s' option.", node[i]->attributes[j], node[i]->element);
                        return OS_INVALID;
                    }
                }
                if (strstr(options->multi_url, MULTI_URL_TAG) && (options->multi_url_start == -1 || options->multi_url_end == -1)) {
                    merror("Invalid use of the '%s' option.", node[i]->element);
                    return OS_INVALID;
                }
            } else {
                mwarn("'%s' option can only be used in a multi-provider.", node[i]->element);
            }
        } else if (!strcmp(node[i]->element, XML_ALLOW)) {
            if (multi_provider) {
                if (!node[i]->attributes || !*node[i]->attributes || strcmp(*node[i]->attributes, XML_REPLACED_OS) ||
                    !node[i]->values || !*node[i]->values || !**node[i]->values) {
                    merror("Invalid '%s' value.", XML_REPLACED_OS);
                    return OS_INVALID;
                }
                for (elements = 0; options->multi_allowed_os_name && options->multi_allowed_os_name[elements]; elements++);
                os_realloc(options->multi_allowed_os_name, (elements + 2) * sizeof(char *), options->multi_allowed_os_name);
                os_realloc(options->multi_allowed_os_ver, (elements + 2) * sizeof(char *), options->multi_allowed_os_ver);
                os_strdup(node[i]->content, options->multi_allowed_os_name[elements]);
                os_strdup(*node[i]->values, options->multi_allowed_os_ver[elements]);
                options->multi_allowed_os_name[elements + 1] = NULL;
                options->multi_allowed_os_ver[elements + 1] = NULL;
            } else {
                mwarn("'%s' option can only be used in a multi-provider.", node[i]->element);
            }
        } else if (!strcmp(node[i]->element, XML_OS)) {
            if (multi_provider) {
                mwarn("'%s' option can only be used in a single-provider.", node[i]->element);
            }
        } else if (strcmp(node[i]->element, XML_ENABLED)) {
            merror("Invalid option in %s section for module %s: %s.", XML_PROVIDER, WM_VULNDETECTOR_CONTEXT.name, node[i]->element);
            return OS_INVALID;
        }
    }

    return 0;
}

char wm_vuldet_provider_type(char *pr_name) {
    if (strcasestr(pr_name, vu_feed_tag[FEED_CANONICAL]) || strcasestr(pr_name, vu_feed_tag[FEED_DEBIAN])) {
        return 0;
    } else if (strcasestr(pr_name, vu_feed_tag[FEED_NVD]) || strcasestr(pr_name, vu_feed_tag[FEED_REDHAT])) {
        return 1;
    } else {
        return OS_INVALID;
    }
}

void wm_vuldet_remove_os_feed(vu_os_feed *feed, char full_r) {
    if (full_r) {
        free(feed->url);
        free(feed->path);
    }
    free(feed->version);
    free(feed->allow);
    free(feed);
}

void wm_vuldet_remove_os_feed_list(vu_os_feed *feeds) {
    while (feeds) {
        vu_os_feed *next = feeds->next;
        wm_vuldet_remove_os_feed(feeds, 1);
        feeds = next;
    }
}

void wm_vuldet_init_provider_options(provider_options *options) {
    options->multi_path = NULL;
    options->multi_url = NULL;
    options->multi_url_start = 0;
    options->multi_url_end = 0;
    options->multi_allowed_os_name = NULL;
    options->multi_allowed_os_ver = NULL;
    options->port = 0;
    options->update_interval = 0;
    options->update_since = 0;
}

void wm_vuldet_clear_provider_options(provider_options options) {
    os_free(options.multi_path);
    os_free(options.multi_url);
    w_FreeArray(options.multi_allowed_os_name);
    w_FreeArray(options.multi_allowed_os_ver);
    os_free(options.multi_allowed_os_name);
    os_free(options.multi_allowed_os_ver);
}

#endif
#endif
