/*
 * Wazuh Module Configuration
 * Copyright (C) 2015-2020, Wazuh Inc.
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
    char *debian_json_path;
    char *debian_json_url;
    char *allow;
    int port;
    struct vu_os_feed *next;
} vu_os_feed;

typedef struct provider_options {
    char *multi_path;
    char *multi_url;
    int multi_url_start;
    int multi_url_end;
    int port;
    time_t update_interval;
    int update_since;
    long timeout;
} provider_options;

static int wm_vuldet_get_interval(char *source, time_t *interval);
static int wm_vuldet_is_valid_year(char *source, int *date, int max);
static int wm_vuldet_set_feed_version(char *feed, char *version, update_node **upd_list);
static int wm_vuldet_read_provider(const OS_XML *xml, xml_node *node, update_node **updates, wm_vuldet_flags *flags);
static int wm_vuldet_provider_enable(xml_node **node);
static char *wm_vuldet_provider_name(xml_node *node);
static int wm_vuldet_provider_os_list(xml_node **node, vu_os_feed **feeds, char *pr_name);
static void wm_vuldet_set_port_to_url(char **url, int port);
static int wm_vuldet_add_allow_os(update_node *update, char *os_tags);
static int wm_vuldet_read_provider_content(xml_node **node, char *name, char multi_provider, provider_options *options);
static char wm_vuldet_provider_type(char *pr_name);
static void wm_vuldet_remove_os_feed(vu_os_feed *feed, char full_r);
static void wm_vuldet_remove_os_feed_list(vu_os_feed *feeds);
static void wm_vuldet_init_provider_options(provider_options *options);
static void wm_vuldet_clear_provider_options(provider_options options);
static void wm_vuldet_enable_rhel_json_feed(update_node **updates);

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
static const char *XML_TIMEOUT = "download_timeout";

static const char *XML_START = "start";
static const char *XML_END = "end";

// Deprecated
static const char *XML_FEED = "feed";
static const char *XML_UPDATE_UBUNTU_OVAL = "update_ubuntu_oval";
static const char *XML_UPDATE_REDHAT_OVAL = "update_redhat_oval";

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
        if (!strcmp(version, "12") || strcasestr(version, "PRECISE")) {
            mwarn("Ubuntu Precise is no longer supported.");
            retval = OS_DEPRECATED;
            goto end;
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
        } else if (!strcmp(version, "20") || strcasestr(version, vu_feed_tag[FEED_FOCAL])) {
            os_index = CVE_FOCAL;
            os_strdup(vu_feed_tag[FEED_FOCAL], upd->version);
            upd->dist_tag_ref = FEED_FOCAL;
            upd->dist_ext = vu_feed_ext[FEED_FOCAL];
        } else {
            merror("Invalid Ubuntu version '%s'", version);
            retval = OS_INVALID;
            goto end;
        }
        upd->dist_ref = FEED_UBUNTU;
    } else if (strcasestr(feed, vu_feed_tag[FEED_DEBIAN]) && version) {
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
        } else if (!strcmp(version, "8") || strcasestr(version, "JESSIE")) {
            mwarn("Debian Jessie is no longer supported.");
            retval = OS_DEPRECATED;
            goto end;
        } else if (!strcmp(version, "7") || strcasestr(version, "WHEEZY")) {
            mwarn("Debian Wheezy is no longer supported.");
            retval = OS_DEPRECATED;
            goto end;
        } else {
            merror("Invalid Debian version '%s'", version);
            retval = OS_INVALID;
            goto end;
        }
        upd->dist_ref = FEED_DEBIAN;

    } else if (strcasestr(feed, vu_feed_tag[FEED_JREDHAT])) {
        // JSON REDHAT
        os_index = CVE_JREDHAT;
        upd->dist_tag_ref = FEED_JREDHAT;
        upd->dist_ext = vu_feed_ext[FEED_JREDHAT];
        upd->dist_ref = FEED_JREDHAT;
        upd->update_from_year = RED_HAT_REPO_MIN_YEAR;
        upd->json_format = 1;

    } else if (strcasestr(feed, vu_feed_tag[FEED_REDHAT])) {
        if (!version) {
            retval = OS_INVALID;
            goto end;
        }
        // RHEL8
        if (!strcmp(version, "8")) {
            os_index = CVE_REDHAT8;
            upd->dist_tag_ref = FEED_RHEL8;
            os_strdup(version, upd->version);
            upd->dist_ext = vu_feed_ext[FEED_RHEL8];
        // RHEL7
        } else if (!strcmp(version, "7")) {
            os_index = CVE_REDHAT7;
            upd->dist_tag_ref = FEED_RHEL7;
            os_strdup(version, upd->version);
            upd->dist_ext = vu_feed_ext[FEED_RHEL7];
        // RHEL6
        } else if (!strcmp(version, "6")) {
            os_index = CVE_REDHAT6;
            upd->dist_tag_ref = FEED_RHEL6;
            os_strdup(version, upd->version);
            upd->dist_ext = vu_feed_ext[FEED_RHEL6];
        // RHEL5
        } else if (!strcmp(version, "5")) {
            os_index = CVE_REDHAT5;
            upd->dist_tag_ref = FEED_RHEL5;
            os_strdup(version, upd->version);
            upd->dist_ext = vu_feed_ext[FEED_RHEL5];
        } else {
            merror("Invalid RedHat version '%s'", version);
            retval = OS_INVALID;
            goto end;
        }
        upd->dist_ref = FEED_REDHAT;
    } else if (strcasestr(feed, vu_feed_tag[FEED_MSU])) {
        os_index = CVE_MSU;
        upd->dist_tag_ref = FEED_MSU;
        upd->dist_ext = vu_feed_ext[FEED_MSU];
        upd->dist_ref = FEED_MSU;
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
    } else {
        merror("Invalid feed '%s' at module '%s'", feed, WM_VULNDETECTOR_CONTEXT.name);
        retval = OS_INVALID;
        goto end;
    }

    os_strdup(feed, upd->dist);

    if (upd_list[os_index]) {
        mwarn("Duplicate OVAL configuration for '%s%s%s'", upd->dist, upd->version ? " " : "", upd->version ? upd->version : "");
        retval = OS_SUPP_SIZE;
        goto end;
    }

    upd_list[os_index] = upd;

    retval = os_index;
end:
    if (retval == OS_SUPP_SIZE || retval == OS_INVALID || retval == OS_DEPRECATED) {
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
                merror("Invalid content for tag '%s' at module '%s'", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            mwarn("'%s' option at module '%s' is deprecated. Use '%s' instead.", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name, XML_ENABLED);
            if (!strcmp(nodes[i]->content, "yes"))
                vuldet->flags.enabled = 0;
            else if (!strcmp(nodes[i]->content, "no")) {
                vuldet->flags.enabled = 1;
            } else {
                merror("Invalid content for tag '%s' at module '%s'", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            if (wm_vuldet_get_interval(nodes[i]->content, &vuldet->detection_interval)) {
                merror("Invalid interval at module '%s'", WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_PROVIDER)) {
            if (wm_vuldet_read_provider(xml, nodes[i], updates, &vuldet->flags)) {
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_FEED) ||
                   !strcmp(nodes[i]->element, XML_UPDATE_UBUNTU_OVAL) ||
                   !strcmp(nodes[i]->element, XML_UPDATE_REDHAT_OVAL)) {
            mwarn("'%s' option at module '%s' is deprecated. Use '%s' instead.", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name, XML_PROVIDER);
            continue;
        } else if (!strcmp(nodes[i]->element, XML_RUN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes")) {
                vuldet->flags.run_on_start = 1;
            } else if (!strcmp(nodes[i]->content, "no")) {
                vuldet->flags.run_on_start = 0;
            } else {
                merror("Invalid content for tag '%s' at module '%s'", XML_RUN_ON_START, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_IGNORE_TIME)) {
            if (wm_vuldet_get_interval(nodes[i]->content, &vuldet->ignore_time)) {
                merror("Invalid ignore_time at module '%s'", WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else {
            merror("No such tag '%s' at module '%s'", nodes[i]->element, WM_VULNDETECTOR_CONTEXT.name);
            return OS_INVALID;
        }
    }

    wm_vuldet_enable_rhel_json_feed(updates);

    vuldet->flags.update = vuldet->flags.update | run_update;

    return 0;
}

void wm_vuldet_enable_rhel_json_feed(update_node **updates) {
    int8_t rhel_enabled = 0;

    // Search for any enabled rhel feed
    for (int i = 0; i <= CVE_JREDHAT; i++) {
        if (updates[i] && updates[i]->dist_ref == FEED_REDHAT) {
            rhel_enabled = i;
            break;
        }
    }

    if (!rhel_enabled)
        return;

    if (updates[CVE_JREDHAT]) {
        // Offline JSON but online OVALs
        if (!updates[rhel_enabled]->path && !updates[rhel_enabled]->url)
            mwarn(VU_OFFLINE_CONFLICT, updates[CVE_JREDHAT]->dist);
    } else {
        // Online JSON but Offline OVALs
        if (updates[rhel_enabled]->path || updates[rhel_enabled]->url) {
            mwarn(VU_OFFLINE_CONFLICT, updates[rhel_enabled]->dist);
        }
        // As soon as a valid RedHat O.S. is detected, enable the RedHat JSON feed
        int retval;
        if (retval = wm_vuldet_set_feed_version("jredhat", NULL, updates), retval == OS_INVALID) {
            mwarn("Unable to load the RedHat JSON feed at module '%s'", WM_VULNDETECTOR_CONTEXT.name);
        }
    }
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
        mwarn("Invalid provider name: '%s'", pr_name);
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
        if(wm_vuldet_provider_os_list(chld_node, &os_list, pr_name)) {
            goto end;
        }
    }

    if (wm_vuldet_read_provider_content(chld_node, pr_name, multi_provider, &p_options)) {
        goto end;
    }

    /**
     *  single_provider = Ubuntu, Debian and RedHat.
     *  Those which use the <os> tag.
     **/
    if (!multi_provider) {
        while (os_list) {
            vu_os_feed *rem = os_list;

            if (os_index = wm_vuldet_set_feed_version(pr_name, os_list->version, updates), os_index == OS_INVALID || os_index == OS_SUPP_SIZE) {
                goto end;
            } else if (os_index == OS_DEPRECATED) {
                os_list = os_list->next;
                wm_vuldet_remove_os_feed(rem, 1);
                continue;
            }

            if (os_list->allow && wm_vuldet_add_allow_os(updates[os_index], os_list->allow)) {
                goto end;
            }

            if (os_list->interval) {
                updates[os_index]->interval = os_list->interval;
            } else if (p_options.update_interval) {
                updates[os_index]->interval = p_options.update_interval;
            }

            updates[os_index]->timeout = p_options.timeout;
            updates[os_index]->url = os_list->url;
            updates[os_index]->path = os_list->path;
            updates[os_index]->port = os_list->port;
            updates[os_index]->multi_path = os_list->debian_json_path;
            updates[os_index]->multi_url = os_list->debian_json_url;

            mdebug1("Added %s (%s) feed. Interval: %lus | Path: '%s' | Url: '%s' | Timeout: %lds",
                        pr_name,
                        os_list->version,
                        updates[os_index]->interval,
                        updates[os_index]->path ? updates[os_index]->path : "none",
                        updates[os_index]->url ? updates[os_index]->url : "none",
                        updates[os_index]->timeout);
            flags->update = 1;

            if (updates[os_index]->path || updates[os_index]->url) {
                // The feed is fetched from a custom location
                updates[os_index]->custom_location = 1;
            }

            if (updates[os_index]->path && updates[os_index]->url) {
                os_free(updates[os_index]->url);
            }

            os_list = os_list->next;
            wm_vuldet_remove_os_feed(rem, 0);
        }
    }

    /**
    *  multi_provider = NVD, RedHat JSON and MSU.
    *  Those which use <path> or <url> tags.
    **/
    if (multi_provider || (p_options.multi_path || p_options.multi_url)) {
        // Only the JSON feed of RedHat is multi_provider
        pr_name = (strcasestr(pr_name, "redhat")) ? "jredhat" : pr_name;

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
        updates[os_index]->url = p_options.multi_url; // Used by MSU.
        updates[os_index]->multi_url_start = p_options.multi_url_start;
        updates[os_index]->multi_url_end = p_options.multi_url_end;
        updates[os_index]->port = p_options.port;
        updates[os_index]->timeout = p_options.timeout;

        p_options.multi_path = NULL;
        p_options.multi_url = NULL;

        if (os_index == CVE_NVD && !flags->patch_scan) {
            wm_vuldet_release_update_node(updates, CVE_MSU);
        }

        mdebug1("Added %s feed. Interval: %lus | Multi path: '%s' | Multi url: '%s' | Update since: %d | Timeout: %lds",
            pr_name,
            updates[os_index]->interval,
            updates[os_index]->multi_path ? updates[os_index]->multi_path : "none",
            updates[os_index]->multi_url ? updates[os_index]->multi_url : "none",
            updates[os_index]->update_from_year,
            updates[os_index]->timeout);
        flags->update = 1;

        if (updates[os_index]->multi_path || updates[os_index]->multi_url) {
                // The feed is fetched from a custom location
                updates[os_index]->custom_location = 1;
            }

        if (updates[os_index]->multi_path && updates[os_index]->multi_url) {
            os_free(updates[os_index]->multi_url);
        }
    }

    retval = 0;
end:
    if (chld_node) {
        OS_ClearNode(chld_node);
    }

    wm_vuldet_clear_provider_options(p_options);

    if (os_list) {
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
                merror("Invalid content '%s' for tag '%s' at module '%s'", node[i]->content, XML_ENABLED, WM_VULNDETECTOR_CONTEXT.name);
                break;
            }
        } else if (!strcmp(node[i]->element, XML_DISABLED)) {
            merror("Invalid option in %s section for module '%s': '%s'", XML_PROVIDER, WM_VULNDETECTOR_CONTEXT.name, node[i]->element);
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

int wm_vuldet_provider_os_list(xml_node **node, vu_os_feed **feeds, char *pr_name) {
    int i;
    int j;
    vu_os_feed *feeds_it = *feeds;
    int8_t debian_provider = (strcasestr(pr_name, vu_feed_tag[FEED_DEBIAN])) ? 1 : 0;
    int8_t redhat_provider = (strcasestr(pr_name, vu_feed_tag[FEED_REDHAT])) ? 1 : 0;

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
                        merror("Invalid content for '%s' option at module '%s'", node[i]->attributes[j], WM_VULNDETECTOR_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else if (!strcmp(node[i]->attributes[j], XML_PATH)) {
                    free(feeds_it->path);
                    os_strdup(node[i]->values[j], feeds_it->path);
                } else if (!strcmp(node[i]->attributes[j], XML_URL)) {
                    free(feeds_it->url);
                    os_strdup(node[i]->values[j], feeds_it->url);
                } else if (!strcmp(node[i]->attributes[j], XML_PORT)) {
                    feeds_it->port = strtol(node[i]->values[j], NULL, 10);
                } else if (!strcmp(node[i]->attributes[j],  XML_ALLOW)) {
                    free(feeds_it->allow);
                    os_strdup(node[i]->values[j], feeds_it->allow);
                } else {
                    merror("Invalid attribute '%s' in '%s' option for '%s'", node[i]->attributes[j], XML_OS, WM_VULNDETECTOR_CONTEXT.name);
                    return OS_INVALID;
                }
            }
            if (feeds_it->url) {
                wm_vuldet_set_port_to_url(&feeds_it->url, feeds_it->port);
            }
        }
    }

    if (feeds_it == NULL) {
        // The OS tag is optional for redhat
        if (redhat_provider) {
            minfo(VU_NO_ENABLED_FEEDS, pr_name);
            char vsr [2] = {0};
            vu_os_feed *tmp_list = NULL;
            // New linked list for RedHat (5, 6, 7 and 8)
            for (int i = 5; i <= 8; i++) {
                os_calloc(1, sizeof(vu_os_feed), feeds_it);
                if (tmp_list) tmp_list->next = feeds_it;
                if (!*feeds)  *feeds = feeds_it; // Save tail
                sprintf(vsr, "%d", i);
                os_strdup(vsr, feeds_it->version);
                tmp_list = feeds_it;
            }
        } else {
            merror("'%s' tag required for '%s' provider.", XML_OS, pr_name);
            return OS_INVALID;
        }
    }

    if (debian_provider && feeds_it) {
        // A second iteration to check for a custom location for the JSON Security Tracker
        // If found, we assign the new location to all Debian nodes read above
        for (i = 0; node[i]; i++) {
            if (!strcmp(node[i]->element, XML_PATH)) {
                feeds_it = *feeds;
                while (feeds_it) {
                    os_strdup(node[i]->content, feeds_it->debian_json_path);
                    feeds_it = feeds_it->next;
                }
            } else if (!strcmp(node[i]->element, XML_URL)) {
                feeds_it = *feeds;
                while (feeds_it) {
                    os_strdup(node[i]->content, feeds_it->debian_json_url);
                    for (j = 0; node[i]->attributes && node[i]->attributes[j]; j++) {
                        if (!strcmp(node[i]->attributes[j], XML_PORT)) {
                            int port;
                            port = strtol(node[i]->values[j], NULL, 10);
                            wm_vuldet_set_port_to_url(&feeds_it->debian_json_url, port);
                        }
                    }
                    feeds_it = feeds_it->next;
                }
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

int wm_vuldet_add_allow_os(update_node *update, char *os_tags) {
    char *found;
    size_t size;

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
        mdebug1("'%s' successfully added to the monitored OS list.", os_tags);
        update->allowed_os_name[size + 1] = NULL;
        os_tags = found;
    }
    os_realloc(update->allowed_os_name, (size + 2)*sizeof(char *), update->allowed_os_name);
    if (format_os_version(os_tags, &update->allowed_os_name[size], &update->allowed_os_ver[size])) {
        merror("Invalid OS entered in %s: %s", WM_VULNDETECTOR_CONTEXT.name, os_tags);
        return OS_INVALID;
    }
    mdebug1("'%s' successfully added to the monitored OS list.", os_tags);
    update->allowed_os_name[size + 1] = NULL;

    return 0;
}

int wm_vuldet_read_provider_content(xml_node **node, char *name, char multi_provider, provider_options *options) {
    int i, j;
    int8_t rhel_enabled = (strcasestr(name, vu_feed_tag[FEED_REDHAT])) ? 1 : 0;
    int8_t msu_enabled = (strcasestr(name, vu_feed_tag[FEED_MSU])) ? 1 : 0;

    memset(options, '\0', sizeof(provider_options));

    // Set default download timeout
    options->timeout = WM_VULNDETECTOR_DEFAULT_TIMEOUT;

    for (i = 0; node[i]; i++) {
        if (!strcmp(node[i]->element, XML_UPDATE_FROM_YEAR)) {
            // Deprecated in RHEL
            if (rhel_enabled) {
                minfo("'%s' option at module '%s' is deprecated. Use '%s' instead.", XML_UPDATE_FROM_YEAR, WM_VULNDETECTOR_CONTEXT.name, XML_OS);
            // Even though MSU is a multi_provider, it does not use the update_from_year option.
            } else if (msu_enabled) {
                mwarn("'%s' option cannot be used for '%s' provider.", node[i]->element, name);
                continue;
            }

            if (multi_provider || rhel_enabled) {
                int min_year = rhel_enabled ? RED_HAT_REPO_MIN_YEAR : NVD_REPO_MIN_YEAR;
                if (!wm_vuldet_is_valid_year(node[i]->content, &options->update_since, min_year)) {
                    merror("Invalid content for '%s' option at module '%s'", XML_UPDATE_FROM_YEAR, WM_VULNDETECTOR_CONTEXT.name);
                    return OS_INVALID;
                }
            } else {
                mwarn("Invalid option '%s' for '%s' provider at '%s'", node[i]->element, name, WM_VULNDETECTOR_CONTEXT.name);
            }
        } else if (!strcmp(node[i]->element, XML_UPDATE_INTERVAL)) {
            if (wm_vuldet_get_interval(node[i]->content, &options->update_interval)) {
                merror("Invalid content for '%s' option at module '%s'", XML_UPDATE_INTERVAL, WM_VULNDETECTOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_TIMEOUT)) {
            char * end;
            options->timeout = strtol(node[i]->content, &end, 10);
            if (options->timeout < 0) {
                merror("Invalid content for '%s' option at module '%s'", XML_TIMEOUT, WM_VULNDETECTOR_CONTEXT.name);
                options->timeout = WM_VULNDETECTOR_DEFAULT_TIMEOUT;
            }
        } else if (!strcmp(node[i]->element, XML_PATH)) {
            if (multi_provider || rhel_enabled) {
                os_free(options->multi_path);
                os_strdup(node[i]->content, options->multi_path);
            }
        } else if (!strcmp(node[i]->element, XML_URL)) {
            if (multi_provider || rhel_enabled) {
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
            }
        } else if (!strcmp(node[i]->element, XML_ALLOW)) {
            if (rhel_enabled) {
                mwarn("Deprecated option '%s' for '%s' provider. Use it as attribute <os %s> instead.", node[i]->element, name, node[i]->element);
            } else {
                mwarn("Invalid option '%s' for '%s' provider at '%s'", node[i]->element, name, WM_VULNDETECTOR_CONTEXT.name);
            }
        } else if (!strcmp(node[i]->element, XML_OS)) {
            if (multi_provider) {
                mwarn("Invalid option '%s' for '%s' provider at '%s'", node[i]->element, name, WM_VULNDETECTOR_CONTEXT.name);
            }
        } else if (strcmp(node[i]->element, XML_ENABLED)) {
            merror("Invalid option in %s section for module '%s': '%s'", XML_PROVIDER, WM_VULNDETECTOR_CONTEXT.name, node[i]->element);
            return OS_INVALID;
        }
    }

    return 0;
}

char wm_vuldet_provider_type(char *pr_name) {
    if (strcasestr(pr_name, vu_feed_tag[FEED_CANONICAL]) ||
        strcasestr(pr_name, vu_feed_tag[FEED_DEBIAN]) ||
        strcasestr(pr_name, vu_feed_tag[FEED_REDHAT])) {
        return 0;
    } else if (strcasestr(pr_name, vu_feed_tag[FEED_NVD]) ||
        strcasestr(pr_name, vu_feed_tag[FEED_MSU])) {
        return 1;
    } else {
        return OS_INVALID;
    }
}

void wm_vuldet_remove_os_feed(vu_os_feed *feed, char full_r) {
    if (full_r) {
        os_free(feed->url);
        os_free(feed->path);
        os_free(feed->debian_json_path);
        os_free(feed->debian_json_url);
    }
    os_free(feed->version);
    os_free(feed->allow);
    os_free(feed);
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
    options->port = 0;
    options->update_interval = 0;
    options->update_since = 0;
    options->timeout = 0;
}

void wm_vuldet_clear_provider_options(provider_options options) {
    os_free(options.multi_path);
    os_free(options.multi_url);
}

#endif
#endif
