/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Functions to handle the configuration files */
#include <pthread.h>

#include "shared.h"
#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"
#include "analysisd.h"
#include "config.h"
#include "rules.h"
#include "stats.h"
#include "fts.h"

static long g_ftell_alerts = 0; ///< file‐offset pointer and its protecting lock, user for second part of alert id.
static pthread_rwlock_t g_ftell_alerts_lock = PTHREAD_RWLOCK_INITIALIZER; ///< Lock for the file‐offset pointer.

_Config Config;       /* Global Config structure */
rlim_t nofile;
int sys_debug_level;

#ifdef LIBGEOIP_ENABLED
GeoIP *geoipdb;
#endif


int GlobalConf(const char *cfgfile)
{
    int modules = 0;

    /* Default values */
    Config.logall = 0;
    Config.logall_json = 0;
    Config.stats = 4;
    Config.integrity = 8;
    Config.rootcheck = 8;
    Config.hostinfo = 8;
    Config.prelude = 0;
    Config.zeromq_output = 0;
    Config.zeromq_output_uri = NULL;
    Config.zeromq_output_server_cert = NULL;
    Config.zeromq_output_client_cert = NULL;
    Config.jsonout_output = 1;
    Config.alerts_log = 1;
    Config.memorysize = 8192;
    Config.mailnotify = -1;
    Config.keeplogdate = 0;
    Config.syscheck_alert_new = 1;
    Config.syscheck_auto_ignore = 0;
    Config.syscheck_ignore_frequency = 10;
    Config.syscheck_ignore_time = 3600;
    Config.ar = 0;

    Config.syscheck_ignore = NULL;
    Config.white_list = NULL;
    Config.hostname_white_list = NULL;

    Config.eps.maximum = EPS_LIMITS_MIN_EPS;
    Config.eps.timeframe = 0;

    /* Default actions -- only log above level 1 */
    Config.mailbylevel = 7;
    Config.logbylevel  = 1;

    Config.custom_alert_output = 0;
    Config.custom_alert_output_format = NULL;

    Config.includes = NULL;
    Config.lists = NULL;
    Config.decoders = NULL;
    Config.forwarders_list = NULL;
    Config.label_cache_maxage = 10;
    Config.show_hidden_labels = 0;

    Config.cluster_name = NULL;
    Config.node_name = NULL;
    Config.hide_cluster_info = 1;
    Config.rotate_interval = 0;
    Config.min_rotate_interval = 0;
    Config.max_output_size = 0;
    Config.queue_size = 0;

    os_calloc(1, sizeof(wlabel_t), Config.labels);

    modules |= CGLOBAL;
    modules |= CRULES;
    modules |= CALERTS;
    modules |= CCLUSTER;
    modules |= CANDSOCKET;

    /* Read config */
    if (ReadConfig(modules, cfgfile, &Config, NULL) < 0 ||
        ReadConfig(CLABELS, cfgfile, &Config.labels, NULL) < 0) {
        return (OS_INVALID);
    }

    Config.min_rotate_interval = getDefine_Int("analysisd", "min_rotate_interval", 10, 86400);

    /* Minimum memory size */
    if (Config.memorysize < 2048) {
        Config.memorysize = 2048;
    }

    if (Config.rotate_interval && (Config.rotate_interval < Config.min_rotate_interval || Config.rotate_interval > 86400)) {
        merror("Rotate interval setting must be between %d seconds and one day.", Config.min_rotate_interval);
        return (OS_INVALID);
    }

    if (Config.max_output_size && (Config.max_output_size < 1000000 || Config.max_output_size > 1099511627776)) {
        merror("Maximum output size must be between 1 MiB and 1 TiB.");
        return (OS_INVALID);
    }

    return (0);
}


cJSON *getGlobalConfig(void) {

    unsigned int i;
    cJSON *root = cJSON_CreateObject();
    cJSON *global = cJSON_CreateObject();

    if (Config.mailnotify) cJSON_AddStringToObject(global, "email_notification", "yes"); else cJSON_AddStringToObject(global, "email_notification", "no");
    if (Config.logall) cJSON_AddStringToObject(global, "logall", "yes"); else cJSON_AddStringToObject(global, "logall", "no");
    if (Config.logall_json) cJSON_AddStringToObject(global, "logall_json", "yes"); else cJSON_AddStringToObject(global, "logall_json", "no");
    cJSON_AddNumberToObject(global, "integrity_checking", Config.integrity);
    cJSON_AddNumberToObject(global, "rootkit_detection", Config.rootcheck);
    cJSON_AddNumberToObject(global, "host_information", Config.hostinfo);
    if (Config.prelude) cJSON_AddStringToObject(global, "prelude_output", "yes"); else cJSON_AddStringToObject(global, "prelude_output", "no");
    if (Config.prelude_profile) cJSON_AddStringToObject(global, "prelude_profile", Config.prelude_profile);
    if (Config.prelude) cJSON_AddNumberToObject(global, "prelude_log_level", Config.hostinfo);
    if (Config.geoipdb_file) cJSON_AddStringToObject(global, "geoipdb", Config.geoipdb_file);
    if (Config.zeromq_output) cJSON_AddStringToObject(global, "zeromq_output", "yes"); else cJSON_AddStringToObject(global, "zeromq_output", "no");
    if (Config.zeromq_output_uri) cJSON_AddStringToObject(global, "zeromq_uri", Config.zeromq_output_uri);
    if (Config.zeromq_output_server_cert) cJSON_AddStringToObject(global, "zeromq_server_cert", Config.zeromq_output_server_cert);
    if (Config.zeromq_output_client_cert) cJSON_AddStringToObject(global, "zeromq_client_cert", Config.zeromq_output_client_cert);
    if (Config.jsonout_output) cJSON_AddStringToObject(global, "jsonout_output", "yes"); else cJSON_AddStringToObject(global, "jsonout_output", "no");
    if (Config.alerts_log) cJSON_AddStringToObject(global, "alerts_log", "yes"); else cJSON_AddStringToObject(global, "alerts_log", "no");
    cJSON_AddNumberToObject(global, "stats", Config.stats);
    cJSON_AddNumberToObject(global, "memory_size", Config.memorysize);
    if (Config.white_list) {
        cJSON *ip_list = cJSON_CreateArray();
        for (i=0;Config.white_list[i] && Config.white_list[i]->ip;i++) {
            cJSON_AddItemToArray(ip_list, cJSON_CreateString(Config.white_list[i]->ip));
        }
        OSMatch **wl;
        wl = Config.hostname_white_list;
        while (wl && *wl) {
            char **tmp_pts = (*wl)->patterns;
            while (*tmp_pts) {
                cJSON_AddItemToArray(ip_list, cJSON_CreateString(*tmp_pts));
                tmp_pts++;
            }
            wl++;
        }
        cJSON_AddItemToObject(global, "white_list", ip_list);
    }
    if (Config.custom_alert_output) cJSON_AddStringToObject(global, "custom_alert_output", Config.custom_alert_output_format);
    cJSON_AddNumberToObject(global, "rotate_interval", Config.rotate_interval);
    cJSON_AddNumberToObject(global, "max_output_size", Config.max_output_size);
    cJSON *eps = cJSON_CreateObject();
    cJSON_AddNumberToObject(eps, "maximum", Config.eps.maximum);
    cJSON_AddNumberToObject(eps, "timeframe", Config.eps.timeframe);
    cJSON_AddItemToObject(global, "eps", eps);

#ifdef LIBGEOIP_ENABLED
    if (Config.geoip_db_path) cJSON_AddStringToObject(global, "geoip_db_path", Config.geoip_db_path);
    if (Config.geoip6_db_path) cJSON_AddStringToObject(global, "geoip6_db_path", Config.geoip6_db_path);
#endif

    cJSON_AddItemToObject(root, "global", global);

    return root;
}


cJSON *getARManagerConfig(void) {

    if (!active_responses) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    OSListNode *node = OSList_GetFirstNode(active_responses);
    cJSON *ar_list = cJSON_CreateArray();
    while (node && node->data) {
        active_response *data = node->data;
        cJSON *ar = cJSON_CreateObject();
        if (data->command) cJSON_AddStringToObject(ar, "command", data->command);
        if (data->agent_id) cJSON_AddStringToObject(ar, "agent_id", data->agent_id);
        if (data->rules_id) cJSON_AddStringToObject(ar, "rules_id", data->rules_id);
        if (data->rules_group) cJSON_AddStringToObject(ar, "rules_group", data->rules_group);
        cJSON_AddNumberToObject(ar, "timeout", data->timeout);
        cJSON_AddNumberToObject(ar, "level", data->level);
        if (data->location & AS_ONLY) cJSON_AddItemToObject(ar, "location", cJSON_CreateString("AS_ONLY"));
        else if (data->location & REMOTE_AGENT) cJSON_AddItemToObject(ar, "location", cJSON_CreateString("REMOTE_AGENT"));
        else if (data->location & SPECIFIC_AGENT) cJSON_AddItemToObject(ar, "location", cJSON_CreateString("SPECIFIC_AGENT"));
        else if (data->location & ALL_AGENTS) cJSON_AddItemToObject(ar, "location", cJSON_CreateString("ALL_AGENTS"));
        cJSON_AddItemToArray(ar_list, ar);
        node = node->next;
    }
    cJSON_AddItemToObject(root, "active-response", ar_list);

    return root;
}


cJSON *getARCommandsConfig(void) {

    if (!ar_commands) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    OSListNode *node = OSList_GetFirstNode(ar_commands);
    cJSON *ar_list = cJSON_CreateArray();
    while (node && node->data) {
        ar_command *data = node->data;
        cJSON *ar = cJSON_CreateObject();
        if (data->name) cJSON_AddStringToObject(ar, "name", data->name);
        if (data->executable) cJSON_AddStringToObject(ar, "executable", data->executable);
        cJSON_AddNumberToObject(ar, "timeout_allowed", data->timeout_allowed);
        cJSON_AddItemToArray(ar_list, ar);
        node = node->next;
    }
    cJSON_AddItemToObject(root, "command", ar_list);

    return root;
}


cJSON *getAlertsConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *alerts = cJSON_CreateObject();

    cJSON_AddNumberToObject(alerts, "email_alert_level", Config.mailbylevel);
    cJSON_AddNumberToObject(alerts, "log_alert_level", Config.logbylevel);
#ifdef LIBGEOIP_ENABLED
    if (Config.loggeoip) cJSON_AddStringToObject(alerts, "use_geoip", "yes"); else cJSON_AddStringToObject(alerts, "use_geoip", "no");
#endif

    cJSON_AddItemToObject(root, "alerts", alerts);

    return root;
}


cJSON *getAnalysisInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();
    cJSON *analysisd = cJSON_CreateObject();

    cJSON_AddNumberToObject(analysisd, "debug", sys_debug_level);
    cJSON_AddNumberToObject(analysisd, "default_timeframe", default_timeframe);
    cJSON_AddNumberToObject(analysisd, "stats_maxdiff", maxdiff);
    cJSON_AddNumberToObject(analysisd, "stats_mindiff", mindiff);
    cJSON_AddNumberToObject(analysisd, "stats_percent_diff", percent_diff);
    cJSON_AddNumberToObject(analysisd, "fts_list_size", fts_list_size);
    cJSON_AddNumberToObject(analysisd, "fts_min_size_for_str", fts_minsize_for_str);
    cJSON_AddNumberToObject(analysisd, "log_fw", Config.logfw);
    cJSON_AddNumberToObject(analysisd, "decoder_order_size", Config.decoder_order_size);
    cJSON_AddNumberToObject(analysisd, "label_cache_maxage", Config.label_cache_maxage);
    cJSON_AddNumberToObject(analysisd, "show_hidden_labels", Config.show_hidden_labels);
    cJSON_AddNumberToObject(analysisd, "rlimit_nofile", nofile);
    cJSON_AddNumberToObject(analysisd, "min_rotate_interval", Config.min_rotate_interval);
#ifdef LIBGEOIP_ENABLED
    cJSON_AddNumberToObject(analysisd, "geoip_jsonout", Config.geoip_jsonout);
#endif

    cJSON_AddItemToObject(internals, "analysisd", analysisd);
    cJSON_AddItemToObject(root, "internal", internals);

    return root;
}


cJSON *getDecodersConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *list = cJSON_CreateArray();

    if (os_analysisd_decoderlist_pn) {
        _getDecodersListJSON(os_analysisd_decoderlist_pn, list);
        _getDecodersListJSON(os_analysisd_decoderlist_nopn, list);
    }

    cJSON_AddItemToObject(root, "decoders", list);

    return root;
}


cJSON *getRulesConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *list = cJSON_CreateArray();

    if (os_analysisd_rulelist) {
        _getRulesListJSON(os_analysisd_rulelist, list);
    }

    cJSON_AddItemToObject(root, "rules", list);

    return root;
}


cJSON *getManagerLabelsConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *labels = cJSON_CreateArray();

    if (Config.labels) {
        unsigned int i;
        for (i=0;Config.labels[i].key; i++) {
            cJSON *label = cJSON_CreateObject();
            cJSON_AddStringToObject(label, "value", Config.labels[i].value);
            cJSON_AddStringToObject(label, "key", Config.labels[i].key);
            cJSON_AddStringToObject(label, "hidden", Config.labels[i].flags.hidden ? "yes" : "no");
            cJSON_AddItemToObject(labels, "", label);
        }
    }

    cJSON_AddItemToObject(root, "labels", labels);

    return root;
}


long get_global_alert_second_id(void) {
    long v;
    pthread_rwlock_rdlock(&g_ftell_alerts_lock);
    v = g_ftell_alerts;
    pthread_rwlock_unlock(&g_ftell_alerts_lock);
    return v;
}

void set_global_alert_second_id(long v) {
    pthread_rwlock_wrlock(&g_ftell_alerts_lock);
    g_ftell_alerts = v;
    pthread_rwlock_unlock(&g_ftell_alerts_lock);
}
