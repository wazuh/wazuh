/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Functions to handle the configuration files */

#include "shared.h"
#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"
#include "analysisd.h"
#include "config.h"
#include "rules.h"
#include "stats.h"

long int __crt_ftell; /* Global ftell pointer */
_Config Config;       /* Global Config structure */
OSList *active_responses;
OSList *ar_commands;
OSDecoderNode *osdecodernode_forpname;
OSDecoderNode *osdecodernode_nopname;
RuleNode *rulenode;

/* Set analysisd internal options to default  */
static void init_conf()
{
    Config.default_timeframe = options.analysis.default_timeframe.def;
    Config.stats_maxdiff = options.analysis.stats_maxdiff.def;
    Config.stats_mindiff = options.analysis.stats_mindiff.def;
    Config.stats_percent_diff = options.analysis.stats_percent_diff.def;
    Config.fts_list_size = options.analysis.fts_list_size.def;
    Config.fts_min_size_for_str = (unsigned int) options.analysis.fts_min_size_for_str.def;
    Config.log_fw = (u_int8_t) options.analysis.log_fw.def;
    Config.decoder_order_size = (size_t) options.analysis.decoder_order_size.def;
#ifdef LIBGEOIP_ENABLED    
    Config.geoip_jsonout = options.analysis.geoip_jsonout.def;
#endif
    Config.label_cache_maxage = options.analysis.label_cache_maxage.def;
    Config.show_hidden_labels = options.analysis.show_hidden_labels.def;
    Config.rlimit_nofile = options.analysis.rlimit_nofile.def;
    Config.min_rotate_interval = options.analysis.min_rotate_interval.def;
    Config.event_threads = options.analysis.event_threads.def;
    Config.syscheck_threads = options.analysis.syscheck_threads.def;
    Config.syscollector_threads = options.analysis.syscollector_threads.def;
    Config.rootcheck_threads = options.analysis.rootcheck_threads.def;
    Config.sca_threads = options.analysis.sca_threads.def;
    Config.hostinfo_threads = options.analysis.hostinfo_threads.def;
    Config.winevt_threads = options.analysis.winevt_threads.def;
    Config.rule_matching_threads = options.analysis.rule_matching_threads.def;
    Config.decode_event_queue_size = options.analysis.decode_event_queue_size.def;
    Config.decode_syscheck_queue_size = options.analysis.decode_syscheck_queue_size.def;
    Config.decode_syscollector_queue_size = options.analysis.decode_syscollector_queue_size.def;
    Config.decode_rootcheck_queue_size = options.analysis.decode_rootcheck_queue_size.def;
    Config.decode_sca_queue_size = options.analysis.decode_sca_queue_size.def;
    Config.decode_hostinfo_queue_size = options.analysis.decode_hostinfo_queue_size.def;
    Config.decode_winevt_queue_size = options.analysis.decode_winevt_queue_size.def;
    Config.decode_output_queue_size = options.analysis.decode_output_queue_size.def;
    Config.archives_queue_size = options.analysis.archives_queue_size.def;
    Config.statistical_queue_size = options.analysis.statistical_queue_size.def;
    Config.alerts_queue_size = options.analysis.alerts_queue_size.def;
    Config.firewall_queue_size = options.analysis.firewall_queue_size.def;
    Config.fts_queue_size = options.analysis.fts_queue_size.def;
    Config.state_interval = options.analysis.state_interval.def;
    Config.log_level = options.analysis.log_level.def;
    Config.thread_stack_size = options.global.thread_stack_size.def; 

    return;
}

/* Set analysisd internal options */
static void read_internal()
{
    int aux;

    if ((aux = getDefine_Int("analysisd", "default_timeframe", options.analysis.default_timeframe.min, options.analysis.default_timeframe.max)) != INT_OPT_NDEF )
        Config.default_timeframe = aux;
    if ((aux = getDefine_Int("analysisd", "stats_maxdiff", options.analysis.stats_maxdiff.min, options.analysis.stats_maxdiff.max)) != INT_OPT_NDEF)
        Config.stats_maxdiff = aux;
    if ((aux = getDefine_Int("analysisd", "stats_mindiff", options.analysis.stats_mindiff.min, options.analysis.stats_mindiff.max)) != INT_OPT_NDEF)
        Config.stats_mindiff = aux;
    if ((aux = getDefine_Int("analysisd", "stats_percent_diff", options.analysis.stats_percent_diff.min, options.analysis.stats_percent_diff.max) ) != INT_OPT_NDEF)
        Config.stats_percent_diff = aux;
    if ((aux = getDefine_Int("analysisd", "fts_list_size", options.analysis.fts_list_size.min, options.analysis.fts_list_size.max)) != INT_OPT_NDEF)
        Config.fts_list_size = aux;
    if ((aux = getDefine_Int("analysisd", "fts_min_size_for_str", options.analysis.fts_min_size_for_str.min, options.analysis.fts_min_size_for_str.max)) != INT_OPT_NDEF)
        Config.fts_min_size_for_str = (unsigned int) aux;
    if ((aux = getDefine_Int("analysisd", "log_fw", options.analysis.log_fw.min, options.analysis.log_fw.max)) != INT_OPT_NDEF)
        Config.log_fw = (u_int8_t) aux;
    if ((aux = getDefine_Int("analysisd", "decoder_order_size", options.analysis.decoder_order_size.min, options.analysis.decoder_order_size.max)) != INT_OPT_NDEF)
        Config.decoder_order_size = (size_t) aux;
#ifdef LIBGEOIP_ENABLED
    if ((aux = getDefine_Int("analysisd", "geoip_jsonout", options.analysis.geoip_jsonout.min, options.analysis.geoip_jsonout.max)) != INT_OPT_NDEF)
        Config.geoip_jsonout = aux;
#endif
    if ((aux = getDefine_Int("analysisd", "label_cache_maxage", options.analysis.label_cache_maxage.min, options.analysis.label_cache_maxage.max)) != INT_OPT_NDEF)
        Config.label_cache_maxage = aux;
    if ((aux = getDefine_Int("analysisd", "show_hidden_labels", options.analysis.show_hidden_labels.min, options.analysis.show_hidden_labels.max)) != INT_OPT_NDEF)
        Config.show_hidden_labels = aux;
    if ((aux = getDefine_Int("analysisd", "rlimit_nofile", options.analysis.rlimit_nofile.min, options.analysis.rlimit_nofile.max)) != INT_OPT_NDEF)
        Config.rlimit_nofile = aux;
    if ((aux = getDefine_Int("analysisd", "min_rotate_interval", options.analysis.min_rotate_interval.min, options.analysis.min_rotate_interval.max)) != INT_OPT_NDEF)
        Config.min_rotate_interval = aux;
    if ((aux = getDefine_Int("analysisd", "event_threads", options.analysis.event_threads.min, options.analysis.event_threads.max)) != INT_OPT_NDEF)
        Config.event_threads = aux;
    if ((aux = getDefine_Int("analysisd", "syscheck_threads", options.analysis.syscheck_threads.min, options.analysis.syscheck_threads.max)) != INT_OPT_NDEF)
        Config.syscheck_threads = aux;
    if ((aux = getDefine_Int("analysisd", "syscollector_threads", options.analysis.syscollector_threads.min, options.analysis.syscollector_threads.max)) != INT_OPT_NDEF)
        Config.syscollector_threads = aux;
    if ((aux = getDefine_Int("analysisd", "rootcheck_threads", options.analysis.rootcheck_threads.min, options.analysis.rootcheck_threads.max)) != INT_OPT_NDEF)
        Config.rootcheck_threads = aux;
    if ((aux = getDefine_Int("analysisd", "sca_threads", options.analysis.sca_threads.min, options.analysis.sca_threads.max)) != INT_OPT_NDEF)
        Config.sca_threads = aux;
    if ((aux = getDefine_Int("analysisd", "hostinfo_threads", options.analysis.hostinfo_threads.min, options.analysis.hostinfo_threads.max)) != INT_OPT_NDEF)
        Config.hostinfo_threads = aux;
    if ((aux = getDefine_Int("analysisd", "winevt_threads", options.analysis.winevt_threads.min, options.analysis.winevt_threads.max)) != INT_OPT_NDEF)
        Config.winevt_threads = aux;
    if ((aux = getDefine_Int("analysisd", "rule_matching_threads", options.analysis.rule_matching_threads.min, options.analysis.rule_matching_threads.max)) != INT_OPT_NDEF)
        Config.rule_matching_threads = aux;
    if ((aux = getDefine_Int("analysisd", "decode_event_queue_size", options.analysis.decode_event_queue_size.min, options.analysis.decode_event_queue_size.max)) != INT_OPT_NDEF)
        Config.decode_event_queue_size = aux;
    if ((aux = getDefine_Int("analysisd", "decode_syscheck_queue_size", options.analysis.decode_syscheck_queue_size.min, options.analysis.decode_syscheck_queue_size.max)) != INT_OPT_NDEF)
        Config.decode_syscheck_queue_size = aux;
    if ((aux = getDefine_Int("analysisd", "decode_syscollector_queue_size", options.analysis.decode_syscollector_queue_size.min, options.analysis.decode_syscollector_queue_size.max)) != INT_OPT_NDEF)
        Config.decode_syscollector_queue_size = aux;
    if ((aux = getDefine_Int("analysisd", "decode_rootcheck_queue_size", options.analysis.decode_rootcheck_queue_size.min, options.analysis.decode_rootcheck_queue_size.max)) != INT_OPT_NDEF)
        Config.decode_rootcheck_queue_size = aux;
    if ((aux = getDefine_Int("analysisd", "decode_sca_queue_size", options.analysis.decode_sca_queue_size.min, options.analysis.decode_sca_queue_size.max)) != INT_OPT_NDEF)
        Config.decode_sca_queue_size = aux;
    if ((aux = getDefine_Int("analysisd", "decode_hostinfo_queue_size", options.analysis.decode_hostinfo_queue_size.min, options.analysis.decode_hostinfo_queue_size.max)) != INT_OPT_NDEF)
        Config.decode_hostinfo_queue_size = aux;
    if ((aux = getDefine_Int("analysisd", "decode_winevt_queue_size", options.analysis.decode_winevt_queue_size.min, options.analysis.decode_winevt_queue_size.max)) != INT_OPT_NDEF)
        Config.decode_winevt_queue_size = aux;
    if ((aux = getDefine_Int("analysisd", "decode_output_queue_size", options.analysis.decode_output_queue_size.min, options.analysis.decode_output_queue_size.max)) != INT_OPT_NDEF)
        Config.decode_output_queue_size = aux;
    if ((aux = getDefine_Int("analysisd", "archives_queue_size", options.analysis.archives_queue_size.min, options.analysis.archives_queue_size.max)) != INT_OPT_NDEF)
        Config.archives_queue_size = aux;
    if ((aux = getDefine_Int("analysisd", "statistical_queue_size", options.analysis.statistical_queue_size.min, options.analysis.statistical_queue_size.max)) != INT_OPT_NDEF)
        Config.statistical_queue_size = aux;
    if ((aux = getDefine_Int("analysisd", "alerts_queue_size", options.analysis.alerts_queue_size.min, options.analysis.alerts_queue_size.max)) != INT_OPT_NDEF)
        Config.alerts_queue_size = aux;
    if ((aux = getDefine_Int("analysisd", "firewall_queue_size", options.analysis.firewall_queue_size.min, options.analysis.firewall_queue_size.max)) != INT_OPT_NDEF)
        Config.firewall_queue_size = aux;
    if ((aux = getDefine_Int("analysisd", "fts_queue_size", options.analysis.fts_queue_size.min, options.analysis.fts_queue_size.max)) != INT_OPT_NDEF)
        Config.fts_queue_size = aux;
    if ((aux = getDefine_Int("analysisd", "state_interval", options.analysis.state_interval.min, options.analysis.state_interval.max)) != INT_OPT_NDEF)
        Config.state_interval = aux;
    if ((aux = getDefine_Int("analysisd", "debug", options.analysis.log_level.min, options.analysis.log_level.max)) != INT_OPT_NDEF)
        Config.log_level = aux;
    if ((aux = getDefine_Int("wazuh", "thread_stack_size", options.global.thread_stack_size.min, options.global.thread_stack_size.max)) != INT_OPT_NDEF)
        Config.thread_stack_size = aux;            

    return;
}

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

    /* Default actions -- only log above level 1 */
    Config.mailbylevel = 7;
    Config.logbylevel  = 1;

    Config.custom_alert_output = 0;
    Config.custom_alert_output_format = NULL;

    Config.includes = NULL;
    Config.lists = NULL;
    Config.decoders = NULL;
    Config.label_cache_maxage = 0;
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
    modules |= CROTANALYSD;

    init_conf();

    /* Read config */
    if (ReadConfig(modules, cfgfile, &Config, NULL) < 0 ||
        ReadConfig(CLABELS, cfgfile, &Config.labels, NULL) < 0) {
        return (OS_INVALID);
    }

    read_internal();

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

    if (Config.mailnotify) cJSON_AddStringToObject(global,"email_notification","yes"); else cJSON_AddStringToObject(global,"email_notification","no");
    if (Config.logall) cJSON_AddStringToObject(global,"logall","yes"); else cJSON_AddStringToObject(global,"logall","no");
    if (Config.logall_json) cJSON_AddStringToObject(global,"logall_json","yes"); else cJSON_AddStringToObject(global,"logall_json","no");
    cJSON_AddNumberToObject(global,"integrity_checking",Config.integrity);
    cJSON_AddNumberToObject(global,"rootkit_detection",Config.rootcheck);
    cJSON_AddNumberToObject(global,"host_information",Config.hostinfo);
    if (Config.prelude) cJSON_AddStringToObject(global,"prelude_output","yes"); else cJSON_AddStringToObject(global,"prelude_output","no");
    if (Config.prelude_profile) cJSON_AddStringToObject(global,"prelude_profile",Config.prelude_profile);
    if (Config.prelude) cJSON_AddNumberToObject(global,"prelude_log_level",Config.hostinfo);
    if (Config.geoipdb_file) cJSON_AddStringToObject(global,"geoipdb",Config.geoipdb_file);
    if (Config.zeromq_output) cJSON_AddStringToObject(global,"zeromq_output","yes"); else cJSON_AddStringToObject(global,"zeromq_output","no");
    if (Config.zeromq_output_uri) cJSON_AddStringToObject(global,"zeromq_uri",Config.zeromq_output_uri);
    if (Config.zeromq_output_server_cert) cJSON_AddStringToObject(global,"zeromq_server_cert",Config.zeromq_output_server_cert);
    if (Config.zeromq_output_client_cert) cJSON_AddStringToObject(global,"zeromq_client_cert",Config.zeromq_output_client_cert);
    if (Config.jsonout_output) cJSON_AddStringToObject(global,"jsonout_output","yes"); else cJSON_AddStringToObject(global,"jsonout_output","no");
    if (Config.alerts_log) cJSON_AddStringToObject(global,"alerts_log","yes"); else cJSON_AddStringToObject(global,"alerts_log","no");
    cJSON_AddNumberToObject(global,"stats",Config.stats);
    cJSON_AddNumberToObject(global,"memory_size",Config.memorysize);
    if (Config.white_list) {
        cJSON *ip_list = cJSON_CreateArray();
        for (i=0;Config.white_list[i] && Config.white_list[i]->ip;i++) {
            cJSON_AddItemToArray(ip_list,cJSON_CreateString(Config.white_list[i]->ip));
        }
        OSMatch **wl;
        wl = Config.hostname_white_list;
        while (wl && *wl) {
            char **tmp_pts = (*wl)->patterns;
            while (*tmp_pts) {
                cJSON_AddItemToArray(ip_list,cJSON_CreateString(*tmp_pts));
                tmp_pts++;
            }
            wl++;
        }
        cJSON_AddItemToObject(global,"white_list",ip_list);
    }
    if (Config.custom_alert_output) cJSON_AddStringToObject(global,"custom_alert_output",Config.custom_alert_output_format);
    cJSON_AddNumberToObject(global,"rotate_interval",Config.rotate_interval);
    cJSON_AddNumberToObject(global,"max_output_size",Config.max_output_size);

#ifdef LIBGEOIP_ENABLED
    if (Config.geoip_db_path) cJSON_AddStringToObject(global,"geoip_db_path",Config.geoip_db_path);
    if (Config.geoip6_db_path) cJSON_AddStringToObject(global,"geoip6_db_path",Config.geoip6_db_path);
#endif

    cJSON_AddItemToObject(root,"global",global);

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
        if (data->command) cJSON_AddStringToObject(ar,"command",data->command);
        if (data->agent_id) cJSON_AddStringToObject(ar,"agent_id",data->agent_id);
        if (data->rules_id) cJSON_AddStringToObject(ar,"rules_id",data->rules_id);
        if (data->rules_group) cJSON_AddStringToObject(ar,"rules_group",data->rules_group);
        cJSON_AddNumberToObject(ar,"timeout",data->timeout);
        cJSON_AddNumberToObject(ar,"level",data->level);
        if (data->location & AS_ONLY) cJSON_AddItemToObject(ar,"location",cJSON_CreateString("AS_ONLY"));
        else if (data->location & REMOTE_AGENT) cJSON_AddItemToObject(ar,"location",cJSON_CreateString("REMOTE_AGENT"));
        else if (data->location & SPECIFIC_AGENT) cJSON_AddItemToObject(ar,"location",cJSON_CreateString("SPECIFIC_AGENT"));
        else if (data->location & ALL_AGENTS) cJSON_AddItemToObject(ar,"location",cJSON_CreateString("ALL_AGENTS"));
        cJSON_AddItemToArray(ar_list,ar);
        node = node->next;
    }
    cJSON_AddItemToObject(root,"active-response",ar_list);

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
        if (data->name) cJSON_AddStringToObject(ar,"name",data->name);
        if (data->executable) cJSON_AddStringToObject(ar,"executable",data->executable);
        cJSON_AddNumberToObject(ar,"timeout_allowed",data->timeout_allowed);
        if (data->expect & USERNAME) cJSON_AddItemToObject(ar,"expect",cJSON_CreateString("username"));
        else if (data->expect & SRCIP) cJSON_AddItemToObject(ar,"expect",cJSON_CreateString("srcip"));
        else if (data->expect & FILENAME) cJSON_AddItemToObject(ar,"expect",cJSON_CreateString("filename"));
        cJSON_AddItemToArray(ar_list,ar);
        node = node->next;
    }
    cJSON_AddItemToObject(root,"command",ar_list);

    return root;
}


cJSON *getAlertsConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *alerts = cJSON_CreateObject();

    cJSON_AddNumberToObject(alerts,"email_alert_level",Config.mailbylevel);
    cJSON_AddNumberToObject(alerts,"log_alert_level",Config.logbylevel);
#ifdef LIBGEOIP_ENABLED
    if (Config.loggeoip) cJSON_AddStringToObject(alerts,"use_geoip","yes"); else cJSON_AddStringToObject(alerts,"use_geoip","no");
#endif

    cJSON_AddItemToObject(root,"alerts",alerts);

    return root;
}


cJSON *getAnalysisOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *analysisd = cJSON_CreateObject();

    cJSON_AddNumberToObject(analysisd, "default_timeframe", Config.default_timeframe);
    cJSON_AddNumberToObject(analysisd, "stats_maxdiff", Config.stats_maxdiff);
    cJSON_AddNumberToObject(analysisd, "stats_mindiff", Config.stats_mindiff);
    cJSON_AddNumberToObject(analysisd, "stats_percent_diff", Config.stats_percent_diff);
    cJSON_AddNumberToObject(analysisd, "fts_list_size", Config.fts_list_size);
    cJSON_AddNumberToObject(analysisd, "fts_min_size_for_str", Config.fts_min_size_for_str);
    cJSON_AddStringToObject(analysisd, "log_fw", Config.log_fw ? "yes" : "no");
    cJSON_AddNumberToObject(analysisd, "decoder_order_size", Config.decoder_order_size);
#ifdef LIBGEOIP_ENABLED
    cJSON_AddStringToObject(analysisd, "geoip_jsonout", Config.geoip_jsonout ? "yes" : "no");
#endif
    cJSON_AddNumberToObject(analysisd, "label_cache_maxage", Config.label_cache_maxage);
    cJSON_AddStringToObject(analysisd, "show_hidden_labels", Config.show_hidden_labels ? "yes" : "no");
    cJSON_AddNumberToObject(analysisd, "rlimit_nofile", Config.rlimit_nofile);
    cJSON_AddNumberToObject(analysisd, "min_rotate_interval", Config.min_rotate_interval);
    cJSON_AddNumberToObject(analysisd, "event_threads", Config.event_threads);
    cJSON_AddNumberToObject(analysisd, "syscheck_threads", Config.syscheck_threads);
    cJSON_AddNumberToObject(analysisd, "syscollector_threads", Config.syscollector_threads);
    cJSON_AddNumberToObject(analysisd, "rootcheck_threads", Config.rootcheck_threads);
    cJSON_AddNumberToObject(analysisd, "sca_threads", Config.sca_threads);
    cJSON_AddNumberToObject(analysisd, "hostinfo_threads", Config.hostinfo_threads);
    cJSON_AddNumberToObject(analysisd, "winevt_threads", Config.winevt_threads);
    cJSON_AddNumberToObject(analysisd, "rule_matching_threads", Config.rule_matching_threads);
    cJSON_AddNumberToObject(analysisd, "decode_event_queue_size", Config.decode_event_queue_size);
    cJSON_AddNumberToObject(analysisd, "decode_syscheck_queue_size", Config.decode_syscheck_queue_size);
    cJSON_AddNumberToObject(analysisd, "decode_syscollector_queue_size", Config.decode_syscollector_queue_size);
    cJSON_AddNumberToObject(analysisd, "decode_rootcheck_queue_size", Config.decode_rootcheck_queue_size);
    cJSON_AddNumberToObject(analysisd, "decode_sca_queue_size", Config.decode_sca_queue_size);
    cJSON_AddNumberToObject(analysisd, "decode_hostinfo_queue_size", Config.decode_hostinfo_queue_size);
    cJSON_AddNumberToObject(analysisd, "decode_winevt_queue_size", Config.decode_winevt_queue_size);
    cJSON_AddNumberToObject(analysisd, "decode_output_queue_size", Config.decode_output_queue_size);
    cJSON_AddNumberToObject(analysisd, "archives_queue_size", Config.archives_queue_size);
    cJSON_AddNumberToObject(analysisd, "statistical_queue_size", Config.statistical_queue_size);
    cJSON_AddNumberToObject(analysisd, "alerts_queue_size", Config.alerts_queue_size);
    cJSON_AddNumberToObject(analysisd, "firewall_queue_size", Config.firewall_queue_size);
    cJSON_AddNumberToObject(analysisd, "fts_queue_size", Config.fts_queue_size);
    cJSON_AddNumberToObject(analysisd, "state_interval", Config.state_interval);
    cJSON_AddNumberToObject(analysisd, "log_level", Config.log_level);
    cJSON_AddNumberToObject(analysisd, "thread_stack_size", Config.thread_stack_size);

    cJSON_AddItemToObject(root, "analysis", analysisd);

    return root;
}


cJSON *getDecodersConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *list = cJSON_CreateArray();

    if (osdecodernode_forpname) {
        _getDecodersListJSON(osdecodernode_forpname, list);
        _getDecodersListJSON(osdecodernode_nopname, list);
    }

    cJSON_AddItemToObject(root,"decoders",list);

    return root;
}


cJSON *getRulesConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *list = cJSON_CreateArray();

    if (rulenode) {
        _getRulesListJSON(rulenode, list);
    }

    cJSON_AddItemToObject(root,"rules",list);

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

cJSON *getAnalysisLoggingConfig(void) {
    char *json_format = "json_format";
    char *plain_format = "plain_format";
    char *compress_rotation = "compress_rotation";
    char *maxsize = "maxsize";
    char *minsize = "minsize";
    char *rotation_schedule = "schedule";
    char *saved_rotations = "saved_rotations";
    char *maxage = "maxage";
    cJSON *root;
    char aux[50];

    if (!Config.archives_enabled && !Config.alerts_enabled)  {
        root = getLoggingConfig();
    } else {
        cJSON *log_type;
        cJSON *logging;

        root = cJSON_CreateObject();
        logging = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "logging", logging);

        if (Config.archives_enabled) {
            log_type = cJSON_CreateObject();
            cJSON_AddStringToObject(log_type, plain_format, Config.archives_log_plain ? "yes" : "no");
            cJSON_AddStringToObject(log_type, json_format, Config.log_archives_json ? "yes" : "no");
            if (Config.alerts_rotation_enabled) {
                cJSON_AddStringToObject(log_type, compress_rotation, Config.archives_compress_rotation ? "yes" : "no");
                snprintf(aux, 50, "%d", Config.archives_rotate);
                cJSON_AddStringToObject(log_type, saved_rotations, Config.archives_rotate == -1 ? "unlimited" : aux);
                if (Config.archives_interval_units =='w') {
                    char *buffer;
                    buffer = int_to_day(Config.archives_interval);
                    cJSON_AddStringToObject(log_type, rotation_schedule, buffer);
                    os_free(buffer);
                } else {
                    snprintf(aux, 50, "%ld%c", Config.archives_interval, Config.archives_interval_units);
                    cJSON_AddStringToObject(log_type, rotation_schedule, Config.archives_interval ? aux : "no");
                }
                snprintf(aux, 50, "%ld%c", Config.archives_size_rotate, Config.archives_size_units);
                cJSON_AddStringToObject(log_type, maxsize, Config.archives_size_rotate ? aux : "no");
                snprintf(aux, 50, "%ld%c", Config.archives_min_size_rotate, Config.archives_min_size_units);
                cJSON_AddStringToObject(log_type, minsize, Config.archives_min_size_rotate ? aux : "no");
                cJSON_AddNumberToObject(log_type, maxage, Config.archives_maxage);
            }
            cJSON_AddItemToObject(logging, "archives", log_type);
        }

        if (Config.alerts_enabled) {
            log_type = cJSON_CreateObject();
            cJSON_AddStringToObject(log_type, plain_format, Config.alerts_log_plain ? "yes" : "no");
            cJSON_AddStringToObject(log_type, json_format, Config.alerts_log_json ? "yes" : "no");
            if (Config.alerts_rotation_enabled) {
                cJSON_AddStringToObject(log_type, compress_rotation, Config.alerts_compress_rotation ? "yes" : "no");
                snprintf(aux, 50, "%d", Config.alerts_rotate);
                cJSON_AddStringToObject(log_type, saved_rotations, Config.alerts_rotate == -1 ? "unlimited" : aux);
                if (Config.alerts_interval_units == 'w') {
                    char *buffer;
                    buffer = int_to_day(Config.alerts_interval);
                    cJSON_AddStringToObject(log_type, rotation_schedule, buffer);
                    os_free(buffer);
                } else {
                    snprintf(aux, 50, "%ld%c", Config.alerts_interval, Config.alerts_interval_units);
                    cJSON_AddStringToObject(log_type, rotation_schedule, Config.alerts_interval ? aux : "no");
                }
                snprintf(aux, 50, "%ld%c", Config.alerts_size_rotate, Config.alerts_size_units);
                cJSON_AddStringToObject(log_type, maxsize, Config.alerts_size_rotate ? aux : "no");
                snprintf(aux, 50, "%ld%c", Config.alerts_min_size_rotate, Config.alerts_min_size_units);
                cJSON_AddStringToObject(log_type, minsize, Config.alerts_min_size_rotate ? aux : "no");
                cJSON_AddNumberToObject(log_type, maxage, Config.alerts_maxage);
            }
            cJSON_AddItemToObject(logging, "alerts", log_type);
        }
    }

    return root;
}