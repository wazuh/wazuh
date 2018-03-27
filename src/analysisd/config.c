/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
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

long int __crt_ftell; /* Global ftell pointer */
_Config Config;       /* Global Config structure */

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
    Config.jsonout_output = 0;
    Config.alerts_log = 1;
    Config.memorysize = 8192;
    Config.mailnotify = -1;
    Config.keeplogdate = 0;
    Config.syscheck_alert_new = 0;
    Config.syscheck_auto_ignore = 1;
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
    Config.queue_size = 131072;

    os_calloc(1, sizeof(wlabel_t), Config.labels);

    modules |= CGLOBAL;
    modules |= CRULES;
    modules |= CALERTS;
    modules |= CCLUSTER;

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

    if (Config.queue_size < 1) {
        merror("Queue size is invalid. Review configuration.");
        return OS_INVALID;
    }

    if (Config.queue_size > 262144) {
        mwarn("Queue size is very high. The application may run out of memory.");
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
        while (*wl) {
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
