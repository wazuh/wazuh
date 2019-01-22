/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "csyslogd.h"
#include "config/global-config.h"
#include "config/config.h"

SyslogConfig **syslog_config;

/* Read configuration */
SyslogConfig **OS_ReadSyslogConf(__attribute__((unused)) int test_config, const char *cfgfile)
{
    int modules = 0;
    struct SyslogConfig_holder config;
    SyslogConfig **syslog_config = NULL;

    /* Modules for the configuration */
    modules |= CSYSLOGD;
    config.data = syslog_config;

    /* Read configuration */
    if (ReadConfig(modules, cfgfile, &config, NULL) < 0) {
        merror_exit(CONFIG_ERROR, cfgfile);
        return (NULL);
    }

    syslog_config = config.data;

    return (syslog_config);
}



cJSON *getCsyslogConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *csys = cJSON_CreateArray();
    unsigned int i, j;

    for(i=0;syslog_config[i];i++) {
        cJSON *cfg = cJSON_CreateObject();
        if (syslog_config[i]->server) cJSON_AddStringToObject(cfg,"server",syslog_config[i]->server);
        cJSON_AddNumberToObject(cfg,"port",syslog_config[i]->port);
        cJSON_AddNumberToObject(cfg,"level",syslog_config[i]->level);
        if (syslog_config[i]->group) {
            cJSON *group_list = cJSON_CreateArray();
            OSMatch *wl;
            j = 0;
            wl = syslog_config[i]->group;
            while (wl[j].patterns) {
                char **tmp_pts = wl[j].patterns;
                while (*tmp_pts) {
                    cJSON_AddItemToArray(group_list,cJSON_CreateString(*tmp_pts));
                    tmp_pts++;
                }
                j++;
            }
            cJSON_AddItemToObject(cfg,"group",group_list);
        }
        if (syslog_config[i]->rule_id) {
            cJSON *id_list = cJSON_CreateArray();
            j = 0;
            while (syslog_config[i]->rule_id[j]) {
                cJSON_AddItemToArray(id_list,cJSON_CreateNumber(syslog_config[i]->rule_id[j]));
                j++;
            }
            cJSON_AddItemToObject(cfg,"rule_id",id_list);
        }
        if (syslog_config[i]->location) {
            cJSON *loc_list = cJSON_CreateArray();
            OSMatch *wl;
            j = 0;
            wl = syslog_config[i]->location;
            while (wl[j].patterns) {
                char **tmp_pts = wl[j].patterns;
                while (*tmp_pts) {
                    cJSON_AddItemToArray(loc_list,cJSON_CreateString(*tmp_pts));
                    tmp_pts++;
                }
                j++;
            }
            cJSON_AddItemToObject(cfg,"location",loc_list);
        }
        if (syslog_config[i]->use_fqdn) cJSON_AddStringToObject(cfg,"use_fqdn","yes"); else cJSON_AddStringToObject(cfg,"use_fqdn","no");
        switch(syslog_config[i]->format) {
            case 0:
                cJSON_AddStringToObject(cfg,"format","default");
                break;
            case 1:
                cJSON_AddStringToObject(cfg,"format","cef");
                break;
            case 2:
                cJSON_AddStringToObject(cfg,"format","json");
                break;
            case 3:
                cJSON_AddStringToObject(cfg,"format","splunk");
                break;
        }

        cJSON_AddItemToArray(csys,cfg);
    }

    cJSON_AddItemToObject(root,"syslog_output",csys);

    return root;
}
