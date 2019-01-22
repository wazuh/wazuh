/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2014 Daniel B. Cid
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 */

#include "integrator.h"
#include "config/global-config.h"
#include "config/config.h"

IntegratorConfig **integrator_config;

void **OS_ReadIntegratorConf(char *cfgfile, IntegratorConfig ***integrator_config)
{
    int modules = 0;

    /* Modules for the configuration */
    modules |= CINTEGRATORD;

    /* Reading configuration */
    if(ReadConfig(modules, cfgfile, integrator_config, NULL) < 0)
    {
        merror_exit(CONFIG_ERROR, cfgfile);
        return(NULL);
    }

    return (void**)*integrator_config;
}


cJSON *getIntegratorConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *integrator = cJSON_CreateArray();
    unsigned int i, j;

    for(i=0;integrator_config[i];i++) {
        cJSON *cfg = cJSON_CreateObject();
        if (integrator_config[i]->name) cJSON_AddStringToObject(cfg,"name",integrator_config[i]->name);
        if (integrator_config[i]->hookurl) cJSON_AddStringToObject(cfg,"hook_url",integrator_config[i]->hookurl);
        if (integrator_config[i]->apikey) cJSON_AddStringToObject(cfg,"api_key",integrator_config[i]->apikey);
        cJSON_AddNumberToObject(cfg,"level",integrator_config[i]->level);
        if (integrator_config[i]->rule_id) {
            cJSON *ids = cJSON_CreateArray();
            for(j=0;integrator_config[i]->rule_id[j];j++){
                cJSON_AddItemToArray(ids,cJSON_CreateNumber(integrator_config[i]->rule_id[j]));
            }
            cJSON_AddItemToObject(cfg,"rule_id",ids);
        }
        if (integrator_config[i]->group) cJSON_AddStringToObject(cfg,"group",integrator_config[i]->group);
        if (integrator_config[i]->alert_format) cJSON_AddStringToObject(cfg,"alert_format",integrator_config[i]->alert_format);
        if (integrator_config[i]->location) {
            cJSON *ids = cJSON_CreateArray();
            for(j=0;integrator_config[i]->location->patterns[j];j++){
                cJSON_AddItemToArray(ids,cJSON_CreateString(integrator_config[i]->location->patterns[j]));
            }
            cJSON_AddItemToObject(cfg,"location",ids);
        }
        cJSON_AddItemToArray(integrator,cfg);
    }

    cJSON_AddItemToObject(root,"integration",integrator);

    return root;
}
