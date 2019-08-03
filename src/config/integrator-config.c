/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2014 Daniel B. Cid
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "integrator-config.h"
#include "config.h"

int Read_Integrator(XML_NODE node, void *config, __attribute__((unused)) void *config2)
{
    int i = 0,s = 0;

    /* XML definitions */
    char *xml_integrator_name = "name";
    char *xml_integrator_apikey = "api_key";
    char *xml_integrator_hookurl = "hook_url";
    char *xml_integrator_level = "level";
    char *xml_integrator_id = "rule_id";
    char *xml_integrator_group = "group";
    char *xml_integrator_location = "event_location";
    char *xml_integrator_max_log = "max_log";
    char *xml_integrator_alert_format = "alert_format";

    IntegratorConfig **integrator_config = *(IntegratorConfig ***)config;

    if(integrator_config)
    {
        while(integrator_config[s])
            s++;
    }

    /* Allocating the memory for the config. */
    os_realloc(integrator_config, (s + 2) * sizeof(IntegratorConfig *), integrator_config);
    os_calloc(1, sizeof(IntegratorConfig), integrator_config[s]);
    integrator_config[s + 1] = NULL;
    *(IntegratorConfig ***)config = integrator_config;

    /* Zeroing the elements. */
    integrator_config[s]->name = NULL;
    integrator_config[s]->apikey = NULL;
    integrator_config[s]->hookurl = NULL;
    integrator_config[s]->rule_id = NULL;
    integrator_config[s]->group = NULL;
    integrator_config[s]->location = NULL;
    integrator_config[s]->path = NULL;
    integrator_config[s]->alert_format = NULL;
    integrator_config[s]->level = 0;
    integrator_config[s]->enabled = 0;
    integrator_config[s]->max_log = 165;

    while(node[i])
    {
        if(!node[i]->element)
        {
            merror(XML_ELEMNULL);
            return(OS_INVALID);
        }
        else if(!node[i]->content)
        {
            merror(XML_VALUENULL, node[i]->element);
            return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, xml_integrator_level) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return(OS_INVALID);
            }

            integrator_config[s]->level = atoi(node[i]->content);
        }
        else if(strcmp(node[i]->element, xml_integrator_name) == 0)
        {
            os_strdup(node[i]->content, integrator_config[s]->name);
        }
        else if(strcmp(node[i]->element, xml_integrator_apikey) == 0)
        {
            os_strdup(node[i]->content, integrator_config[s]->apikey);
        }
        else if(strcmp(node[i]->element, xml_integrator_alert_format) == 0)
        {
            os_strdup(node[i]->content, integrator_config[s]->alert_format);
        }
        else if(strcmp(node[i]->element, xml_integrator_hookurl) == 0)
        {
            os_strdup(node[i]->content, integrator_config[s]->hookurl);
        }
        else if(strcmp(node[i]->element, xml_integrator_id) == 0)
        {
            int r_id = 0;
            char *str_pt = node[i]->content;

            while(*str_pt != '\0')
            {
                /* We allow spaces in between */
                if(*str_pt == ' ')
                {
                    str_pt++;
                    continue;
                }

                /* If is digit, we get the value
                 * and search for the next digit
                 * available
                 */
                else if(isdigit((int)*str_pt))
                {
                    int id_i = 0;

                    r_id = atoi(str_pt);
                    if(integrator_config[s]->rule_id)
                    {
                        while(integrator_config[s]->rule_id[id_i])
                            id_i++;
                    }

                    os_realloc(integrator_config[s]->rule_id,
                               (id_i +2) * sizeof(int),
                               integrator_config[s]->rule_id);

                    integrator_config[s]->rule_id[id_i + 1] = 0;
                    integrator_config[s]->rule_id[id_i] = r_id;

                    str_pt = strchr(str_pt, ',');
                    if(str_pt)
                    {
                        str_pt++;
                    }
                    else
                    {
                        break;
                    }
                }

                /* Checking for duplicate commas */
                else if(*str_pt == ',')
                {
                    str_pt++;
                    continue;
                }

                else
                {
                    break;
                }
            }

        }
        else if(strcmp(node[i]->element, xml_integrator_location) == 0)
        {
            os_calloc(1, sizeof(OSMatch),integrator_config[s]->location);
            if(!OSMatch_Compile(node[i]->content,
                                integrator_config[s]->location, 0))
            {
                merror(REGEX_COMPILE, node[i]->content,
                       integrator_config[s]->location->error);
                return(-1);
            }
        }
        else if(strcmp(node[i]->element, xml_integrator_group) == 0)
        {
            os_strdup(node[i]->content, integrator_config[s]->group);
        } else if (strcmp(node[i]->element, xml_integrator_max_log) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR,node[i]->element, node[i]->content);
                return(OS_INVALID);
            }

            integrator_config[s]->max_log = atoi(node[i]->content);

            if (integrator_config[s]->max_log < 165 || integrator_config[s]->max_log > 1024) {
                merror(XML_VALUEERR,node[i]->element, node[i]->content);
                return(OS_INVALID);
            }
        } else
        {
            merror(XML_INVELEM, node[i]->element);
            return(OS_INVALID);
        }
        i++;
    }

    /* We must have at least one entry set */
    if(!integrator_config[s]->name)
    {
        merror(XML_INV_INTEGRATOR);
        return(OS_INVALID);
    }

    return(0);
}
