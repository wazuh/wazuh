/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "global-config.h"
#include "config.h"


int Read_Alerts(XML_NODE node, void *configp, __attribute__((unused)) void *mailp, char **output)
{
    int i = 0;
    char message[OS_FLSIZE];

    /* XML definitions */
    const char *xml_email_level = "email_alert_level";
    const char *xml_log_level = "log_alert_level";

#ifdef LIBGEOIP_ENABLED
    /* GeoIP */
    const char *xml_log_geoip = "use_geoip";
#endif

    _Config *Config;
    Config = (_Config *)configp;

    if (!Config) {
        if (output == NULL) {
            merror("Configuration handle is NULL.");
        } else {
            wm_strcat(output, "Configuration handle is NULL.", '\n');
        }
        return (OS_INVALID);
    }

    while (node[i]) {
        if (!node[i]->element) {
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return (OS_INVALID);
        } else if (!node[i]->content) {
            if (output == NULL) {
                merror(XML_VALUENULL, node[i]->element);
            } else {
                snprintf(message, OS_FLSIZE + 1,
                    "Invalid NULL content for element: %s.",
                    node[i]->element);
                wm_strcat(output, message, '\n');
            }
            return (OS_INVALID);
        }
        /* Mail notification */
        else if (strcmp(node[i]->element, xml_email_level) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                if (output == NULL){
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE + 1,
                        "Invalid value for element '%s': %s.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }

            Config->mailbylevel = (u_int8_t) atoi(node[i]->content);
        }
        /* Log alerts */
        else if (strcmp(node[i]->element, xml_log_level) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                if (output == NULL){
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE + 1,
                        "Invalid value for element '%s': %s.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
            Config->logbylevel  = (u_int8_t) atoi(node[i]->content);
        }
#ifdef LIBGEOIP_ENABLED
        /* Enable GeoIP */
        else if (strcmp(node[i]->element, xml_log_geoip) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                Config->loggeoip = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                Config->loggeoip = 0;
            } else if (output == NULL) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            } else {
                snprintf(message, OS_FLSIZE + 1,
                    "Invalid value for element '%s': %s.",
                    node[i]->element, node[i]->content);
                wm_strcat(output, message, '\n');
                return (OS_INVALID);
            }

        }
#endif
        else if (output == NULL) {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        } else {
            snprintf(message, OS_FLSIZE + 1,
                "Invalid element in the configuration: '%s'.",
                node[i]->element);
            wm_strcat(output, message, '\n');
            return (OS_INVALID);
        }
        i++;
    }
    return (0);
}

