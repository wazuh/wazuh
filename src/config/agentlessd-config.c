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
#include "agentlessd-config.h"
#include "config.h"


int Read_CAgentless(XML_NODE node, void *config, __attribute__((unused)) void *config2, char **output)
{
    unsigned int i = 0, j = 0, s = 0;
    char message[OS_FLSIZE];

    /* XML definitions */
    const char *xml_lessd_server = "host";
    const char *xml_lessd_port = "port";
    const char *xml_lessd_type = "type";
    const char *xml_lessd_frequency = "frequency";
    const char *xml_lessd_state = "state";
    const char *xml_lessd_command = "run_command";
    const char *xml_lessd_options = "arguments";

    agentlessd_config *lessd_config = (agentlessd_config *)config;

    /* Get any configured entry */
    if (lessd_config->entries) {
        while (lessd_config->entries[s]) {
            s++;
        }
    }

    /* Allocate the memory for the config */
    os_realloc(lessd_config->entries, (s + 2) * sizeof(agentlessd_entries *),
               lessd_config->entries);
    os_calloc(1, sizeof(agentlessd_entries), lessd_config->entries[s]);
    lessd_config->entries[s + 1] = NULL;

    /* Zero the elements */
    lessd_config->entries[s]->server = NULL;
    lessd_config->entries[s]->command = NULL;
    lessd_config->entries[s]->options = "";
    lessd_config->entries[s]->type = NULL;
    lessd_config->entries[s]->frequency = 86400;
    lessd_config->entries[s]->state = 0;
    lessd_config->entries[s]->current_state = 0;
    lessd_config->entries[s]->port = 0;
    lessd_config->entries[s]->error_flag = 0;

    /* Read the XML */
    while (node[i]) {
        if (!node[i]->element) {
            if (output == NULL){
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return (OS_INVALID);
        } else if (!node[i]->content) {
            if (output == NULL){
                merror(XML_VALUENULL, node[i]->element);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid NULL content for element: %s.",
                    node[i]->element);
                wm_strcat(output, message, '\n');
            }
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_lessd_frequency) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                if (output == NULL) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': '%s'.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }

            lessd_config->entries[s]->frequency = atoi(node[i]->content);
        } else if (strcmp(node[i]->element, xml_lessd_port) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                if (output == NULL) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': '%s'.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }

            lessd_config->entries[s]->port = atoi(node[i]->content);
        } else if (strcmp(node[i]->element, xml_lessd_server) == 0) {
            char s_content[1024 + 1];
            s_content[1024] = '\0';

            /* Get any configured entry */
            j = 0;
            if (lessd_config->entries[s]->server) {
                while (lessd_config->entries[s]->server[j]) {
                    j++;
                }
            }

            os_realloc(lessd_config->entries[s]->server, (j + 2) *
                       sizeof(char *),
                       lessd_config->entries[s]->server);
            if (strncmp(node[i]->content, "use_su ", 7) == 0) {
                snprintf(s_content, 1024, "s%s", node[i]->content + 7);
            } else if (strncmp(node[i]->content, "use_sudo ", 9) == 0) {
                snprintf(s_content, 1024, "o%s", node[i]->content + 9);
            } else {
                snprintf(s_content, 1024, " %s", node[i]->content);
            }

            os_strdup(s_content,
                      lessd_config->entries[s]->server[j]);
            lessd_config->entries[s]->server[j + 1] = NULL;
        } else if (strcmp(node[i]->element, xml_lessd_type) == 0) {
            char script_path[1024 + 1];

            script_path[1024] = '\0';
            snprintf(script_path, 1024, "%s/%s", AGENTLESSDIRPATH,
                     node[i]->content);

            if (w_ref_parent_folder(script_path)) {
                if (output == NULL){
                    merror("Invalid Agentless type '%s': it contains references to parent folder.", node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid Agentless type '%s': it contains references to parent folder.",
                        node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            if (File_DateofChange(script_path) <= 0) {
                if (output == NULL) {
                    merror("Unable to find '%s' at '%s'.",
                       node[i]->content, AGENTLESSDIRPATH);
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Unable to find '%s' at '%s'.",
                        node[i]->content, AGENTLESSDIRPATH);
                    wm_strcat(output, message, '\n');
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
            os_free(lessd_config->entries[s]->type);
            os_strdup(node[i]->content, lessd_config->entries[s]->type);
        } else if (strcmp(node[i]->element, xml_lessd_command) == 0) {
            os_strdup(node[i]->content, lessd_config->entries[s]->command);
        } else if (strcmp(node[i]->element, xml_lessd_options) == 0) {
            if (strcmp(node[i]->content, lessd_config->entries[s]->options) == 0) {
                os_strdup(node[i]->content, lessd_config->entries[s]->options);
            }
        } else if (strcmp(node[i]->element, xml_lessd_state) == 0) {
            if (strcmp(node[i]->content, "periodic") == 0) {
                lessd_config->entries[s]->state |= LESSD_STATE_PERIODIC;
            } else if (strcmp(node[i]->content, "stay_connected") == 0) {
                lessd_config->entries[s]->state |= LESSD_STATE_CONNECTED;
            } else if (strcmp(node[i]->content, "periodic_diff") == 0) {
                lessd_config->entries[s]->state |= LESSD_STATE_PERIODIC;
                lessd_config->entries[s]->state |= LESSD_STATE_DIFF;
            } else if (output == NULL){
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid value for element '%s': '%s'.",
                    node[i]->element, node[i]->content);
                wm_strcat(output, message, '\n');
                return (OS_INVALID);
            }
        } else if (output == NULL){
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        } else {
            snprintf(message, OS_FLSIZE,
                "Invalid element in the configuration: '%s'.",
                node[i]->element);
            wm_strcat(output, message, '\n');
            return (OS_INVALID);
        }
        i++;
    }

    /* We must have at least one entry set */
    if (!lessd_config->entries[s]->server ||
            !lessd_config->entries[s]->state ||
            !lessd_config->entries[s]->type) {
        if (output == NULL){
            merror(XML_INV_MISSOPTS);
        } else {
            wm_strcat(output, "Missing agentless options.", '\n');
        }
        return (OS_INVALID);
    }

    if ((lessd_config->entries[s]->state == LESSD_STATE_PERIODIC) &&
            !lessd_config->entries[s]->frequency) {
        if (output == NULL) {
            merror(XML_INV_MISSFREQ);
        } else {
            wm_strcat(output, "Frequency not set for the periodic option.", '\n');
        }
        return (OS_INVALID);
    }

    return (0);
}

int Test_Agentlessd(const char *path, char **output) {
    agentlessd_config *agtless_config;
    os_calloc(1, sizeof(agentlessd_config), agtless_config);

    if(ReadConfig(CAGENTLESS, path, agtless_config, NULL, output) < 0) {
        if (output == NULL){
            merror(XML_INV_AGENTLESS);
        } else {
            wm_strcat(output, "ERROR: Invalid configuration in Agentless", '\n');
        }
        free_AgentlessConfig(agtless_config);
        return OS_INVALID;
    }

    // Free Memory
    free_AgentlessConfig(agtless_config);
    return 0;
}

void free_AgentlessConfig(agentlessd_config *config) {
    if(config) {
        int i, j;
        if(config->entries) {
            for(i= 0; config->entries[i]; i++) {
                if(config->entries[i]->server) {
                    for (j= 0; config->entries[i]->server[j]; j++) {
                        free(config->entries[i]->server[j]);
                    }
                    free(config->entries[i]->server);
                }
                free(config->entries[i]->type);
                free(config->entries[i]->command);
                free(config->entries[i]);
            }
            free(config->entries);
        }
        free(config);
    }
}
