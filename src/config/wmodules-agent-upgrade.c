/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wazuh_modules/wmodules.h"

#ifdef CLIENT
#include "wazuh_modules/agent_upgrade/agent/wm_agent_upgrade_agent.h"

static const char *XML_ENABLED = "enabled";
static const char *XML_WAIT_START = "notification_wait_start";
static const char *XML_WAIT_MAX = "notification_wait_max";
static const char *XML_WAIT_FACTOR = "notification_wait_factor";
static const char *XML_CA_VERIFICATION = "ca_verification";
static const char *XML_CA_STORE = "ca_store";
#else
static const char *XML_WPK_REPOSITORY = "wpk_repository";
static const char *XML_CHUNK_SIZE = "chunk_size";
static const char *XML_MAX_THREADS = "max_threads";
#endif

#ifdef CLIENT
static int wm_agent_upgrade_read_ca_verification(xml_node **nodes, unsigned int *verification_flag);
static int wm_agent_upgrade_read_ca_verification_old(unsigned int *verification_flag);
#endif

#ifdef CLIENT
int wm_agent_upgrade_read(const OS_XML *xml, xml_node **nodes, wmodule *module) {
#else
int wm_agent_upgrade_read(__attribute__((unused)) const OS_XML *xml, xml_node **nodes, wmodule *module) {
#endif
    wm_agent_upgrade* data = NULL;

    if (!module->data) {
        // Default initialization
        module->context = &WM_AGENT_UPGRADE_CONTEXT;
        module->tag = strdup(module->context->name);
        os_calloc(1, sizeof(wm_agent_upgrade), data);
        data->enabled = 1;
        #ifdef CLIENT
        data->agent_config.upgrade_wait_start = WM_UPGRADE_WAIT_START;
        data->agent_config.upgrade_wait_max = WM_UPGRADE_WAIT_MAX;
        data->agent_config.upgrade_wait_factor_increase = WM_UPGRADE_WAIT_FACTOR_INCREASE;
        data->agent_config.enable_ca_verification = 1;
        #else
        data->manager_config.max_threads = WM_UPGRADE_MAX_THREADS;
        data->manager_config.chunk_size = WM_UPGRADE_CHUNK_SIZE;
        data->manager_config.wpk_repository = NULL;
        #endif
        module->data = data;
    }

    data = module->data;

    #ifdef CLIENT
    // Read deprecated CA configuration
    if (!wcom_ca_store) {
        if (wm_agent_upgrade_read_ca_verification_old(&data->agent_config.enable_ca_verification)) {
            return OS_INVALID;
        }
    }
    #endif

    for (int i = 0; nodes && nodes[i]; i++)
    {
        if(!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }
        #ifdef CLIENT
        // Agent configurations
        else if (!strcmp(nodes[i]->element, XML_ENABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                data->enabled = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                data->enabled = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_WAIT_START)) {
            char *endptr;
            data->agent_config.upgrade_wait_start = strtol(nodes[i]->content,  &endptr, 0);

            if (data->agent_config.upgrade_wait_start == 0 || data->agent_config.upgrade_wait_start == INT_MAX) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_WAIT_START, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'h':
                data->agent_config.upgrade_wait_start *= 3600;
                break;
            case 'm':
                data->agent_config.upgrade_wait_start *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid %s at module '%s'", XML_WAIT_START, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_WAIT_MAX)) {
            char *endptr;
            data->agent_config.upgrade_wait_max = strtol(nodes[i]->content, &endptr, 0);
            if (data->agent_config.upgrade_wait_max == 0 || data->agent_config.upgrade_wait_max == INT_MAX) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_WAIT_MAX, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'h':
                data->agent_config.upgrade_wait_max *= 3600;
                break;
            case 'm':
                data->agent_config.upgrade_wait_max *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid content for tag '%s' at module '%s'", XML_WAIT_MAX, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_WAIT_FACTOR)) {
            float wait_factor = strtol(nodes[i]->content, NULL, 10);
            if (wait_factor > 1.0) {
                data->agent_config.upgrade_wait_factor_increase = wait_factor;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_WAIT_FACTOR, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_CA_VERIFICATION)) {
            XML_NODE childs = OS_GetElementsbyNode(xml, nodes[i]);
            if (!childs || wm_agent_upgrade_read_ca_verification(childs, &data->agent_config.enable_ca_verification)) {
                OS_ClearNode(childs);
                return OS_INVALID;
            }
            OS_ClearNode(childs);
        }
        #else
        else if (!strcmp(nodes[i]->element, XML_CHUNK_SIZE)) {
            if (!OS_StrIsNum(nodes[i]->content)) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_CHUNK_SIZE, WM_AGENT_UPGRADE_CONTEXT.name);
                return (OS_INVALID);
            }
            int chunk;
            if (chunk = atoi(nodes[i]->content), chunk < WM_UPGRADE_CHUNK_SIZE_MIN || chunk > WM_UPGRADE_CHUNK_SIZE_MAX) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_CHUNK_SIZE, WM_AGENT_UPGRADE_CONTEXT.name);
                return (OS_INVALID);
            }

            data->manager_config.chunk_size = chunk;

        } else if (!strcmp(nodes[i]->element, XML_MAX_THREADS)) {
            if (!OS_StrIsNum(nodes[i]->content)) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_MAX_THREADS, WM_AGENT_UPGRADE_CONTEXT.name);
                return (OS_INVALID);
            }
            int max_threads = atoi(nodes[i]->content);
            if (!max_threads) {
                // If 0, we assign the number of cpu cores
                data->manager_config.max_threads = get_nproc();
            } else if (max_threads <= 256) {
                data->manager_config.max_threads = max_threads;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_MAX_THREADS, WM_AGENT_UPGRADE_CONTEXT.name);
                return (OS_INVALID);
            }

        } else if (!strcmp(nodes[i]->element, XML_WPK_REPOSITORY)) {
            os_free(data->manager_config.wpk_repository);
            os_strdup(nodes[i]->content, data->manager_config.wpk_repository);
        }
        #endif
        else {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_AGENT_UPGRADE_CONTEXT.name);
        }
    }

    #ifdef CLIENT
    if (data->agent_config.enable_ca_verification) {
        if (!wcom_ca_store || !wcom_ca_store[0]) {
            os_realloc(wcom_ca_store, 2 * sizeof(char *), wcom_ca_store);
            os_strdup(DEF_CA_STORE, wcom_ca_store[0]);
            wcom_ca_store[1] = NULL;
        }
    } else {
        minfo("WPK verification with CA is disabled.");
        if (wcom_ca_store) {
            for (int i = 0; wcom_ca_store[i]; ++i) {
                os_free(wcom_ca_store[i]);
            }
            os_free(wcom_ca_store);
        }
    }
    #endif

    return 0;
}

#ifdef CLIENT
static int wm_agent_upgrade_read_ca_verification(xml_node **nodes, unsigned int *verification_flag) {
    int ca_store_count = 0;

    if (wcom_ca_store) {
        for (int i = 0; wcom_ca_store[i]; ++i) {
            os_free(wcom_ca_store[i]);
        }
        os_realloc(wcom_ca_store, sizeof(char *), wcom_ca_store);
        wcom_ca_store[0] = NULL;
    }

    for (int i = 0; nodes[i]; i++) {
        if (!strcmp(nodes[i]->element, XML_ENABLED)) {
            if (strcasecmp(nodes[i]->content, "yes") == 0) {
                *verification_flag = 1;
            } else if (strcasecmp(nodes[i]->content, "no") == 0) {
                *verification_flag = 0;
            } else {
                merror("Invalid content for tag <%s>", nodes[i]->element);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_CA_STORE)) {
            os_realloc(wcom_ca_store, (ca_store_count + 2) * sizeof(char *), wcom_ca_store);
            os_strdup(nodes[i]->content, wcom_ca_store[ca_store_count]);
            ca_store_count++;
            wcom_ca_store[ca_store_count] = NULL;
        }
    }

    return 0;
}

static int wm_agent_upgrade_read_ca_verification_old(unsigned int *verification_flag) {
    // Read CA deprecated configuration
    const char *(caverify[]) = {"ossec_config", "active-response", "ca_verification", NULL};
    const char *(castore[]) = {"ossec_config", "active-response", "ca_store", NULL};

    char **ca_verification = NULL;

    OS_XML xml2;

    /* Read XML file */
    if (OS_ReadXML(OSSECCONF, &xml2) < 0) {
        merror_exit(XML_ERROR, OSSECCONF, xml2.err, xml2.err_line);
    }

    if (ca_verification = OS_GetContents(&xml2, caverify), ca_verification) {

        for (int i = 0; ca_verification[i]; ++i) {
            if (strcasecmp(ca_verification[i], "yes") == 0) {
                *verification_flag = 1;
            }
            else if (strcasecmp(ca_verification[i], "no") == 0) {
                *verification_flag = 0;
            }
            else {
                merror("Invalid content for tag <%s>: '%s'", caverify[2], ca_verification[i]);
                free_strarray(ca_verification);
                return OS_INVALID;
            }
        }

        free_strarray(ca_verification);
    }

    wcom_ca_store = OS_GetContents(&xml2, castore);

    OS_ClearXML(&xml2);

    return 0;
}
#endif
