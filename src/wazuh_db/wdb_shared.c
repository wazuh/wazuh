/*
 * Wazuh-DB Common variables and functions.
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 22, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

/* Variables */

wdb_config wconfig;
_Config gconfig;

/// Strings used with wdbc_result.
const char* WDBC_RESULT[] = {
    [WDBC_OK]      = "ok",
    [WDBC_DUE]     = "due",
    [WDBC_ERROR]   = "err",
    [WDBC_IGNORE]  = "ign",
    [WDBC_UNKNOWN] = "unk"
};

/// Array of component strings.
const char* WDBC_VALID_COMPONENTS[] = { 
    [WB_COMP_SYSCOLLECTOR_PROCESSES]        = "syscollector_processes",
    [WB_COMP_SYSCOLLECTOR_PACKAGES]         = "syscollector_packages",
    [WB_COMP_SYSCOLLECTOR_HOTFIXES]         = "syscollector_hotfixes",
    [WB_COMP_SYSCOLLECTOR_PORTS]            = "syscollector_ports",
    [WB_COMP_SYSCOLLECTOR_NETWORK_PROTOCOL] = "syscollector_network_protocol",
    [WB_COMP_SYSCOLLECTOR_NETWORK_ADDRESS]  = "syscollector_network_address",
    [WB_COMP_SYSCOLLECTOR_NETWORK_IFACE]    = "syscollector_network_iface",
    [WB_COMP_SYSCOLLECTOR_HWINFO]           = "syscollector_hwinfo",
    [WB_COMP_SYSCOLLECTOR_OSINFO]           = "syscollector_osinfo",
    [WB_COMP_SYSCOLLECTOR_USERS]            = "syscollector_users",
    [WB_COMP_SYSCOLLECTOR_GROUPS]           = "syscollector_groups",
    [WB_COMP_SYSCHECK]                      = "syscheck",
    [WB_COMP_FIM_FILE]                      = "fim_file",
    [WB_COMP_FIM_REGISTRY]                  = "fim_registry",
    [WB_COMP_FIM_REGISTRY_KEY]              = "fim_registry_key",
    [WB_COMP_FIM_REGISTRY_VALUE]            = "fim_registry_value"
};

/* Methods */

/**
 * @brief Frees agent_info_data struct memory.
 *
 * @param[in] agent_data Pointer to the struct to be freed.
 */
void wdb_free_agent_info_data(agent_info_data *agent_data) {
    if (agent_data) {
        os_free(agent_data->version);
        os_free(agent_data->config_sum);
        os_free(agent_data->merged_sum);
        os_free(agent_data->manager_host);
        os_free(agent_data->node_name);
        os_free(agent_data->agent_ip);
        os_free(agent_data->labels);
        os_free(agent_data->connection_status);
        os_free(agent_data->sync_status);
        os_free(agent_data->group_config_status);
        if (agent_data->osd) {
            os_free(agent_data->osd->os_name);
            os_free(agent_data->osd->os_version);
            os_free(agent_data->osd->os_major);
            os_free(agent_data->osd->os_minor);
            os_free(agent_data->osd->os_codename);
            os_free(agent_data->osd->os_platform);
            os_free(agent_data->osd->os_build);
            os_free(agent_data->osd->os_uname);
            os_free(agent_data->osd->os_arch);
            os_free(agent_data->osd);
        }
        os_free(agent_data);
    }
}

// Calculates SHA1 hash from a NULL terminated string array
int wdbi_array_hash(const char ** strings_to_hash, os_sha1 hexdigest) {
    size_t it = 0;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size;
    int ret_val = OS_SUCCESS;

    EVP_MD_CTX * ctx = EVP_MD_CTX_create();
    if (!ctx) {
        mdebug2("Failed during hash context creation");
        return OS_INVALID;
    }

    if (1 != EVP_DigestInit(ctx, EVP_sha1()) ) {
        mdebug2("Failed during hash context initialization");
        EVP_MD_CTX_destroy(ctx);
        return OS_INVALID;
    }

    if (strings_to_hash) {
        while(strings_to_hash[it]) {
            if (1 != EVP_DigestUpdate(ctx, strings_to_hash[it], strlen(strings_to_hash[it])) ) {
                mdebug2("Failed during hash context update");
                ret_val = OS_INVALID;
                break;
            }
            it++;
        }
    }

    EVP_DigestFinal_ex(ctx, digest, &digest_size);
    EVP_MD_CTX_destroy(ctx);
    if (ret_val != OS_INVALID) {
        OS_SHA1_Hexdigest(digest, hexdigest);
    }

    return ret_val;
}

 // Calculates SHA1 hash from a set of strings as parameters, with NULL as end
 int wdbi_strings_hash(os_sha1 hexdigest, ...) {
    char* parameter = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size;
    int ret_val = OS_SUCCESS;
    va_list parameters;

    EVP_MD_CTX * ctx = EVP_MD_CTX_create();
    if (!ctx) {
        mdebug2("Failed during hash context creation");
        return OS_INVALID;
    }

    if (1 != EVP_DigestInit(ctx, EVP_sha1()) ) {
        mdebug2("Failed during hash context initialization");
        EVP_MD_CTX_destroy(ctx);
        return OS_INVALID;
    }

    va_start(parameters, hexdigest);

    while(parameter = va_arg(parameters, char*), parameter) {
        if (1 != EVP_DigestUpdate(ctx, parameter, strlen(parameter)) ) {
            mdebug2("Failed during hash context update");
            ret_val = OS_INVALID;
            break;
        }
    }
    va_end(parameters);

    EVP_DigestFinal_ex(ctx, digest, &digest_size);
    EVP_MD_CTX_destroy(ctx);
    if (ret_val != OS_INVALID) {
        OS_SHA1_Hexdigest(digest, hexdigest);
    }

    return ret_val;
 }
