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
