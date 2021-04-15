/*
 * Wazuh module configuration
 * Copyright (C) 2015-2021, Wazuh Inc.
 * April 6, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "os_execd/execd.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_execd.h"

int wm_execd_read(const OS_XML *xml, __attribute__((unused)) xml_node **nodes, wmodule *module) {
    int ret_val = OS_SUCCESS;

    if (NULL != xml) {
        if (-1 != ExecdConfig(xml)) {
            wm_execd_t* wmexecd = NULL;

            if (NULL == module->data) {
                os_calloc(1, sizeof(wm_execd_t), wmexecd);
                /* Reading the internal options
                int ret = OS_SUCCESS;
                if (ret = wm_logcollector_read(wmexecd), OS_SUCCESS != ret) {
                    os_free(wmexecd);
                    return ret;
                }*/
                module->data = wmexecd;
            } else {
                wmexecd = module->data;
            }

            wmexecd->is_disabled = is_disabled;
            wmexecd->max_restart_lock = max_restart_lock;
            wmexecd->pending_upg = pending_upg;
            wmexecd->req_timeout = req_timeout;
            //wmexecd->repeated_offenders_timeout = repeated_offenders_timeout;
        }
    }

    return ret_val;
}