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

int wm_execd_read(__attribute__((unused)) const OS_XML *xml, __attribute__((unused)) xml_node **nodes, wmodule *const module) {
    int ret_val = OS_INVALID;

    if (module) {
        module->context = &WM_EXECD_CONTEXT;
        module->tag = strdup(EXECD_WM_NAME);
        if (-1 != ExecdConfig()) {
            wm_execd_t* wmexecd = NULL;

            if (NULL == module->data) {
                os_calloc(1, sizeof(wm_execd_t), wmexecd);
                module->data = wmexecd;
            } else {
                wmexecd = module->data;
            }
            max_restart_lock = getDefine_Int("execd", "max_restart_lock", 0, 3600);
            req_timeout = getDefine_Int("execd", "request_timeout", 1, 3600);

            wmexecd->is_disabled = is_disabled;
            wmexecd->max_restart_lock = max_restart_lock;
            wmexecd->req_timeout = req_timeout;
            wmexecd->repeated_offenders_timeout = repeated_offenders_timeout;
            ret_val = OS_SUCCESS;
        }
    }

    return ret_val;
}
