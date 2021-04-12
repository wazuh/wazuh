/*
 * Wazuh EXECD
 * Copyright (C) 2015-2021, Wazuh Inc.
 * April 5, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules_def.h"
#include "os_xml/os_xml.h"

#ifndef WM_EXECD_H
#define WM_EXECD_H

extern const wm_context WM_EXECD_CONTEXT; // Context

typedef struct wm_execd_t {
    time_t pending_upg;
    int is_disabled;
    int req_timeout;
    int max_restart_lock;
    //int repeated_offenders_timeout[];
} wm_execd_t;

/**
 * @brief Parses internal configuration.
 *
 * @param wmexecd Execd module to be populated.
 * @return 1 if everything was ok, 0 otherwise.
 */
int wm_execd_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif // WM_EXECD_H