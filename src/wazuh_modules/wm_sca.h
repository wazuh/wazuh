/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015, Wazuh Inc.
 * November 25, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_SCA_H
#define WM_SCA_H

#include "../os_xml/os_xml.h"
#include "wmodules_def.h"

#define WM_SCA_LOGTAG ARGV0 ":sca"

typedef struct wm_sca_t
{
    int enabled : 1;
    int scan_on_start : 1;
} wm_sca_t;

extern const wm_context WM_SCA_CONTEXT;

// Read configuration and return a module (if enabled) or NULL (if disabled)
int wm_sca_read(const OS_XML* xml, xml_node** nodes, wmodule* module);

#endif // WM_SCA_H
