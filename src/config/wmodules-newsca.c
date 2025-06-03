/*
 * Wazuh NewSca Module Configuration
 * Copyright (C) 2015, Wazuh Inc.
 * March 9, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

//#ifdef ENABLE_NEWSCA
#include "wazuh_modules/wmodules.h"

// static const char *XML_INTERVAL = "interval";
// static const char *XML_SCAN_ON_START = "scan_on_start";
// static const char *XML_DISABLED = "disabled";
// static const char *XML_NETWORK = "network";
// static const char *XML_OS_SCAN = "os";
// static const char *XML_HARDWARE = "hardware";
// static const char *XML_PACKAGES = "packages";
// static const char *XML_PORTS = "ports";
// static const char *XML_PROCS = "processes";
// static const char *XML_HOTFIXES = "hotfixes";
// static const char *XML_SYNC = "synchronization";

// static void parse_synchronization_section(wm_sys_t * newsca, XML_NODE node) {
//     const char *XML_DB_SYNC_MAX_EPS = "max_eps";
//     const int XML_DB_SYNC_MAX_EPS_SIZE = 7;
//     const int MIN_SYNC_MESSAGES_THROUGHPUT = 0; // It means disabled
//     const int MAX_SYNC_MESSAGES_THROUGHPUT = 1000000;
//     for (int i = 0; node[i]; ++i) {
//         if (strncmp(node[i]->element, XML_DB_SYNC_MAX_EPS, XML_DB_SYNC_MAX_EPS_SIZE) == 0) {
//             char * end;
//             const long value = strtol(node[i]->content, &end, 10);

//             if (value < MIN_SYNC_MESSAGES_THROUGHPUT || value > MAX_SYNC_MESSAGES_THROUGHPUT || *end) {
//                 mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
//             } else {
//                 newsca->sync.sync_max_eps = value;
//             }
//         } else {
//             mwarn(XML_INVELEM, node[i]->element);
//         }
//     }
// }

wmodule* wm_newsca_read()
{
    wmodule* module;

    os_calloc(1, sizeof(wmodule), module);

    module->context = &WM_NEWSCA_CONTEXT;
    module->tag = strdup(module->context->name);
    mtinfo(WM_NEWSCA_LOGTAG, "Loaded newsca module.");
    return module;
}
//#endif // ENABLE_NEWSCA
