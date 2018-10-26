/*
 * URL download support library
 * Copyright (C) 2018 Wazuh Inc.
 * October 26, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "../config/config.h"
#include "../config/global-config.h"

// Returns 1 if the node is a worker, 0 if it is not and -1 if error.
int w_is_worker(){

    OS_XML xml;
    const char * xmlf[] = {"ossec_config", "cluster", "disabled", NULL};
    const char * xmlf2[] = {"ossec_config", "cluster", "node_type", NULL};
    const char *cfgfile = DEFAULTCPATH;
    int modules = 0;
    int is_worker = 0;
    _Config cfg;

    modules |= CCLUSTER;

    if (ReadConfig(modules, cfgfile, &cfg, NULL) < 0) {
        return (OS_INVALID);
    }

    if (OS_ReadXML(cfgfile, &xml) < 0) {
        mdebug1(XML_ERROR, cfgfile, xml.err, xml.err_line);
    } else {
        char * cl_status = OS_GetOneContentforElement(&xml, xmlf);
        if (cl_status && cl_status[0] != '\0') {
            if (!strcmp(cl_status, "no")) {
                char * cl_type = OS_GetOneContentforElement(&xml, xmlf2);
                if (cl_type && cl_type[0] != '\0') {
                    if (!strcmp(cl_type, "client") || !strcmp(cl_type, "worker")) {
                        is_worker = 1;
                    } else if (!strcmp(cl_type, "master")){
                        is_worker = 0;
                    } else {
                        is_worker = -1;
                    }
                    free(cl_type);
                }
            } else if (strcmp(cl_status, "yes")){
                is_worker = -1;
            }
            free(cl_status);
        } else {
            is_worker = -1;
        }
    }
    OS_ClearXML(&xml);

    return is_worker;
}