/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 27, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "config.h"
#include "exec-config.h"

 int Read_Exec(XML_NODE node, void *d1)
 {
     int i = 0;

     /* XML Definitions */
    const char *xml_request_timeout = "request_timeout";
    const char *xml_max_restart_lock = "max_restart_lock";
    const char *xml_log_level = "log_level";
    const char *xml_thread_stack_size = "thread_stack_size";

    if (!node)
        return 0;

    ExecConfig *exec_config;

    exec_config = (ExecConfig *)d1;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_request_timeout) == 0) {
            SetConf(node[i]->content, &exec_config->req_timeout, options.exec.request_timeout, xml_request_timeout);
        } else if (strcmp(node[i]->element, xml_max_restart_lock) == 0) {
            SetConf(node[i]->content, &exec_config->max_restart_lock, options.exec.max_restart_lock, xml_max_restart_lock);
        } else if (strcmp(node[i]->element, xml_log_level) == 0) {
            SetConf(node[i]->content, &exec_config->log_level, options.exec.log_level, xml_log_level);
        } else if (strcmp(node[i]->element, xml_thread_stack_size) == 0) {
            SetConf(node[i]->content, &exec_config->thread_stack_size, options.global.thread_stack_size, xml_thread_stack_size);            
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

     return 0;
 }