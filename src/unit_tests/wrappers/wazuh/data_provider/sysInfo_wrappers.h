/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SYSINFO_WRAPPERS_H
#define SYSINFO_WRAPPERS_H

#include "cJSON.h"

int __wrap_sysinfo_hardware(cJSON** js_result);
int __wrap_sysinfo_packages(cJSON** js_result);
int __wrap_sysinfo_os(cJSON** js_result);
int __wrap_sysinfo_processes(cJSON** js_result);
int __wrap_sysinfo_networks(cJSON** js_result);
int __wrap_sysinfo_ports(cJSON** js_result);
void __wrap_sysinfo_free_result(cJSON** js_data);

#endif