/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2020, Wazuh Inc.
 * November 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#ifndef _SYS_INFO_H
#define _SYS_INFO_H

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "cJSON.h"
#ifdef __cplusplus
extern "C" {
#endif

EXPORTED void sysinfo_hardware(cJSON** js_result);
EXPORTED void sysinfo_packages(cJSON** js_result);
EXPORTED void sysinfo_os(cJSON** js_result);
EXPORTED void sysinfo_processes(cJSON** js_result);
EXPORTED void sysinfo_networks(cJSON** js_result);
EXPORTED void sysinfo_ports(cJSON** js_result);
EXPORTED void sysinfo_free_result(cJSON** js_data);

#ifdef __cplusplus
}
#endif

#endif //_SYS_INFO_H