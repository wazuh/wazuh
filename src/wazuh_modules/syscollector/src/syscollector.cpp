/*
 * Wazuh SysCollector
 * Copyright (C) 2015-2020, Wazuh Inc.
 * November 15, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscollector.h"
#include "syscollector.hpp"
#include "sysInfo.hpp"
#include <iostream>

#ifdef __cplusplus
extern "C" {
#endif
void syscollector_start(const unsigned int inverval,
                        send_data_callback_t callback,
                        const bool scanOnStart,
                        const bool hardware,
                        const bool os,
                        const bool network,
                        const bool packages,
                        const bool ports,
                        const bool portsAll,
                        const bool processes,
                        const bool hotfixes)
{
    std::function<void(const std::string&)> callbackWrapper
    {
        [callback](const std::string& data)
        {
            callback(data.c_str());
        }
    };

    Syscollector::instance().init(std::make_shared<SysInfo>(),
                                  callbackWrapper,
                                  inverval,
                                  scanOnStart,
                                  hardware,
                                  os,
                                  network,
                                  packages,
                                  ports,
                                  portsAll,
                                  processes,
                                  hotfixes);
}
void syscollector_stop()
{
    Syscollector::instance().destroy();
}

#ifdef __cplusplus
}
#endif