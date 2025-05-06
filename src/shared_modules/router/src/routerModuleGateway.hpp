/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * May 30, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROUTER_MODULE_GATEWAY_HPP
#define _ROUTER_MODULE_GATEWAY_HPP

#include "external/cpp-httplib/httplib.h"
#include "wazuh-db/gateway.hpp"
#include <string_view>

/**
 * @brief RouterModuleGateway class.
 *
 */
class RouterModuleGateway final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief
     *

     */
    static void redirect(std::string_view module,
                         void* callbackPre,
                         void* callbackPost,
                         std::string_view endpoint,
                         std::string_view method,
                         const httplib::Request& req,
                         httplib::Response& res)
    {
        if (module.compare("wazuh-db") == 0)
        {
            WDB::redirect(callbackPre, callbackPost, endpoint, method, req, res);
        }
        else
        {
            throw std::runtime_error("Module not implemented");
        }
    }
};

#endif /* _ROUTER_MODULE_GATEWAY_HPP */
