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
     * @brief Redirects the request to the appropriate module.
     *
     * @param module The module to be used. E.g. "wazuh-db"
     * @param callbackPre The pre callback function, this function is called before the endpoint
     * @param callbackPost The post callback function, this function is called after the endpoint
     * @param endpoint The endpoint to be used. E.g. "/v1/agents"
     * @param method The HTTP method to be used. E.g. "GET", "POST", "PUT", "DELETE"
     * @param req The HTTP request
     * @param res The HTTP response
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
