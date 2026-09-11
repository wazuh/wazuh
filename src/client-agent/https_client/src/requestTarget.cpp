/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "requestTarget.hpp"

std::string prefixedTarget(const std::string& endpoint, const std::string& target)
{
    if (endpoint.empty())
    {
        return target;
    }

    return "/" + endpoint + target;
}
