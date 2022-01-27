/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ENDPOINT_FACTORY_H
#define _ENDPOINT_FACTORY_H

#include <memory>
#include <string>

#include "baseEndpoint.hpp"

namespace engineserver::endpoints
{
/**
 * @brief Endpoint enum type
 *
 */
enum EndpointType
{
    TCP,
    UDP,
    SOCKET
};

/**
 * @brief Return endpoint enum from string
 *
 * @param endpointName
 * @return EndpointType
 */
EndpointType stringToEndpoint(const std::string & endpointName);

/**
 * @brief Factory method to create endpoints
 *
 * @param type
 * @param config
 * @return std::unique_ptr<BaseEndpoint>
 */
std::unique_ptr<BaseEndpoint> create(const std::string & type, const std::string & config);
} // namespace engineserver::endpoints

#endif // _ENDPOINT_FACTORY_H
