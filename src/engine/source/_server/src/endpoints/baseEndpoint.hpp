/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BASE_ENDPOINT_H
#define _BASE_ENDPOINT_H

#include <string>

#include <queue/concurrentQueue.hpp>

/**
 * @brief Contains all endpoint related functionality.
 *
 */
namespace engineserver::endpoints
{

/**
 * @brief Endpoint base interfaz that exposes functionality required by EngineServer.
 */
class BaseEndpoint
{

protected:
    std::string m_path;

    BaseEndpoint(const std::string& path)
        : m_path {path} {};

public:
    /**
     * @brief Destroy the Base Endpoint object, made virtual to destroy children classes.
     *
     */
    virtual ~BaseEndpoint() {};

    /**
     * @brief Start endpoint.
     *
     */
    virtual void bind(void) = 0;

    /**
     * @brief Close and liberate all resources used by endpoint.
     *
     */
    virtual void close(void) = 0;

};

} // namespace engineserver::endpoints

#endif // _BASE_ENDPOINT_H
