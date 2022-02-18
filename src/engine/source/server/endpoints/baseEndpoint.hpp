/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BASE_ENDPOINT_H_
#define _BASE_ENDPOINT_H_

#include <rxcpp/rx.hpp>
#include <string>

#include "json.hpp"

/**
 * @brief Contains all endpoint related functionality
 *
 */
namespace engineserver::endpoints
{

/**
 * @brief Endpoint base interfaz that exposes functionality required by EngineServer
 *
 */
class BaseEndpoint
{
public:
    using Event = std::string;
    using EventObs = rxcpp::observable<Event>;
    using ConnectionObs = rxcpp::observable<EventObs>;
    using EndpointObs = rxcpp::observable<ConnectionObs>;

protected:
    std::string m_path;
    EndpointObs m_out;

    explicit BaseEndpoint(const std::string & path);

public:
    /**
     * @brief Destroy the Base Endpoint object, made virtual to destroy children classes.
     *
     */
    virtual ~BaseEndpoint();

    /**
     * @brief Get the Observable object
     *
     * @return auto Observable object
     */
    EndpointObs output(void) const;

    /**
     * @brief Start endpoint.
     *
     */
    virtual void run(void) = 0;

    /**
     * @brief Close and liberate all resources used by endpoint.
     *
     */
    virtual void close(void) = 0;
};

} // namespace engineserver::endpoints

#endif // _BASE_ENDPOINT_H_
