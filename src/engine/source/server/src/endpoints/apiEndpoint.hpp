/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _API_ENDPOINT_H
#define _API_ENDPOINT_H

#include <uvw/pipe.hpp>

#include <api/api.hpp>

#include "baseEndpoint.hpp"

namespace engineserver::endpoints
{

/**
 * @brief Implements tcp server endpoint using uvw library.
 *
 */
class APIEndpoint : public BaseEndpoint
{
private:
    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<uvw::PipeHandle> m_handle;
    std::shared_ptr<api::Registry> m_registry;

    void connectionHandler(uvw::PipeHandle& handle);

public:
    /**
     * @brief Construct a new APIEndpoint object
     *
     * @param Path to the unix socket.
     * @param Registry with all available API calls.
     */
    explicit APIEndpoint(const std::string& config,
                         std::shared_ptr<api::Registry> registry);
    ~APIEndpoint();

    void run() override;

    void configure() override;

    void close() override;

    std::shared_ptr<api::Registry> getRegistry() const;
};

} // namespace engineserver::endpoints

#endif // _TCP_ENDPOINT_H
