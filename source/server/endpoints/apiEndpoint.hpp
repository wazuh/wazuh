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
    std::string m_path;

    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<uvw::PipeHandle> m_handle;

    void connectionHandler(uvw::PipeHandle &handle);

public:
    /**
     * @brief Construct a new APIEndpoint object
     *
     * @param config
     * @param eventBuffer
     */
    explicit APIEndpoint(const std::string &config, ServerOutput &eventBuffer);
    ~APIEndpoint();

    void run() override;

    void configure() override;

    void close() override;
};

} // namespace engineserver::endpoints

#endif // _TCP_ENDPOINT_H
