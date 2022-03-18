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

#include <string>

#include <blockingconcurrentqueue.h>

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
protected:
    using ServerOutput = moodycamel::BlockingConcurrentQueue<std::string>;

    std::string m_path;
    ServerOutput & m_out;

    BaseEndpoint(const std::string & path, ServerOutput & out);

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
    const ServerOutput & output(void) const;

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
