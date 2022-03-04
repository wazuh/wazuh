/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ENGINE_SERVER_H_
#define _ENGINE_SERVER_H_

#include <map>
#include <memory>
#include <rxcpp/rx.hpp>

#include "blockingconcurrentqueue.h"
#include "endpoints/baseEndpoint.hpp"
#include "json.hpp"

/**
 * @brief Defines all related server functionality.
 *
 */
namespace engineserver
{

/**
 * @brief Class that handles all endpoints and exposes Server functionality.
 *
 */
class EngineServer
{
private:
    std::map<std::string, std::unique_ptr<endpoints::BaseEndpoint>> m_endpoints;
    moodycamel::BlockingConcurrentQueue<std::string> m_eventBuffer;

public:
    /**
     * @brief Construct a new Engine Server object
     *
     * @param bufferSize
     */
    explicit EngineServer(const size_t & bufferSize);

    /**
     * @brief Construct a new Engine Server object
     *
     * @param config <type>:<config> string describing endpoint type with it associated configuration.
     */

    /**
     * @brief Set up endpoints and internal structures.
     *
     * @param config <type>:<config> string describing endpoint type with it associated configuration.
     */
    void configure(const std::vector<std::string> & config);

    /**
     * @brief Start server.
     *
     */
    void run(void);

    /**
     * @brief Close and liberate resources used by server.
     *
     */
    void close(void);

    /**
     * @brief Get server output queue
     *
     * @return const moodycamel::BlockingConcurrentQueue&
     */
    moodycamel::BlockingConcurrentQueue<std::string>& output();
};

} // namespace engineserver

#endif // _ENGINE_SERVER_H_
