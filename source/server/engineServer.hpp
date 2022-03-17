/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ENGINE_SERVER_H
#define _ENGINE_SERVER_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "endpoints/tcpEndpoint.hpp"
#include "endpoints/udpEndpoint.hpp"
#include "endpoints/datagramSocketEndpoint.hpp"

/**
 * @brief Defines all related server functionality.
 *
 */
namespace engineserver
{

constexpr uint32_t DEFAULT_BUFFER_SIZE = 1024;

/**
 * @brief Class that handles all endpoints and exposes Server functionality.
 *
 */
class EngineServer
{
private:
    std::map<std::string, std::unique_ptr<endpoints::BaseEndpoint>> m_endpoints;
    moodycamel::BlockingConcurrentQueue<std::string> m_eventBuffer;
    bool m_isConfigured;

    /**
     * @brief
     *
     * @param type
     * @param path
     * @param eventBuffer
     * @return std::unique_ptr<endpoints::BaseEndpoint>
     */
    std::unique_ptr<endpoints::BaseEndpoint> createEndpoint(
        const std::string & type, const std::string & path,
        moodycamel::BlockingConcurrentQueue<std::string> & eventBuffer) const;

public:
    /**
     * @brief Construct a new Engine Server object
     *
     * @param config <type>:<config> string describing endpoint type with it associated configuration.
     *
     * @param bufferSize Events queue buffer size.
     */
    explicit EngineServer(const std::vector<std::string> & config, size_t bufferSize = DEFAULT_BUFFER_SIZE);

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
     * @brief Returns the current configuration state of the server.
     *
     * @return true
     * @return false
     */
    bool isConfigured(void) const
    {
        return m_isConfigured;
    };

    /**
     * @brief Get server output queue
     *
     * @return const moodycamel::BlockingConcurrentQueue&
     */
    moodycamel::BlockingConcurrentQueue<std::string> & output();
};

} // namespace engineserver

#endif // _ENGINE_SERVER_H
