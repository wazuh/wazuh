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
    rxcpp::observable<json::Document> m_output;

public:
    /**
     * @brief Construct a new Engine Server object.
     *
     */

    EngineServer() = default;
    /**
     * @brief Construct a new Engine Server object
     *
     * @param config <type>:<config> string describing endpoint type with it associated configuration.
     */
    //explicit EngineServer(const std::vector<std::string> & config);

    /**
     * @brief Set up endpoints and internal structures.
     *
     * @param config <type>:<config> string describing endpoint type with it associated configuration.
     */
    void configure(const std::vector<std::string> & config, rxcpp::observe_on_one_worker & mainthread);

    /**
     * @brief Server rxcpp endpoint, all events ingested come through here.
     *
     * @return rxcpp::observable<json::Document>
     */
    rxcpp::observable<json::Document> output() const;

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
};

} // namespace engineserver

#endif // _ENGINE_SERVER_H_
