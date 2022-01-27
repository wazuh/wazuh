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

#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>

#include "endpoints/baseEndpoint.hpp"
#include "protocolHandler.hpp"

namespace engineserver
{

class EngineServer
{
private:
    std::map<std::string, std::unique_ptr<endpoints::BaseEndpoint>> m_endpoints;
    rxcpp::observable<nlohmann::json> m_output;

public:
    explicit EngineServer(const std::vector<std::string> & config);

    rxcpp::observable<nlohmann::json> output() const;

    void run(void);

    void close(void);
};

} // namespace engineserver

#endif // _ENGINE_SERVER_H_
