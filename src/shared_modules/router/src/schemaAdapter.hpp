/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * July 24, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SCHEMA_ADAPTER_HPP
#define _SCHEMA_ADAPTER_HPP

#include "logging_helper.h"
#include "router.h"
#include "simdjson.h"
#include "stringHelper.h"
#include <stdexcept>

extern void logMessage(modules_log_level_t level, const std::string& msg);

class SchemaAdapter final
{
public:
    static void
    adaptJsonMessage(std::string_view message, const msg_type schema, const agent_ctx* agentCtx, std::string& buffer)
    {
        thread_local simdjson::dom::parser parser;
        simdjson::dom::element parsedResponse;

        if (agentCtx == nullptr)
        {
            throw std::invalid_argument("Agent context is null");
        }

        if (auto parseResult = parser.parse(message).get(parsedResponse); parseResult != simdjson::SUCCESS)
        {
            throw std::invalid_argument("Failed to parse the indexer response " + std::string(message));
        }

        auto typeElem = parsedResponse["type"];
        if (typeElem.error())
        {
            throw std::invalid_argument("No 'type' object in message: " + std::string(message));
        }

        auto type = typeElem.get_string().value();

        if (type == "integrity_check_left" || type == "integrity_check_right")
        {
            // Discard integrity_check_left and integrity_check_right messages
            return;
        }

        buffer.append(R"({"agent_info":{"agent_id":")");
        buffer.append(agentCtx->agent_id);
        buffer.append(R"(","agent_name":")");
        buffer.append(agentCtx->agent_name);
        buffer.append(R"(","agent_ip":")");
        buffer.append(agentCtx->agent_ip);
        buffer.append(R"(","agent_version":")");
        buffer.append(agentCtx->agent_version ? agentCtx->agent_version : "");
        buffer.append(R"("},)");

        buffer.append(R"("data_type":")");
        buffer.append(type);
        buffer.append(R"(",)");

        if (schema == MT_SYS_DELTAS || schema == MT_SYSCHECK_DELTAS)
        {
            buffer.append(message.substr(1));
        }
        else if (schema == MT_SYNC)
        {
            auto dataElem = parsedResponse["data"];
            auto componentElem = parsedResponse["component"];

            if (!dataElem.error())
            {
                if (type == "state")
                {
                    auto data = simdjson::minify(dataElem);
                    std::string_view dataView(data);
                    buffer.append(R"("data":{"attributes_type":")");
                    buffer.append(componentElem.get_string().value());
                    buffer.append(R"(",)");
                    buffer.append(dataView.substr(1));
                    buffer.append(R"(})");
                }
                else if (type == "integrity_check_global" || type == "integrity_clear")
                {
                    buffer.append(message.substr(1));
                }
                else
                {
                    throw std::invalid_argument("Type " + std::string(type) + " not implemented");
                }
            }
            else
            {
                throw std::invalid_argument("No 'data' object in MT_SYNC message: " + std::string(message));
            }
        }
        else
        {
            throw std::invalid_argument("Not implemented");
        }
    }
};

#endif // _SCHEMA_ADAPTER_HPP
