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
#include <stdexcept>

extern void logMessage(modules_log_level_t level, const std::string& msg);

/**
 * @brief Schema adapter for converting agent format to FlatBuffers parseable format
 *
 * The SchemaAdapter class provides functionality to adapt JSON messages from the agent
 * (with enriched agent context) to a format that is parseable by the FlatBuffers schema.
 * It handles different message types and schemas, transforming the data structure
 * to be compatible with FlatBuffers parsing requirements.
 *
 * This class is designed to be used as a static utility class, with all methods
 * being static. It uses thread-local storage for the JSON parser to ensure
 * thread safety in multi-threaded environments.
 *
 * @note This class is final and cannot be inherited from.
 * @note All methods are static and do not require class instantiation.
 */
class SchemaAdapter final
{
public:
    /**
     * @brief Adapts agent format messages to FlatBuffers parseable format
     *
     * This method parses a JSON message from the agent (with enriched agent context)
     * and converts it to a format that is parseable by the FlatBuffers schema.
     * The adapted message maintains agent information while transforming the structure
     * to be compatible with FlatBuffers parsing requirements.
     *
     * The method handles different message types:
     * - Integrity check messages (left/right) are discarded
     * - System deltas and syscheck deltas are processed with agent context preserved
     * - Sync messages are processed with component-specific data transformation
     *
     * @param[in] message The agent format JSON message to adapt (as string_view for efficiency)
     * @param[in] schema The message type schema (MT_SYS_DELTAS, MT_SYSCHECK_DELTAS, MT_SYNC)
     * @param[in] agentCtx Pointer to the agent context containing enriched agent information
     * @param[out] buffer The output buffer where the FlatBuffers-parseable message will be stored
     *
     * @throws std::invalid_argument If agentCtx is null
     * @throws std::invalid_argument If the agent format JSON message cannot be parsed
     * @throws std::invalid_argument If the message is missing required fields (type, data)
     * @throws std::invalid_argument If the message type is not implemented for the given schema
     * @throws std::invalid_argument If the schema type is not implemented
     *
     * @note The method uses thread-local storage for the JSON parser to ensure
     *       thread safety in multi-threaded environments.
     * @note The buffer parameter is appended to, so any existing content is preserved.
     * @note Integrity check messages (integrity_check_left, integrity_check_right) are
     *       silently discarded and the buffer remains unchanged.
     * @note The output format is designed to be compatible with FlatBuffers schema parsing.
     *
     * @see msg_type for available schema types
     * @see agent_ctx for agent context structure
     * @see FlatBuffers schema for output format specification
     *
     */
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
                if (type == "state" || type == "integrity_check_global" || type == "integrity_clear")
                {
                    static thread_local simdjson::internal::string_builder<> sb;
                    sb.clear();
                    sb.append(dataElem.get_object());
                    auto dataView = sb.str();

                    buffer.append(R"("data":{"attributes_type":")");
                    buffer.append(componentElem.get_string().value());
                    buffer.append(R"(",)");
                    buffer.append(dataView.substr(1));
                    buffer.append(R"(})");
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
