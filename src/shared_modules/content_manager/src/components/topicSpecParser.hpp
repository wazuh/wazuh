/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TOPIC_SPEC_PARSER_HPP
#define _TOPIC_SPEC_PARSER_HPP

#include "contentTopicSpec.hpp"
#include <cstdint>
#include <initializer_list>
#include <json.hpp>
#include <stdexcept>
#include <string>
#include <string_view>

/**
 * @brief Registration parameters → @ref content_manager::TopicSpec, strictly (D2).
 *
 * The one place a registration is checked, at construction: every later stage reads the typed model,
 * never the JSON. Every block rejects keys it does not know — a key of the other strategy included —
 * naming the key and its block, so a stale or mistyped registration fails with a message an operator
 * can act on instead of being half-ignored.
 */
class TopicSpecParser final
{
public:
    /**
     * @brief Parse and validate registration parameters.
     *
     * @param parameters The parameters a `ContentRegister` received.
     * @return The registration.
     * @throws std::invalid_argument naming the offending block and key.
     */
    static content_manager::TopicSpec parse(const nlohmann::json& parameters)
    {
        requireObject(parameters, "parameters");
        rejectUnknown(parameters, "parameters", {"schedule", "source", "readiness", "detection", "fullLoad", "state"});

        content_manager::TopicSpec spec;

        if (parameters.contains("schedule"))
        {
            spec.schedule = parseSchedule(parameters.at("schedule"));
        }

        if (!parameters.contains("source"))
        {
            throw std::invalid_argument {"parameters: 'source' is required"};
        }
        spec.source = parseSource(parameters.at("source"));

        if (parameters.contains("readiness"))
        {
            spec.readiness = parseReadiness(parameters.at("readiness"));
        }

        if (!parameters.contains("detection"))
        {
            throw std::invalid_argument {"parameters: 'detection' is required"};
        }
        spec.detection = parseDetection(parameters.at("detection"));

        if (parameters.contains("fullLoad"))
        {
            spec.fullLoad = parseFullLoad(parameters.at("fullLoad"));
        }

        if (parameters.contains("state"))
        {
            spec.state = parseState(parameters.at("state"));
        }

        return spec;
    }

private:
    static content_manager::Schedule parseSchedule(const nlohmann::json& block)
    {
        constexpr std::string_view NAME {"schedule"};
        requireObject(block, NAME);
        rejectUnknown(block, NAME, {"intervalSeconds", "onDemand"});

        content_manager::Schedule schedule;
        if (block.contains("intervalSeconds"))
        {
            schedule.intervalSeconds = positiveInteger(block, NAME, "intervalSeconds");
        }
        schedule.onDemand = boolean(block, NAME, "onDemand", schedule.onDemand);
        return schedule;
    }

    static content_manager::Source parseSource(const nlohmann::json& block)
    {
        constexpr std::string_view NAME {"source"};
        requireObject(block, NAME);
        rejectUnknown(
            block, NAME, {"indices", "expandWildcards", "query", "sourceFilter", "pageSize", "slices", "pitKeepAlive"});

        content_manager::Source source;
        source.indices = nonEmptyStrings(block, NAME, "indices", true);
        source.expandWildcards = boolean(block, NAME, "expandWildcards", source.expandWildcards);
        if (block.contains("query"))
        {
            source.query = object(block, NAME, "query");
        }
        if (block.contains("sourceFilter"))
        {
            source.sourceFilter = object(block, NAME, "sourceFilter");
        }
        if (block.contains("pageSize"))
        {
            source.pageSize = positiveInteger(block, NAME, "pageSize");
        }
        if (block.contains("slices"))
        {
            source.slices = positiveInteger(block, NAME, "slices");
        }
        if (block.contains("pitKeepAlive"))
        {
            source.pitKeepAlive = nonEmptyString(block, NAME, "pitKeepAlive");
        }
        return source;
    }

    static content_manager::Readiness parseReadiness(const nlohmann::json& block)
    {
        constexpr std::string_view NAME {"readiness"};
        requireObject(block, NAME);
        rejectUnknown(block, NAME, {"consumerIndex", "consumerId", "retrySeconds", "cacheSeconds"});

        content_manager::Readiness readiness;
        readiness.consumerIndex = nonEmptyString(block, NAME, "consumerIndex");
        readiness.consumerId = nonEmptyString(block, NAME, "consumerId");

        // Both defences against consumer documents leaking into the content — the query-side
        // `must_not` on `_index` and the hit-side drop — compare against the `_index` metafield, which
        // reports the concrete backing index. A pattern or a list would simply never match, so the
        // leak would be silent; rejecting it here is the only place it is cheap to catch.
        const auto& index = readiness.consumerIndex;
        if (index.find('*') != std::string::npos || index.find(',') != std::string::npos || index.front() == '-')
        {
            throw std::invalid_argument {
                "readiness.consumerIndex: must be a concrete index name (no wildcard, comma list or exclusion): '" +
                index + "'"};
        }

        if (block.contains("retrySeconds"))
        {
            readiness.retrySeconds = positiveInteger(block, NAME, "retrySeconds");
        }
        if (block.contains("cacheSeconds"))
        {
            readiness.cacheSeconds = nonNegativeInteger(block, NAME, "cacheSeconds");
        }
        return readiness;
    }

    static std::variant<content_manager::CursorDetection, content_manager::HashDetection>
    parseDetection(const nlohmann::json& block)
    {
        constexpr std::string_view NAME {"detection"};
        requireObject(block, NAME);

        const auto type = nonEmptyString(block, NAME, "type");
        if (type == "cursor")
        {
            rejectUnknown(block, NAME, {"type", "field", "unmappedType"});
            content_manager::CursorDetection cursor;
            if (block.contains("field"))
            {
                cursor.field = nonEmptyString(block, NAME, "field");
            }
            if (block.contains("unmappedType"))
            {
                cursor.unmappedType = nonEmptyString(block, NAME, "unmappedType");
            }
            return cursor;
        }

        if (type == "hash")
        {
            rejectUnknown(block, NAME, {"type", "probe", "tokenPointers", "metadata"});
            content_manager::HashDetection hash;
            hash.probe = parseProbe(block);

            hash.tokenPointers = nonEmptyStrings(block, NAME, "tokenPointers", true);
            for (const auto& pointer : hash.tokenPointers)
            {
                requirePointer(pointer, "detection.tokenPointers");
            }

            if (block.contains("metadata"))
            {
                const auto& metadata = object(block, NAME, "metadata");
                for (const auto& [name, pointer] : metadata.items())
                {
                    if (!pointer.is_string())
                    {
                        throw std::invalid_argument {"detection.metadata: '" + name + "' must be a JSON pointer"};
                    }
                    requirePointer(pointer.get<std::string>(), "detection.metadata");
                    hash.metadata.emplace(name, pointer.get<std::string>());
                }
            }
            return hash;
        }

        throw std::invalid_argument {"detection.type: must be \"cursor\" or \"hash\", got '" + type + "'"};
    }

    static std::variant<content_manager::DocumentProbe, content_manager::QueryProbe>
    parseProbe(const nlohmann::json& detection)
    {
        constexpr std::string_view NAME {"detection.probe"};
        if (!detection.contains("probe"))
        {
            throw std::invalid_argument {"detection: 'probe' is required for hash detection"};
        }
        const auto& block = detection.at("probe");
        requireObject(block, NAME);

        const auto type = nonEmptyString(block, NAME, "type");
        if (type == "document")
        {
            rejectUnknown(block, NAME, {"type", "id"});
            return content_manager::DocumentProbe {nonEmptyString(block, NAME, "id")};
        }
        if (type == "query")
        {
            rejectUnknown(block, NAME, {"type", "query"});
            if (!block.contains("query"))
            {
                throw std::invalid_argument {"detection.probe: 'query' is required for a query probe"};
            }
            return content_manager::QueryProbe {object(block, NAME, "query")};
        }

        throw std::invalid_argument {"detection.probe.type: must be \"document\" or \"query\", got '" + type + "'"};
    }

    static content_manager::FullLoad parseFullLoad(const nlohmann::json& block)
    {
        constexpr std::string_view NAME {"fullLoad"};
        requireObject(block, NAME);
        rejectUnknown(block, NAME, {"requiredDocumentIds"});

        content_manager::FullLoad fullLoad;
        fullLoad.requiredDocumentIds = nonEmptyStrings(block, NAME, "requiredDocumentIds", false);
        return fullLoad;
    }

    static content_manager::State parseState(const nlohmann::json& block)
    {
        constexpr std::string_view NAME {"state"};
        requireObject(block, NAME);
        rejectUnknown(block, NAME, {"databasePath", "resetOnRegister"});

        content_manager::State state;
        if (block.contains("databasePath"))
        {
            state.databasePath = nonEmptyString(block, NAME, "databasePath");
        }
        state.resetOnRegister = boolean(block, NAME, "resetOnRegister", state.resetOnRegister);
        return state;
    }

    // --- primitives ------------------------------------------------------------------------------

    static std::string qualified(std::string_view block, std::string_view key)
    {
        return std::string {block} + "." + std::string {key};
    }

    static void requireObject(const nlohmann::json& value, std::string_view name)
    {
        if (!value.is_object())
        {
            throw std::invalid_argument {std::string {name} + ": must be an object"};
        }
    }

    static void
    rejectUnknown(const nlohmann::json& block, std::string_view name, std::initializer_list<std::string_view> known)
    {
        for (const auto& [key, _] : block.items())
        {
            bool isKnown = false;
            for (const auto candidate : known)
            {
                isKnown = isKnown || key == candidate;
            }
            if (!isKnown)
            {
                throw std::invalid_argument {std::string {name} + ": unknown key '" + key + "'"};
            }
        }
    }

    static void requirePointer(const std::string& pointer, std::string_view name)
    {
        if (pointer.empty() || pointer.front() != '/')
        {
            throw std::invalid_argument {std::string {name} + ": '" + pointer +
                                         "' is not a JSON pointer (it must start with '/')"};
        }
    }

    /// An integer by VALUE, not by storage class: nlohmann keeps `= 1` as signed and a parsed or
    /// unsigned-typed value as unsigned, so testing `is_number_unsigned()` alone rejects valid
    /// registrations depending on how the host happened to build them.
    static std::int64_t integer(const nlohmann::json& block, std::string_view name, std::string_view key)
    {
        const auto& value = block.at(std::string {key});
        if (value.is_number_unsigned())
        {
            return static_cast<std::int64_t>(value.get<std::uint64_t>());
        }
        if (value.is_number_integer())
        {
            return value.get<std::int64_t>();
        }
        throw std::invalid_argument {qualified(name, key) + ": must be an integer"};
    }

    static std::size_t positiveInteger(const nlohmann::json& block, std::string_view name, std::string_view key)
    {
        const auto value = integer(block, name, key);
        if (value <= 0)
        {
            throw std::invalid_argument {qualified(name, key) + ": must be a positive integer"};
        }
        return static_cast<std::size_t>(value);
    }

    static std::size_t nonNegativeInteger(const nlohmann::json& block, std::string_view name, std::string_view key)
    {
        const auto value = integer(block, name, key);
        if (value < 0)
        {
            throw std::invalid_argument {qualified(name, key) + ": must be a non-negative integer"};
        }
        return static_cast<std::size_t>(value);
    }

    static bool boolean(const nlohmann::json& block, std::string_view name, std::string_view key, bool fallback)
    {
        if (!block.contains(std::string {key}))
        {
            return fallback;
        }
        const auto& value = block.at(std::string {key});
        if (!value.is_boolean())
        {
            throw std::invalid_argument {qualified(name, key) + ": must be a boolean"};
        }
        return value.get<bool>();
    }

    static std::string nonEmptyString(const nlohmann::json& block, std::string_view name, std::string_view key)
    {
        if (!block.contains(std::string {key}))
        {
            throw std::invalid_argument {qualified(name, key) + ": is required"};
        }
        const auto& value = block.at(std::string {key});
        if (!value.is_string() || value.get_ref<const std::string&>().empty())
        {
            throw std::invalid_argument {qualified(name, key) + ": must be a non-empty string"};
        }
        return value.get<std::string>();
    }

    static const nlohmann::json& object(const nlohmann::json& block, std::string_view name, std::string_view key)
    {
        const auto& value = block.at(std::string {key});
        if (!value.is_object())
        {
            throw std::invalid_argument {qualified(name, key) + ": must be an object"};
        }
        return value;
    }

    static std::vector<std::string>
    nonEmptyStrings(const nlohmann::json& block, std::string_view name, std::string_view key, bool required)
    {
        if (!block.contains(std::string {key}))
        {
            if (required)
            {
                throw std::invalid_argument {qualified(name, key) + ": is required"};
            }
            return {};
        }

        const auto& value = block.at(std::string {key});
        if (!value.is_array() || (required && value.empty()))
        {
            throw std::invalid_argument {qualified(name, key) + (required ? ": must be a non-empty array of strings"
                                                                          : ": must be an array of strings")};
        }

        std::vector<std::string> strings;
        for (const auto& entry : value)
        {
            if (!entry.is_string() || entry.get_ref<const std::string&>().empty())
            {
                throw std::invalid_argument {qualified(name, key) + ": entries must be non-empty strings"};
            }
            strings.push_back(entry.get<std::string>());
        }
        return strings;
    }
};

#endif // _TOPIC_SPEC_PARSER_HPP
