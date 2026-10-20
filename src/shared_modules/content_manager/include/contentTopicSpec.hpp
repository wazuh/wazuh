/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _CONTENT_TOPIC_SPEC_HPP
#define _CONTENT_TOPIC_SPEC_HPP

#include <cstddef>
#include <json.hpp>
#include <map>
#include <optional>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

/**
 * @file contentTopicSpec.hpp
 * @brief A registration, described by concern (D2).
 *
 * Hosts fill a @ref content_manager::TopicSpec and hand @ref content_manager::toParameters's JSON to
 * `ContentRegister`. Everything here is header-only and runs in the host: only that JSON crosses
 * the library boundary, so none of these structs is part of the binary contract. Defaults are the
 * library's; a host sets only what differs.
 */
namespace content_manager
{
    /// When the topic runs. With no interval the host drives `runOnce` itself.
    struct Schedule
    {
        std::optional<std::size_t> intervalSeconds; ///< Library-driven period; empty = host-driven.
        bool onDemand {false};                      ///< Publish the topic on the on-demand lane.
    };

    /// What a cycle reads.
    struct Source
    {
        std::vector<std::string> indices;           ///< Content indices. Required, non-empty.
        bool expandWildcards {false};               ///< Expand wildcard patterns in @ref indices.
        std::optional<nlohmann::json> query;        ///< Selects this topic's documents; empty = all.
        std::optional<nlohmann::json> sourceFilter; ///< `_source` filter for every page.
        std::size_t pageSize {100};                 ///< Documents per request.
        std::size_t slices {1};                     ///< Parallel PIT slices for a full fetch.
        std::string pitKeepAlive {"5m"};            ///< Lease of the snapshot a cycle reads from.
    };

    /// The CTI consumer whose readiness gates the topic. No readiness = never gated.
    struct Readiness
    {
        std::string consumerIndex;     ///< A concrete index name: no alias, wildcard or list.
        std::string consumerId;        ///< The consumer document id.
        std::size_t retrySeconds {60}; ///< Back-off while the consumer is not ready.
        std::size_t cacheSeconds {5};  ///< How long a readiness answer is shared across topics.
    };

    /// Change detection by a monotonic cursor carried by every document; supports incremental fetches.
    struct CursorDetection
    {
        std::string field {"offset"};      ///< The cursor field.
        std::string unmappedType {"long"}; ///< Its type, for indices where it is not mapped yet.
    };

    /// The content hash lives in a document whose id is known.
    struct DocumentProbe
    {
        std::string id; ///< Document id.
    };

    /// The content hash lives in the one document a query selects.
    struct QueryProbe
    {
        nlohmann::json query; ///< Must match exactly one document.
    };

    /// Change detection by a content hash the source publishes; any change is a full reload.
    struct HashDetection
    {
        std::variant<DocumentProbe, QueryProbe> probe; ///< Where the hash is.
        std::vector<std::string> tokenPointers;        ///< JSON pointers to it; first match wins.
        std::map<std::string, std::string> metadata;   ///< name -> pointer, surfaced to the sink.
    };

    /// Preconditions of a full fetch.
    struct FullLoad
    {
        std::vector<std::string> requiredDocumentIds; ///< Documents that must exist before one runs.
    };

    /// Where the change-detection token lives, when the library keeps it.
    struct State
    {
        std::string databasePath;     ///< Built-in RocksDB token store; empty = host-supplied store.
        bool resetOnRegister {false}; ///< Clear the stored token at registration.
    };

    /// A whole registration.
    struct TopicSpec
    {
        Schedule schedule;
        Source source;
        std::optional<Readiness> readiness;
        std::variant<CursorDetection, HashDetection> detection;
        FullLoad fullLoad;
        State state;
    };

    /**
     * @brief The registration parameters for @p spec, in the shape `ContentRegister` parses.
     *
     * @param spec The registration.
     * @return The parameters.
     */
    inline nlohmann::json toParameters(const TopicSpec& spec)
    {
        nlohmann::json parameters = nlohmann::json::object();

        auto& schedule = parameters["schedule"];
        schedule = nlohmann::json {{"onDemand", spec.schedule.onDemand}};
        if (spec.schedule.intervalSeconds.has_value())
        {
            schedule["intervalSeconds"] = *spec.schedule.intervalSeconds;
        }

        auto& source = parameters["source"];
        source = nlohmann::json {{"indices", spec.source.indices},
                                 {"expandWildcards", spec.source.expandWildcards},
                                 {"pageSize", spec.source.pageSize},
                                 {"slices", spec.source.slices},
                                 {"pitKeepAlive", spec.source.pitKeepAlive}};
        if (spec.source.query.has_value())
        {
            source["query"] = *spec.source.query;
        }
        if (spec.source.sourceFilter.has_value())
        {
            source["sourceFilter"] = *spec.source.sourceFilter;
        }

        if (spec.readiness.has_value())
        {
            parameters["readiness"] = nlohmann::json {{"consumerIndex", spec.readiness->consumerIndex},
                                                      {"consumerId", spec.readiness->consumerId},
                                                      {"retrySeconds", spec.readiness->retrySeconds},
                                                      {"cacheSeconds", spec.readiness->cacheSeconds}};
        }

        parameters["detection"] = std::visit(
            [](const auto& detection) -> nlohmann::json
            {
                using T = std::decay_t<decltype(detection)>;
                if constexpr (std::is_same_v<T, CursorDetection>)
                {
                    return nlohmann::json {
                        {"type", "cursor"}, {"field", detection.field}, {"unmappedType", detection.unmappedType}};
                }
                else
                {
                    nlohmann::json hash {{"type", "hash"}, {"tokenPointers", detection.tokenPointers}};
                    hash["probe"] = std::visit(
                        [](const auto& probe) -> nlohmann::json
                        {
                            using P = std::decay_t<decltype(probe)>;
                            if constexpr (std::is_same_v<P, DocumentProbe>)
                            {
                                return nlohmann::json {{"type", "document"}, {"id", probe.id}};
                            }
                            else
                            {
                                return nlohmann::json {{"type", "query"}, {"query", probe.query}};
                            }
                        },
                        detection.probe);
                    if (!detection.metadata.empty())
                    {
                        hash["metadata"] = detection.metadata;
                    }
                    return hash;
                }
            },
            spec.detection);

        if (!spec.fullLoad.requiredDocumentIds.empty())
        {
            parameters["fullLoad"] = nlohmann::json {{"requiredDocumentIds", spec.fullLoad.requiredDocumentIds}};
        }

        parameters["state"] = nlohmann::json {{"resetOnRegister", spec.state.resetOnRegister}};
        if (!spec.state.databasePath.empty())
        {
            parameters["state"]["databasePath"] = spec.state.databasePath;
        }

        return parameters;
    }
} // namespace content_manager

#endif // _CONTENT_TOPIC_SPEC_HPP
