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
#include <variant>
#include <vector>

/**
 * @file contentTopicSpec.hpp
 * @brief A registration, described by concern (D2).
 *
 * Defaults are the library's; a host sets only what differs. `ContentRegister` validates the whole
 * spec at construction and names the field at fault.
 */
namespace content_manager
{
    /// When the topic runs. With no interval the host drives `runOnce` itself.
    struct Schedule
    {
        /// Library-driven period. Empty = host-driven: no driver thread, and `requestRun` is refused.
        std::optional<std::size_t> intervalSeconds;
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
} // namespace content_manager

#endif // _CONTENT_TOPIC_SPEC_HPP
