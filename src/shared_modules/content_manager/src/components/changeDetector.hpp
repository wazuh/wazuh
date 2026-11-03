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

#ifndef _CHANGE_DETECTOR_HPP
#define _CHANGE_DETECTOR_HPP

#include "contentIndexer.hpp"
#include "pitSession.hpp"
#include "tokenHelpers.hpp"
#include <json.hpp>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

/**
 * @brief What the source says its current state is.
 */
struct ProbeResult
{
    std::string remoteToken;    ///< Current remote token. "" in cursor mode, which does not probe.
    nlohmann::json metadata;    ///< Detector extras handed to the sink, e.g. `{"enabled": false}`.
    bool sourceMissing {false}; ///< The content this topic tracks does not exist remotely (yet).
    /// Set when the probe found the *configuration* to be unusable against the live data — not when
    /// it merely found nothing. A remote state that cannot be identified unambiguously is a config
    /// error, not a transient one: retrying cannot fix it, so the cycle ends `FailedConfig` and says
    /// which field to look at rather than silently picking one of the candidates.
    std::string configError;
};

/**
 * @brief What the cycle should fetch, given the remote state and the stored token.
 */
struct FetchPlan
{
    /// Shape of the fetch.
    enum class Mode
    {
        Full,        ///< Fetch everything.
        Incremental, ///< Fetch only what is newer than the stored token.
        NoChange     ///< Fetch nothing.
    };

    Mode mode {Mode::Full}; ///< Shape of the fetch.
    nlohmann::json query;   ///< Query to run. NOT yet scoped by `PitSession::scopeToData`.
};

/**
 * @brief How a topic decides whether its content moved.
 *
 * Two shapes, differing only in where the "current state" of the source lives: a monotonically
 * increasing integer written onto every document, or a content hash published next to the data.
 */
class IChangeDetector
{
public:
    virtual ~IChangeDetector() = default;

    /**
     * @brief Read the source's current token, from inside the snapshot.
     *
     * @param session The open PIT.
     * @param port Indexer access, for detectors that need a query the session does not offer.
     * @return The remote state.
     * @throws std::exception whatever the indexer throws when the probe query fails.
     */
    virtual ProbeResult probe(PitSession& session, content_manager::IContentIndexer& port) = 0;

    /**
     * @brief Decide what to fetch.
     *
     * @param remote The probed remote state.
     * @param localToken The token stored by the previous successful commit ("" forces a full fetch).
     * @return The plan.
     */
    virtual FetchPlan plan(const ProbeResult& remote, const std::string& localToken) const = 0;

    /**
     * @brief The token to persist once the sink has committed.
     *
     * @param remote The probed remote state.
     * @param highestPageToken Highest per-page token the fetch observed.
     * @return The token to store.
     */
    virtual std::string finalToken(const ProbeResult& remote, const std::string& highestPageToken) const = 0;

    /**
     * @brief The JSON pointer the paginator reads a page's token from.
     *
     * @return A pointer into a hit, or "" when the detector does not tokenise pages.
     */
    virtual std::string pageTokenPointer() const = 0;
};

/**
 * @brief Change detection by a monotonic integer cursor carried on every document.
 *
 * The stored token is the highest value seen; the next cycle asks for everything strictly greater.
 * The topic's own `source.query`, when it has one, narrows both shapes of fetch: a full one runs it
 * as is, an incremental one runs it AND the cursor range.
 */
class OffsetCursorDetector final : public IChangeDetector
{
public:
    /**
     * @brief Build a cursor detector.
     *
     * @param cursorField Document field carrying the cursor.
     * @param sourceQuery The topic's own query; empty selects everything.
     */
    explicit OffsetCursorDetector(std::string cursorField, std::optional<nlohmann::json> sourceQuery = std::nullopt)
        : m_cursorField {std::move(cursorField)}
        , m_sourceQuery {std::move(sourceQuery)}
    {
    }

    /// Nothing to probe: the cursor is carried by the documents themselves.
    ProbeResult probe(PitSession&, content_manager::IContentIndexer&) override
    {
        return ProbeResult {};
    }

    FetchPlan plan(const ProbeResult&, const std::string& localToken) const override
    {
        FetchPlan result;

        // A cursor that is absent, zeroed or corrupt all mean the same thing: there is no safe
        // lower bound, so the only correct fetch is everything. Falling through to a range query
        // with a garbage bound would either throw on every cycle or silently skip documents.
        std::uint64_t parsed = 0;
        if (!tokenHelpers::parseUnsigned(localToken, parsed) || parsed == 0)
        {
            result.mode = FetchPlan::Mode::Full;
            result.query = m_sourceQuery.value_or(nlohmann::json {{"match_all", nlohmann::json::object()}});
            return result;
        }

        result.mode = FetchPlan::Mode::Incremental;
        const nlohmann::json range {{"range", {{m_cursorField, {{"gt", parsed}}}}}};
        result.query = m_sourceQuery.has_value()
                           ? nlohmann::json {{"bool", {{"filter", nlohmann::json::array({*m_sourceQuery, range})}}}}
                           : range;
        return result;
    }

    std::string finalToken(const ProbeResult&, const std::string& highestPageToken) const override
    {
        return highestPageToken;
    }

    std::string pageTokenPointer() const override
    {
        return "/_source/" + m_cursorField;
    }

private:
    std::string m_cursorField;
    std::optional<nlohmann::json> m_sourceQuery; ///< The topic's own query, if any.
};

/**
 * @brief Change detection by a content hash published alongside the data.
 *
 * Two probe shapes:
 *
 *  - **doc probe** (`hashDocId` set): the hash lives in a manifest document whose id is known,
 *    e.g. the IOC sync's `__ioc_type_hashes__`.
 *  - **query probe** (`hashDocId` empty): the hash lives on the one document `hashQuery` selects,
 *    e.g. the ruleset sync's per-space policy document.
 *
 * @note The query probe runs inside the PIT, which spans every data index, so `hashQuery` must itself
 *       be selective enough to match exactly one document. When the configured names are aliases,
 *       `_index` reports the suffixed backing index, so an index has to be singled out by a wildcard
 *       on `_index`, never an exact match.
 */
class ContentHashDetector final : public IChangeDetector
{
public:
    /// Where the hash is and what else to read next to it.
    struct Config
    {
        std::string hashDocId;                               ///< Manifest document id (doc probe).
        nlohmann::json hashQuery;                            ///< Query selecting the hash document (query probe).
        std::vector<std::string> hashPointers;               ///< Candidate pointers to the hash; first match wins.
        std::map<std::string, std::string> metadataPointers; ///< name -> pointer, surfaced to the sink.
        nlohmann::json dataQuery;                            ///< Query selecting this topic's content.
    };

    /**
     * @brief Build a hash detector.
     *
     * @param config Probe configuration, already validated with the registration.
     */
    explicit ContentHashDetector(Config config)
        : m_config {std::move(config)}
    {
    }

    ProbeResult probe(PitSession& session, content_manager::IContentIndexer& port) override
    {
        const bool docProbe = !m_config.hashDocId.empty();
        const auto query = docProbe
                               ? nlohmann::json {{"ids", {{"values", nlohmann::json::array({m_config.hashDocId})}}}}
                               : m_config.hashQuery;

        // A doc probe selects by `_id`, which is unique, so one hit is all there can be. A query
        // probe has to prove it: two documents matching `hashQuery` mean the query is not selective
        // enough, and taking `front()` would pick one by shard order — unstable across cycles and
        // across shard relocations, so the topic would alternate between two hashes and reload on
        // every single cycle without ever reporting a fault. Ask for one more than we want, so the
        // ambiguity is visible rather than truncated away.
        const auto probeSize = docProbe ? std::size_t {1} : std::size_t {2};

        const auto hits = port.search(session.pit(),
                                      probeSize,
                                      session.scopeToData(query),
                                      PitSession::docSort(),
                                      std::nullopt,
                                      sourceFilter(),
                                      std::nullopt);

        const auto& hitArray = hits.contains("hits") ? hits.at("hits") : nlohmann::json::array();

        ProbeResult result;
        if (!hitArray.is_array() || hitArray.empty())
        {
            // Nothing published yet. Not an error: a space that does not exist remotely, or an
            // install whose IOC manifest has not been written, simply has nothing to sync.
            result.sourceMissing = true;
            return result;
        }

        if (!docProbe && hitArray.size() > 1)
        {
            result.configError = "detection.probe.query matched more than one document (" + m_config.hashQuery.dump() +
                                 "); it must select exactly one";
            return result;
        }

        const auto& hit = hitArray.front();
        const auto* source = tokenHelpers::resolve(hit, "/_source");
        result.remoteToken = source != nullptr ? readFirstString(*source) : std::string {};
        if (result.remoteToken.empty())
        {
            result.sourceMissing = true;
            return result;
        }

        result.metadata = nlohmann::json::object();
        for (const auto& [name, pointer] : m_config.metadataPointers)
        {
            if (const auto* value = tokenHelpers::resolve(*source, pointer); value != nullptr)
            {
                result.metadata[name] = *value;
            }
        }

        return result;
    }

    FetchPlan plan(const ProbeResult& remote, const std::string& localToken) const override
    {
        FetchPlan result;

        if (remote.sourceMissing || (!remote.remoteToken.empty() && remote.remoteToken == localToken))
        {
            result.mode = FetchPlan::Mode::NoChange;
            return result;
        }

        // A hash says "the content as a whole is at version X": there is no notion of fetching only
        // the part that moved, so every change is a full reload.
        result.mode = FetchPlan::Mode::Full;
        result.query = m_config.dataQuery;
        return result;
    }

    std::string finalToken(const ProbeResult& remote, const std::string&) const override
    {
        return remote.remoteToken;
    }

    /// Hash-tracked content has no per-page resume point: the promotion is all-or-nothing.
    std::string pageTokenPointer() const override
    {
        return {};
    }

private:
    /// Only the pointer roots are fetched: the manifest document can be large and the probe reads
    /// two or three fields out of it.
    nlohmann::json sourceFilter() const
    {
        auto includes = nlohmann::json::array();
        const auto add = [&includes](const std::string& pointer)
        {
            const auto end = pointer.find('/', 1);
            includes.push_back(pointer.substr(1, end == std::string::npos ? std::string::npos : end - 1));
        };

        for (const auto& pointer : m_config.hashPointers)
        {
            add(pointer);
        }
        for (const auto& [_, pointer] : m_config.metadataPointers)
        {
            add(pointer);
        }
        return nlohmann::json {{"includes", std::move(includes)}, {"excludes", nlohmann::json::array()}};
    }

    std::string readFirstString(const nlohmann::json& source) const
    {
        for (const auto& pointer : m_config.hashPointers)
        {
            const auto* value = tokenHelpers::resolve(source, pointer);
            if (value != nullptr && value->is_string() && !value->get_ref<const std::string&>().empty())
            {
                return value->get<std::string>();
            }
        }
        return {};
    }

    Config m_config;
};

#endif // _CHANGE_DETECTOR_HPP
