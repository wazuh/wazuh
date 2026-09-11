/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CHANGE_DETECTOR_HPP
#define _CHANGE_DETECTOR_HPP

#include "indexerQueryPort.hpp"
#include "pitSession.hpp"
#include <json.hpp>
#include <map>
#include <string>
#include <utility>
#include <vector>

/**
 * @brief What the source says its current state is.
 */
struct ProbeResult
{
    std::string remoteToken;      ///< Current remote token. "" in cursor mode, which does not probe.
    nlohmann::json metadata;      ///< Detector extras handed to the sink, e.g. `{"enabled": false}`.
    bool sourceMissing {false};   ///< The content this topic tracks does not exist remotely (yet).
    /// Set when the probe found the *configuration* to be unusable against the live data — not when
    /// it merely found nothing. A remote state that cannot be identified unambiguously is a config
    /// error, not a transient one: retrying cannot fix it, so the cycle ends `FailedConfig` and says
    /// which key to look at rather than silently picking one of the candidates.
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
        Incremental, ///< Fetch only what is newer than `startToken`.
        NoChange     ///< Fetch nothing.
    };

    Mode mode {Mode::Full}; ///< Shape of the fetch.
    nlohmann::json query;   ///< Query to run. NOT yet scoped by `PitSession::scopeToData`.
    std::string startToken; ///< Lower bound, for `Incremental`.
};

/**
 * @brief How a topic decides whether its content moved.
 *
 * The two implementations below are the only two shapes the three consumers need, and they differ
 * only in where the "current state" of the source lives: a monotonically increasing integer written
 * onto every document (VD), or a content hash published next to the data (both Engine consumers).
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
     * @throws IndexerConnectorException if the probe query fails.
     */
    virtual ProbeResult probe(PitSession& session, IIndexerQueryPort& port) = 0;

    /**
     * @brief Decide what to fetch.
     *
     * @param remote The probed remote state.
     * @param localToken The token stored by the previous successful commit.
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
 * The field name is configuration (`indexer.cursorField`, default `"offset"`), which is what lets
 * this class be reused by anything that publishes an increasing sequence number.
 */
class OffsetCursorDetector final : public IChangeDetector
{
public:
    /**
     * @brief Build a cursor detector.
     *
     * @param cursorField Document field carrying the cursor.
     */
    explicit OffsetCursorDetector(std::string cursorField)
        : m_cursorField {std::move(cursorField)}
    {
    }

    /// Nothing to probe: the cursor is carried by the documents themselves.
    ProbeResult probe(PitSession&, IIndexerQueryPort&) override
    {
        return ProbeResult {};
    }

    FetchPlan plan(const ProbeResult&, const std::string& localToken) const override
    {
        FetchPlan result;
        result.startToken = localToken;

        // A cursor that is absent, zeroed or corrupt all mean the same thing: there is no safe
        // lower bound, so the only correct fetch is everything. Falling through to a range query
        // with a garbage bound would either throw on every cycle or silently skip documents.
        std::uint64_t parsed = 0;
        if (!parseToken(localToken, parsed) || parsed == 0)
        {
            result.mode = FetchPlan::Mode::Full;
            result.query = nlohmann::json {{"match_all", nlohmann::json::object()}};
            result.startToken.clear();
            return result;
        }

        result.mode = FetchPlan::Mode::Incremental;
        result.query = nlohmann::json {{"range", {{m_cursorField, {{"gt", parsed}}}}}};
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

    /// @return The document field carrying the cursor.
    const std::string& cursorField() const noexcept
    {
        return m_cursorField;
    }

    /**
     * @brief Parse a stored cursor.
     *
     * @param token Stored token.
     * @param[out] value Parsed value, untouched on failure.
     * @return True when @p token is a well-formed unsigned integer.
     */
    static bool parseToken(const std::string& token, std::uint64_t& value)
    {
        if (token.empty() || token.find_first_not_of("0123456789") != std::string::npos)
        {
            return false;
        }
        try
        {
            value = std::stoull(token);
        }
        catch (const std::exception&)
        {
            return false;
        }
        return true;
    }

private:
    std::string m_cursorField;
};

/**
 * @brief Change detection by a content hash published alongside the data.
 *
 * Two probe shapes, because the two Engine consumers locate their hash differently:
 *
 *  - **doc probe** (`hashDocId` set): the hash lives in a dedicated manifest document whose id is
 *    known, e.g. `iocsync`'s `__ioc_type_hashes__`.
 *  - **query probe** (`hashIndex` set): the hash lives on a document that has to be searched for,
 *    e.g. `cmsync`'s per-space policy document.
 *
 * @note The query probe runs inside the PIT, which spans every data index. Restricting it to
 *       `hashIndex` via the `_index` metafield is NOT possible in general: when the configured name
 *       is an alias, `_index` reports the concrete backing index instead. So `hashQuery` must
 *       itself be selective enough to match exactly one document — for the policy case, filtering on
 *       a policy-only field does it. `hashIndex` is kept for diagnostics and to select this shape.
 */
class ContentHashDetector final : public IChangeDetector
{
public:
    /// Where the hash is and what else to read next to it.
    struct Config
    {
        std::string hashDocId;                          ///< Manifest document id (doc probe).
        std::string hashIndex;                          ///< Index the hash document lives in (query probe).
        nlohmann::json hashQuery;                       ///< Query selecting the hash document (query probe).
        std::vector<std::string> hashPointers;          ///< Candidate pointers to the hash; first match wins.
        std::map<std::string, std::string> metadataPointers; ///< name -> pointer, surfaced to the sink.
        nlohmann::json dataQuery;                       ///< Query selecting this topic's content.
    };

    /**
     * @brief Build a hash detector.
     *
     * @param config Probe configuration. Validated by `ExecutionContext` before it gets here.
     */
    explicit ContentHashDetector(Config config)
        : m_config {std::move(config)}
    {
    }

    ProbeResult probe(PitSession& session, IIndexerQueryPort& port) override
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
                                      probeSort(),
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
            result.configError = "indexer.hashQuery matched more than one document in '" + m_config.hashIndex +
                                 "'; it must select exactly one";
            return result;
        }

        const auto& hit = hitArray.front();
        if (!hit.contains("_source") || !hit.at("_source").is_object())
        {
            result.sourceMissing = true;
            return result;
        }

        const auto& source = hit.at("_source");
        result.remoteToken = readFirstString(source, m_config.hashPointers);
        if (result.remoteToken.empty())
        {
            result.sourceMissing = true;
            return result;
        }

        result.metadata = nlohmann::json::object();
        for (const auto& [name, pointer] : m_config.metadataPointers)
        {
            if (const auto* value = resolve(source, pointer); value != nullptr)
            {
                result.metadata[name] = *value;
            }
        }

        return result;
    }

    FetchPlan plan(const ProbeResult& remote, const std::string& localToken) const override
    {
        FetchPlan result;
        result.startToken = localToken;

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
            auto root = pointerRoot(pointer);
            if (!root.empty())
            {
                includes.push_back(std::move(root));
            }
        };

        for (const auto& pointer : m_config.hashPointers)
        {
            add(pointer);
        }
        for (const auto& [_, pointer] : m_config.metadataPointers)
        {
            add(pointer);
        }

        if (includes.empty())
        {
            return nlohmann::json {{"includes", nlohmann::json::array({"*"})},
                                   {"excludes", nlohmann::json::array()}};
        }
        return nlohmann::json {{"includes", std::move(includes)}, {"excludes", nlohmann::json::array()}};
    }

    /// "/type_hashes/url_domain/hash/sha256" -> "type_hashes"
    static std::string pointerRoot(const std::string& pointer)
    {
        if (pointer.size() < 2 || pointer.front() != '/')
        {
            return {};
        }
        const auto end = pointer.find('/', 1);
        return pointer.substr(1, end == std::string::npos ? std::string::npos : end - 1);
    }

    static const nlohmann::json* resolve(const nlohmann::json& document, const std::string& pointer)
    {
        if (pointer.empty() || pointer.front() != '/')
        {
            return nullptr;
        }
        try
        {
            const nlohmann::json::json_pointer jp {pointer};
            if (!document.contains(jp))
            {
                return nullptr;
            }
            return &document.at(jp);
        }
        catch (const std::exception&)
        {
            return nullptr;
        }
    }

    static std::string readFirstString(const nlohmann::json& document, const std::vector<std::string>& pointers)
    {
        for (const auto& pointer : pointers)
        {
            const auto* value = resolve(document, pointer);
            if (value != nullptr && value->is_string())
            {
                auto text = value->get<std::string>();
                if (!text.empty())
                {
                    return text;
                }
            }
        }
        return {};
    }

    static const nlohmann::json& probeSort()
    {
        static const nlohmann::json sort =
            nlohmann::json::array({nlohmann::json {{"_shard_doc", "asc"}}, nlohmann::json {{"_id", "asc"}}});
        return sort;
    }

    Config m_config;
};

#endif // _CHANGE_DETECTOR_HPP
