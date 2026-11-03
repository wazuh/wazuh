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

#ifndef _CONSUMER_GATE_HPP
#define _CONSUMER_GATE_HPP

#include "contentIndexer.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"
#include <chrono>
#include <cstdint>
#include <json.hpp>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

/**
 * @brief The consumer document's format, and the cheap pre-flight check that it says "ready".
 *
 * @ref PitSession validates readiness *inside* the snapshot, which is the correctness gate, with
 * the query and the parser defined here. The probe below is the cost gate, and it is not redundant
 * with it: a full VD load is a multi-minute, multi-gigabyte operation, and discovering "the consumer
 * is mid-update" only after opening a PIT over the whole CVE index wastes a lease and a round trip
 * on every cycle during an indexer content update.
 *
 *  - **It is bounded.** One probe per cycle; a busy consumer ends the cycle `SkippedConsumerNotReady`
 *    with a short `retryAfter` rather than parking the thread.
 *  - **It is cached, process-wide, per consumer id.** Registrations that watch the same consumer —
 *    the Engine's six IOC topics do — pay for one probe between them.
 *  - **It stays at DEBUG for the first few bad answers**, then escalates: an indexer that has just
 *    restarted is expected to answer badly for a few seconds.
 */
class ConsumerGate final
{
public:
    /// Consecutive bad answers tolerated below WARNING, while the indexer settles after a restart.
    static constexpr std::size_t WARN_AFTER_ATTEMPTS {3};

    /// Once escalated, how many further probes pass before the line is repeated.
    ///
    /// A consumer that stays unusable is a condition an operator has to be able to see at the
    /// default log level — "there is no CVE feed and nothing says why" is the single most expensive
    /// way for this to fail. But the gate is probed once per retry interval (60 s by default), so
    /// repeating on every probe would spend a line a minute for as long as the outage lasts. One in
    /// ten keeps the condition visible for hours without becoming the log.
    static constexpr std::size_t REPEAT_EVERY_ATTEMPTS {10};

    /// What the consumer document says about itself.
    enum class Status : std::uint8_t
    {
        Ready,      ///< Safe to query.
        Running,    ///< The indexer is rewriting the content.
        Failed,     ///< The consumer reports its own failure.
        Missing,    ///< No such document. The normal state of a fresh install.
        Empty,      ///< The document exists but carries no status.
        Unknown,    ///< A status string we do not recognise.
        Unreachable ///< The probe itself failed; the indexer could not be queried.
    };

    /// Outcome of one probe.
    struct Result
    {
        Status status {Status::Unknown}; ///< Consumer state.
        std::string raw;                 ///< Raw status string, for logging.
        std::string error;               ///< Transport error, when `status == Unreachable`.
    };

    /**
     * @brief Probe a consumer, reusing a recent answer when one is available.
     *
     * @param port Indexer access.
     * @param index Consumer status index. Empty disables the gate (returns `Ready`).
     * @param id Consumer document id. Empty disables the gate.
     * @param cacheTtl How long an answer may be reused across topics.
     * @return The consumer's state.
     */
    static Result probe(content_manager::IContentIndexer& port,
                        const std::string& index,
                        const std::string& id,
                        std::chrono::seconds cacheTtl)
    {
        if (index.empty() || id.empty())
        {
            return Result {Status::Ready, {}, {}};
        }

        const auto key = index + '\0' + id;
        const auto now = std::chrono::steady_clock::now();

        // The registry lock only finds the consumer's slot; the query runs under the slot's own lock.
        // Topics watching the same consumer still coalesce onto one probe — the point of the cache —
        // but one slow or timing-out consumer no longer queues every other consumer's probe behind it.
        std::shared_ptr<Slot> slot;
        {
            std::lock_guard<std::mutex> registryLock {mutex()};
            auto& found = cache()[key];
            if (!found)
            {
                found = std::make_shared<Slot>();
            }
            slot = found;
        }

        std::lock_guard<std::mutex> lock {slot->mutex};
        auto& entry = slot->entry;

        if (entry.valid && now < entry.expiresAt)
        {
            return entry.result;
        }

        entry.result = query(port, index, id);
        entry.valid = true;
        entry.expiresAt = now + cacheTtl;

        report(entry, index, id);
        return entry.result;
    }

    /**
     * @brief Drop every cached answer.
     *
     * The cache is process-wide and has no natural reset point, which unit tests need one of.
     */
    static void resetCache()
    {
        std::lock_guard<std::mutex> lock {mutex()};
        cache().clear();
    }

    /**
     * @brief Test seam over the escalation cadence.
     *
     * The cadence is the whole behaviour worth pinning here — whether a given attempt logs is not
     * observable from a probe's return value, and driving it through `probe()` would mean running
     * dozens of fake round trips to assert an arithmetic property.
     *
     * @param attempt 1-based count of consecutive non-ready answers.
     * @return True when that attempt should be reported above DEBUG.
     */
    static bool shouldEscalateForTest(std::size_t attempt) noexcept
    {
        return shouldEscalate(attempt);
    }

    /// @return The query selecting the consumer document @p id.
    static nlohmann::json statusQuery(const std::string& id)
    {
        return nlohmann::json {{"ids", {{"values", nlohmann::json::array({id})}}}};
    }

    /// @return The `_source` filter that keeps only the consumer's status.
    static nlohmann::json statusSourceFilter()
    {
        return nlohmann::json {{"includes", nlohmann::json::array({"status"})}, {"excludes", nlohmann::json::array()}};
    }

    /**
     * @brief Read a consumer's state out of the hits object of a @ref statusQuery search.
     *
     * @param hitsObject The `hits` object of the response.
     * @return The consumer's state. Never `Unreachable`: that is the search failing, not its answer.
     */
    static Result parse(const nlohmann::json& hitsObject)
    {
        const auto hits =
            hitsObject.is_object() ? hitsObject.value("hits", nlohmann::json::array()) : nlohmann::json::array();
        if (!hits.is_array() || hits.empty())
        {
            return Result {Status::Missing, {}, {}};
        }

        const auto& hit = hits.front();
        const auto source = hit.is_object() ? hit.value("_source", nlohmann::json::object()) : nlohmann::json {};
        if (!source.is_object() || !source.contains("status") || !source.at("status").is_string())
        {
            return Result {Status::Empty, {}, {}};
        }

        auto raw = source.at("status").get<std::string>();
        if (raw.empty())
        {
            return Result {Status::Empty, {}, {}};
        }
        if (raw == "ready")
        {
            return Result {Status::Ready, std::move(raw), {}};
        }
        if (raw == "running")
        {
            return Result {Status::Running, std::move(raw), {}};
        }
        if (raw == "failed")
        {
            return Result {Status::Failed, std::move(raw), {}};
        }
        return Result {Status::Unknown, std::move(raw), {}};
    }

    /// @return A short human-readable name for a status, for log messages.
    static const char* describe(Status status) noexcept
    {
        switch (status)
        {
            case Status::Ready: return "ready";
            case Status::Running: return "running";
            case Status::Failed: return "failed";
            case Status::Missing: return "missing";
            case Status::Empty: return "empty";
            case Status::Unreachable: return "unreachable";
            case Status::Unknown: break;
        }
        return "unknown";
    }

private:
    struct Entry
    {
        Result result;
        std::chrono::steady_clock::time_point expiresAt {};
        bool valid {false};
        std::size_t consecutiveNotReady {0}; ///< Consecutive answers of any kind other than `Ready`.
    };

    /// One consumer's cached answer and the lock its probes serialise on.
    struct Slot
    {
        std::mutex mutex;
        Entry entry;
    };

    static Result query(content_manager::IContentIndexer& port, const std::string& index, const std::string& id)
    {
        try
        {
            return parse(port.searchIndex(index, 1, statusQuery(id), statusSourceFilter()));
        }
        catch (const std::exception& e)
        {
            return Result {Status::Unreachable, {}, e.what()};
        }
    }

    /// Stay quiet while a bad answer is still plausibly transient — a restarting indexer is expected
    /// to answer badly for a few seconds — then escalate, because past that point the content is not
    /// being downloaded and an operator needs to know why without turning on debug logging.
    static void report(Entry& entry, const std::string& index, const std::string& id)
    {
        if (entry.result.status == Status::Ready)
        {
            entry.consecutiveNotReady = 0;
            logDebug2(WM_CONTENTUPDATER, "Consumer '%s' in '%s' is ready.", id.c_str(), index.c_str());
            return;
        }

        ++entry.consecutiveNotReady;

        if (!shouldEscalate(entry.consecutiveNotReady))
        {
            logDebug2(WM_CONTENTUPDATER,
                      "Consumer '%s' in '%s' is not usable yet (%s) (attempt %zu/%zu).",
                      id.c_str(),
                      index.c_str(),
                      describe(entry.result.status),
                      entry.consecutiveNotReady,
                      WARN_AFTER_ATTEMPTS);
            return;
        }

        switch (entry.result.status)
        {
            case Status::Failed:
                logWarn(WM_CONTENTUPDATER,
                        "Consumer '%s' in '%s' reports a failed status; content cannot be downloaded.",
                        id.c_str(),
                        index.c_str());
                break;

            case Status::Unreachable:
                logWarn(WM_CONTENTUPDATER,
                        "Failed to query consumer '%s' in '%s': %s",
                        id.c_str(),
                        index.c_str(),
                        entry.result.error.c_str());
                break;

            case Status::Unknown:
                logWarn(WM_CONTENTUPDATER,
                        "Consumer '%s' in '%s' returned an unknown status '%s'.",
                        id.c_str(),
                        index.c_str(),
                        entry.result.raw.c_str());
                break;

            case Status::Missing:
                // The normal state of a fresh install, and the reason a brand-new manager has no
                // content: the indexer has not published the consumer document yet. Named
                // explicitly rather than folded into the generic line, because the operator action
                // is different — wait for, or fix, the indexer-side content load.
                logInfo(WM_CONTENTUPDATER,
                        "Consumer '%s' is not present in '%s' yet; content cannot be downloaded until the "
                        "indexer publishes it.",
                        id.c_str(),
                        index.c_str());
                break;

            case Status::Running:
            case Status::Empty:
            case Status::Ready:
            default:
                logInfo(WM_CONTENTUPDATER,
                        "Consumer '%s' in '%s' is still not ready (%s); content download is deferred.",
                        id.c_str(),
                        index.c_str(),
                        describe(entry.result.status));
                break;
        }
    }

    /// @return True on the attempt that first crosses the threshold, and once every
    ///         REPEAT_EVERY_ATTEMPTS attempts after it.
    static bool shouldEscalate(std::size_t attempt) noexcept
    {
        if (attempt < WARN_AFTER_ATTEMPTS)
        {
            return false;
        }
        return (attempt - WARN_AFTER_ATTEMPTS) % REPEAT_EVERY_ATTEMPTS == 0;
    }

    static std::mutex& mutex()
    {
        static std::mutex instance;
        return instance;
    }

    static std::unordered_map<std::string, std::shared_ptr<Slot>>& cache()
    {
        static std::unordered_map<std::string, std::shared_ptr<Slot>> instance;
        return instance;
    }
};

#endif // _CONSUMER_GATE_HPP
