/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// The periodic log summary (stage E5c, plan 18 I102/I104). Contract: runtime/logSummary.hpp. The quota edges live in
// write/bucket.cpp and write/budget.cpp; this file drains them too.

#include "runtime/logSummary.hpp"

#include <algorithm>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "loggerHelper.h"
#include "query/pit.hpp"
#include "runtime/runtimeInternal.hpp"
#include "write/bucket.hpp"
#include "write/writer.hpp"

namespace indexer_client::detail::logging
{
    namespace
    {
        constexpr const char* TAG = "indexer-client";

        /// A line decided under the summary's mutex, emitted after it is dropped.
        using Line = std::function<void()>;

        unsigned long long ull(std::uint64_t value) noexcept
        {
            return static_cast<unsigned long long>(value);
        }

        /// Control bytes of a server-supplied token (itemErrorType) shown as '?': one log line stays one line.
        std::string printable(std::string_view text)
        {
            std::string out(text);
            for (auto& c : out)
            {
                const auto byte = static_cast<unsigned char>(c);
                if (byte < 0x20U || byte == 0x7FU)
                {
                    c = '?';
                }
            }
            return out;
        }

        std::string keyName(Cause cause, std::string_view itemErrorType)
        {
            std::string name = toString(cause);
            if (!itemErrorType.empty())
            {
                name += '/';
                name += printable(itemErrorType);
            }
            return name;
        }

        /// The lines of one bucket's interval: WARN with the keys (only when something was unsuccessful), INFO with
        /// the totals, DEBUG with the sample reason.
        void bucketLines(const std::string& consumer,
                         const std::string& bucket,
                         const write::LogInterval& interval,
                         unsigned long long seconds,
                         std::vector<Line>& lines)
        {
            if (!interval.keys.empty() || interval.other != 0)
            {
                std::string keys;
                for (const auto& key : interval.keys)
                {
                    if (!keys.empty())
                    {
                        keys += ", ";
                    }
                    keys += keyName(key.cause, key.itemErrorType) + '=' + std::to_string(key.count);
                }
                if (interval.other != 0)
                {
                    keys += (keys.empty() ? "other=" : ", other=") + std::to_string(interval.other);
                }
                lines.emplace_back(
                    [consumer, bucket, keys = std::move(keys), seconds]()
                    {
                        logWarn(TAG,
                                "Indexer client bucket '%s/%s' unsuccessful operations in the last %llu s: %s.",
                                consumer.c_str(),
                                bucket.c_str(),
                                seconds,
                                keys.c_str());
                    });
            }
            lines.emplace_back(
                [consumer,
                 bucket,
                 seconds,
                 accepted = ull(interval.accepted),
                 ok = ull(interval.ok),
                 failed = ull(interval.failed),
                 dropped = ull(interval.dropped)]()
                {
                    logInfo(TAG,
                            "Indexer client bucket '%s/%s' in the last %llu s: %llu accepted, %llu ok, %llu failed, "
                            "%llu dropped.",
                            consumer.c_str(),
                            bucket.c_str(),
                            seconds,
                            accepted,
                            ok,
                            failed,
                            dropped);
                });
            if (!interval.sampleReason.empty())
            {
                lines.emplace_back(
                    [consumer,
                     bucket,
                     key = keyName(interval.sampleCause, interval.sampleItemErrorType),
                     reason = interval.sampleReason]()
                    {
                        logDebug1(TAG,
                                  "Indexer client bucket '%s/%s' sample reason (%s): %s",
                                  consumer.c_str(),
                                  bucket.c_str(),
                                  key.c_str(),
                                  reason.c_str());
                    });
            }
        }

        class Summary final
            : public LogSummary
            , public std::enable_shared_from_this<Summary>
        {
        public:
            explicit Summary(std::weak_ptr<RuntimeState> runtime)
                : m_runtime(std::move(runtime))
            {
            }

            void start() override
            {
                const auto sources = runtimeLogSummarySources(m_runtime);
                if (!sources)
                {
                    return;
                }
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_started || m_stopped)
                    {
                        return;
                    }
                    m_started = true;
                    m_interval = sources->interval;
                    m_last = std::chrono::steady_clock::now();
                }
                arm();
            }

            void flush() override
            {
                body();
            }

            void stop() override
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_stopped = true; // No re-arm from here on; the runtime stops the timers right after.
            }

            void finish() override
            {
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_stopped = true;
                    if (m_finished)
                    {
                        return;
                    }
                    m_finished = true;
                }
                body(); // The final summary, synchronous.
            }

        private:
            void arm()
            {
                Duration interval {};
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_stopped)
                    {
                        return;
                    }
                    interval = m_interval;
                }
                // Weak capture: the timer never keeps the summary alive (the runtime owns it).
                runtimeLogSummaryAfter(m_runtime,
                                       interval,
                                       [weak = weak_from_this()]()
                                       {
                                           if (auto self = weak.lock())
                                           {
                                               self->body();
                                               self->arm();
                                           }
                                       });
            }

            /// The summary of the interval since the previous one. Every line is decided under m_mutex (which
            /// serializes the timer's run and the final one) and emitted after it is dropped; the bucket and global
            /// edge lines still pending are drained last, also outside every mutex.
            void body()
            {
                // Taken outside m_mutex (they lock the runtime mutex). The clients are released right after m_mutex,
                // before the emission: the body must not be the one holding a closed client's name while it logs
                // (dropping the last reference releases it under the runtime mutex, which nothing here holds).
                auto clients = runtimeLiveClients(m_runtime);
                const auto sources = runtimeLogSummarySources(m_runtime);
                std::vector<std::shared_ptr<write::Bucket>> buckets;
                std::vector<Line> lines;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    const auto now = std::chrono::steady_clock::now();
                    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_last).count();
                    m_last = now;
                    const auto seconds =
                        static_cast<unsigned long long>(std::max<std::int64_t>(1, (elapsed + 999) / 1000));
                    for (const auto& client : clients)
                    {
                        for (const auto& bucket : client->bucketStates)
                        {
                            if (!bucket)
                            {
                                continue;
                            }
                            buckets.push_back(bucket);
                            const auto interval = bucket->takeLogInterval();
                            if (interval.active())
                            {
                                bucketLines(client->consumer, bucket->spec().name, interval, seconds, lines);
                            }
                        }
                        const auto overruns = client->callbackOverruns.load();
                        const auto delta = overruns - client->overrunsLogged;
                        client->overrunsLogged = overruns;
                        const auto maxMicros = std::max<std::int64_t>(0, client->callbackIntervalMaxMicros.exchange(0));
                        if (delta != 0)
                        {
                            lines.emplace_back(
                                [consumer = client->consumer,
                                 delta = ull(delta),
                                 budget = static_cast<long long>(client->callbackBudget.count()),
                                 maxMs = ull((static_cast<std::uint64_t>(maxMicros) + 999) / 1000),
                                 seconds]()
                                {
                                    logWarn(TAG,
                                            "Indexer client consumer '%s': %llu callbacks exceeded the callback budget "
                                            "of %lld ms in the last %llu s (the slowest took %llu ms).",
                                            consumer.c_str(),
                                            delta,
                                            budget,
                                            seconds,
                                            maxMs);
                                });
                        }
                    }
                    if (sources && sources->pits)
                    {
                        auto expired = sources->pits->takeExpiredDeletes();
                        if (expired.count != 0)
                        {
                            lines.emplace_back(
                                [count = ull(expired.count), id = printable(expired.firstId), seconds]()
                                {
                                    logWarn(TAG,
                                            "Indexer client gave up %llu PIT delete(s) in the last %llu s (first PIT "
                                            "id '%s...'): the indexer frees them when their keep_alive lapses.",
                                            count,
                                            seconds,
                                            id.c_str());
                                });
                        }
                    }
                }
                clients.clear(); // `buckets` and the lines' captures keep what the emission needs.
                for (const auto& line : lines)
                {
                    try
                    {
                        line();
                    }
                    catch (...)
                    {
                        // A log sink must never take a runtime thread down.
                    }
                }
                for (const auto& bucket : buckets)
                {
                    bucket->emitPendingLogs();
                }
                if (sources && sources->writePath)
                {
                    sources->writePath->budget().emitPendingLogs();
                }
            }

            const std::weak_ptr<RuntimeState> m_runtime;
            std::mutex m_mutex; ///< The body's; guards the members below and ClientState::overrunsLogged.
            bool m_started {false};
            bool m_stopped {false};
            bool m_finished {false};
            Duration m_interval {Duration {60000}};
            TimePoint m_last {std::chrono::steady_clock::now()};
        };
    } // namespace

    std::shared_ptr<LogSummary> makeLogSummary(const std::weak_ptr<RuntimeState>& runtime)
    {
        return std::make_shared<Summary>(runtime);
    }
} // namespace indexer_client::detail::logging
