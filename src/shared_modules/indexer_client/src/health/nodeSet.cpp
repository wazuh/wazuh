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

#include "health/nodeSet.hpp"

#include <functional>
#include <tuple>
#include <utility>

#include "json.hpp"
#include "loggerHelper.h"

// Node health (plan 18, I57): the probe table, the rounds, the passive signals, the selector and the edge-triggered
// logs. Every transition is computed under m_mutex; the log lines and the onTransition hook run after releasing it.

namespace indexer_client::detail
{
    namespace
    {
        constexpr const char* TAG = "indexer-client";

        /// The WARN of a node that goes Down, queued until the mutex is released.
        struct DownLine final
        {
            std::string host;
            std::string reason;

            void operator()() const
            {
                logWarn(TAG, "Indexer node '%s' is no longer available. Reason: %s", host.c_str(), reason.c_str());
            }
        };

        /// Outcome of one probe result in the I57 table.
        struct Verdict final
        {
            NodeSet::State state {NodeSet::State::Down};
            std::string reason;
            bool permanent {false};
            bool red {false};
            bool local {false}; ///< TlsConfig, LocalError, ResponseTooLarge: the runtime is at fault (D36).
        };

        bool isPermanent(const nlohmann::json& error)
        {
            if (!error.is_object())
            {
                return false;
            }
            const auto durability = error.find("durability");
            return durability != error.end() && durability->is_string() &&
                   durability->get<std::string>() == "PERMANENT";
        }

        /// OpenSearch's 429 body: `durability` in `error` or in `error.root_cause[0]` (the top-level `status` is the
        /// number 429). An unreadable body is transient.
        bool permanent429(const std::string& body)
        {
            const auto json = nlohmann::json::parse(body, nullptr, false);
            if (json.is_discarded() || !json.is_object())
            {
                return false;
            }
            const auto error = json.find("error");
            if (error == json.end() || !error->is_object())
            {
                return false;
            }
            if (isPermanent(*error))
            {
                return true;
            }
            const auto rootCause = error->find("root_cause");
            return rootCause != error->end() && rootCause->is_array() && !rootCause->empty() &&
                   isPermanent(rootCause->front());
        }

        std::string causeReason(const HttpResult& result)
        {
            return std::string(toString(result.cause)) + " (curl " + std::to_string(result.curlCode) + ")";
        }

        Verdict classify(const HttpResult& result)
        {
            Verdict verdict;
            if (result.cause == TransportCause::None)
            {
                if (result.status >= 200 && result.status < 300)
                {
                    const auto json = nlohmann::json::parse(result.body, nullptr, false);
                    const auto status = (!json.is_discarded() && json.is_object()) ? json.find("status") : json.end();
                    if (status != json.end() && status->is_string())
                    {
                        const auto& value = status->get_ref<const std::string&>();
                        if (value == "green" || value == "yellow")
                        {
                            verdict.state = NodeSet::State::Available;
                            return verdict;
                        }
                        if (value == "red")
                        {
                            verdict.red = true;
                            return verdict;
                        }
                    }
                    verdict.reason = "invalid _cluster/health body";
                    return verdict;
                }
                if (result.status == 429)
                {
                    verdict.state = NodeSet::State::Throttled;
                    verdict.permanent = permanent429(result.body);
                    return verdict;
                }
                verdict.reason = "HTTP " + std::to_string(result.status);
                if (result.status == 401 || result.status == 403)
                {
                    verdict.reason += ": check indexer credentials / permissions";
                }
                return verdict;
            }
            if (nodeAttributable(result.cause))
            {
                verdict.reason = causeReason(result);
                return verdict;
            }
            // TlsConfig, LocalError, ResponseTooLarge (Cancelled/Shutdown never get here: the round is discarded). A
            // result the prober synthesised (a refused admission) carries its reason in `body` and no curl code.
            verdict.local = true;
            verdict.reason = (result.curlCode == 0 && !result.body.empty()) ? result.body : causeReason(result);
            return verdict;
        }
    } // namespace

    struct NodeSet::Pending final
    {
        std::vector<std::function<void()>> lines; ///< Each writes one log line with its exact format string.
        std::vector<std::tuple<std::size_t, State, State>> transitions;
        TransitionHook hook;
    };

    NodeSet::NodeSet(std::vector<std::string> hosts)
    {
        m_nodes.reserve(hosts.size());
        for (auto& host : hosts)
        {
            Node node;
            node.host = std::move(host);
            m_nodes.push_back(std::move(node));
        }
    }

    std::size_t NodeSet::size() const
    {
        return m_nodes.size();
    }

    const std::string& NodeSet::host(std::size_t index) const
    {
        return m_nodes.at(index).host;
    }

    void NodeSet::transition(std::size_t index, State to, std::string reason, bool permanent, Pending& pending)
    {
        auto& node = m_nodes[index];
        const auto from = node.state;
        if (from != to)
        {
            node.state = to;
            ++node.transitions;
            ++m_generation;
            pending.transitions.emplace_back(index, from, to);
        }
        // The reason of the last Down, kept even when the state does not change; empty otherwise. A node that stays
        // Down with a new reason logs it once (e.g. connect refused, then 401 once the indexer is back): edge-triggered
        // on the reason, never per round.
        const bool newDownReason = to == State::Down && node.logged == LogState::Down && node.reason != reason;
        node.reason = to == State::Down ? std::move(reason) : std::string {};
        if (newDownReason)
        {
            pending.lines.emplace_back(DownLine {node.host, node.reason});
        }

        const auto logged = to == State::Available ? LogState::Available
                                                   : (to == State::Throttled ? LogState::Throttled : LogState::Down);
        const bool wasPermanent = node.logged == LogState::Throttled && node.permanent;
        if (logged != node.logged)
        {
            if (logged == LogState::Available)
            {
                pending.lines.emplace_back([host = node.host]()
                                           { logInfo(TAG, "Indexer node '%s' is available.", host.c_str()); });
            }
            else if (logged == LogState::Throttled)
            {
                pending.lines.emplace_back(
                    [host = node.host]() { logInfo(TAG, "Indexer node '%s' is throttled (HTTP 429).", host.c_str()); });
            }
            else
            {
                pending.lines.emplace_back(DownLine {node.host, node.reason});
            }
            node.logged = logged;
        }
        node.permanent = to == State::Throttled && permanent;
        if (node.permanent && !wasPermanent)
        {
            pending.lines.emplace_back(
                [host = node.host]()
                {
                    logWarn(TAG,
                            "Indexer node '%s' is throttled with durability PERMANENT: it will not recover without "
                            "operator action.",
                            host.c_str());
                });
        }
    }

    void NodeSet::updateTlsEpisode(Pending& pending)
    {
        bool allTls = !m_nodes.empty();
        for (const auto& node : m_nodes)
        {
            if (node.state != State::Down || node.lastCause != TransportCause::Tls)
            {
                allTls = false;
                break;
            }
        }
        if (allTls && !m_allTls)
        {
            pending.lines.emplace_back(
                [curlCode = m_nodes.front().lastCurlCode]()
                {
                    logWarn(TAG,
                            "Every indexer node rejects the TLS handshake with the configured CA (curl %d): if the "
                            "indexer CA was rotated, update <indexer><ssl> and restart the manager.",
                            curlCode);
                });
        }
        m_allTls = allTls;
    }

    void NodeSet::emit(Pending& pending) const
    {
        for (const auto& line : pending.lines)
        {
            line();
        }
        if (pending.hook)
        {
            for (const auto& [index, from, to] : pending.transitions)
            {
                pending.hook(index, from, to);
            }
        }
    }

    bool NodeSet::applyRound(const std::vector<HttpResult>& round)
    {
        if (round.size() != m_nodes.size())
        {
            return false;
        }
        std::vector<Verdict> verdicts;
        verdicts.reserve(round.size());
        std::optional<std::size_t> redReporter;
        std::optional<std::string> localFault;
        for (std::size_t i = 0; i < round.size(); ++i)
        {
            const auto cause = round[i].cause;
            if (cause == TransportCause::Cancelled || cause == TransportCause::Shutdown)
            {
                return false; // Discarded: no transition, no log.
            }
            verdicts.push_back(classify(round[i]));
            if (verdicts.back().red && !redReporter)
            {
                redReporter = i;
            }
            if (verdicts.back().local && !localFault)
            {
                localFault = verdicts.back().reason;
            }
        }

        Pending pending;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            pending.hook = m_hook;
            const bool red = redReporter.has_value();
            if (red && !m_clusterRed)
            {
                pending.lines.emplace_back(
                    []() { logError(TAG, "Indexer cluster health is red: every node is marked down."); });
            }
            else if (!red && m_clusterRed)
            {
                pending.lines.emplace_back([]() { logInfo(TAG, "Indexer cluster is no longer red."); });
            }
            m_clusterRed = red;

            if (localFault && !m_localFault)
            {
                pending.lines.emplace_back([fault = *localFault]()
                                           { logError(TAG, "Indexer client local fault: %s", fault.c_str()); });
            }
            else if (!localFault && m_localFault)
            {
                pending.lines.emplace_back([]() { logInfo(TAG, "Indexer client local fault cleared."); });
            }
            m_localFault = localFault;

            for (std::size_t i = 0; i < m_nodes.size(); ++i)
            {
                m_nodes[i].lastCause = round[i].cause;
                m_nodes[i].lastCurlCode = round[i].curlCode;
                if (red && verdicts[i].state == State::Down && !verdicts[i].red)
                {
                    // Down by its own result: keep that reason, it is still the node's problem once red clears.
                    transition(i, State::Down, std::move(verdicts[i].reason), false, pending);
                }
                else if (red)
                {
                    transition(i,
                               State::Down,
                               "cluster health is red (reported by '" + m_nodes[*redReporter].host + "')",
                               false,
                               pending);
                }
                else
                {
                    auto& verdict = verdicts[i];
                    transition(i, verdict.state, std::move(verdict.reason), verdict.permanent, pending);
                }
            }
            updateTlsEpisode(pending);
        }
        emit(pending);
        return true;
    }

    void NodeSet::report(std::size_t index, const HttpResult& result)
    {
        if (index >= m_nodes.size())
        {
            return;
        }
        const bool down = nodeAttributable(result.cause);
        const bool throttled = !down && result.cause == TransportCause::None && result.status == 429;
        if (!down && !throttled)
        {
            return; // A passive success never promotes; everything else is the probe's.
        }
        Pending pending;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            pending.hook = m_hook;
            auto& node = m_nodes[index];
            if (down)
            {
                node.lastCause = result.cause;
                node.lastCurlCode = result.curlCode;
                transition(index, State::Down, causeReason(result), false, pending);
                updateTlsEpisode(pending);
            }
            else if (node.state == State::Available)
            {
                node.lastCause = result.cause;
                node.lastCurlCode = result.curlCode;
                transition(index, State::Throttled, {}, permanent429(result.body), pending);
                updateTlsEpisode(pending);
            }
            else
            {
                return;
            }
        }
        emit(pending);
    }

    std::optional<std::size_t> NodeSet::choose()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto count = m_nodes.size();
        for (const auto wanted : {State::Available, State::Throttled})
        {
            for (std::size_t step = 0; step < count; ++step)
            {
                const auto index = (m_next + step) % count;
                if (m_nodes[index].state == wanted)
                {
                    m_next = (index + 1) % count;
                    return index;
                }
            }
        }
        return std::nullopt;
    }

    HealthView NodeSet::view() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        HealthView view;
        for (const auto& node : m_nodes)
        {
            view.nodes.push_back({node.host, node.state, node.reason});
        }
        view.clusterRed = m_clusterRed;
        view.localFault = m_localFault;
        return view;
    }

    std::uint64_t NodeSet::generation() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_generation;
    }

    std::uint64_t NodeSet::transitions(std::size_t index) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_nodes.at(index).transitions;
    }

    void NodeSet::onTransition(TransitionHook hook)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_hook = std::move(hook);
    }
} // namespace indexer_client::detail
