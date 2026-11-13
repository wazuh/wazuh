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

#ifndef _INDEXER_CLIENT_TESTS_FAKE_HEALTH_RULES_HPP
#define _INDEXER_CLIENT_TESTS_FAKE_HEALTH_RULES_HPP

// Scripted answers of the fake indexer to the health probe: `GET /_cluster/health/wazuh-*,.wazuh-*` with
// OpenSearch's real bodies, the 429 shapes of a circuit breaker and the probe counters. Every helper returns a plain
// Rule, so a test can still tune it (times, latency, retryAfter) before FakeIndexer::addRule().

#include "fakeIndexer.hpp"

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace indexer_client::testing
{
    /// Exact path of the health probe: the health of the manager's indices only (the query string, if any, is not
    /// part of Rule::pathRegex matching). Spelled out, not built from the library's constant, so that a change of
    /// the probe's URL breaks the fake's rules instead of following them.
    inline constexpr std::string_view HEALTH_PATH {"/_cluster/health/wazuh-*,.wazuh-*"};
    /// HEALTH_PATH as an ECMAScript regex for Rule::pathRegex (its `*` and `.` escaped): it matches only that path.
    inline constexpr std::string_view HEALTH_PATH_REGEX {R"(/_cluster/health/wazuh-\*,\.wazuh-\*)"};

    /// `durability` of an OpenSearch 429 (the value is serialized upper-case, as OpenSearch does).
    enum class Durability
    {
        Transient,
        Permanent
    };

    namespace detail
    {
        /// Escapes @p text as the contents of a JSON string literal (quotes, backslashes and control characters).
        inline std::string jsonEscape(std::string_view text)
        {
            static constexpr const char* HEX {"0123456789abcdef"};
            std::string out;
            out.reserve(text.size());
            for (const char c : text)
            {
                switch (c)
                {
                    case '"': out += "\\\""; break;
                    case '\\': out += "\\\\"; break;
                    case '\n': out += "\\n"; break;
                    case '\r': out += "\\r"; break;
                    case '\t': out += "\\t"; break;
                    default:
                        if (static_cast<unsigned char>(c) < 0x20)
                        {
                            out += "\\u00";
                            out += HEX[(static_cast<unsigned char>(c) >> 4) & 0xfU];
                            out += HEX[static_cast<unsigned char>(c) & 0xfU];
                        }
                        else
                        {
                            out += c;
                        }
                }
            }
            return out;
        }

        /// The fields of a one-node OpenSearch `_cluster/health` answer that follow `status` (no leading comma).
        inline constexpr std::string_view HEALTH_TAIL {
            R"("timed_out":false,"number_of_nodes":1,"number_of_data_nodes":1,"discovered_master":true,)"
            R"("discovered_cluster_manager":true,"active_primary_shards":12,"active_shards":12,)"
            R"("relocating_shards":0,"initializing_shards":0,"unassigned_shards":0,"delayed_unassigned_shards":0,)"
            R"("number_of_pending_tasks":0,"number_of_in_flight_fetch":0,"task_max_waiting_in_queue_millis":0,)"
            R"("active_shards_percent_as_number":100.0})"};

        /// A health rule answering 200 with @p body.
        inline Rule healthOk(std::string body)
        {
            Rule rule;
            rule.method = "GET";
            rule.pathRegex = std::string(HEALTH_PATH_REGEX);
            rule.status = 200;
            rule.body = std::move(body);
            return rule;
        }
    } // namespace detail

    /**
     * @brief Body of a 200 `_cluster/health` answer whose `status` is the JSON string @p status.
     *
     * Any value is served verbatim ("green", "yellow", "red" or something else such as "unknown").
     */
    inline std::string healthBody(std::string_view status)
    {
        return std::string(R"({"cluster_name":"wazuh-cluster","status":")") + detail::jsonEscape(status) + "\"," +
               std::string(detail::HEALTH_TAIL);
    }

    /// `GET /_cluster/health` ⇒ 200 with healthBody(@p status).
    inline Rule healthRule(std::string_view status)
    {
        return detail::healthOk(healthBody(status));
    }

    /// `GET /_cluster/health` ⇒ 200 with a realistic body that has no `status` member.
    inline Rule healthRuleWithoutStatus()
    {
        return detail::healthOk(R"({"cluster_name":"wazuh-cluster",)" + std::string(detail::HEALTH_TAIL));
    }

    /// `GET /_cluster/health` ⇒ 200 with a realistic body whose `status` is the number 1 (not a string).
    inline Rule healthRuleNonStringStatus()
    {
        return detail::healthOk(R"({"cluster_name":"wazuh-cluster","status":1,)" + std::string(detail::HEALTH_TAIL));
    }

    /// `GET /_cluster/health` ⇒ 200 with a body that is not JSON (a health answer truncated mid-object).
    inline Rule healthRuleInvalidJson()
    {
        return detail::healthOk(R"({"cluster_name":"wazuh-cluster","status":"gre)");
    }

    /**
     * @brief OpenSearch's body for an error @p httpStatus of the health endpoint.
     *
     * 401: the security plugin's plain `Unauthorized` (what it sends for missing or wrong Basic credentials);
     * 403: the security plugin's `security_exception` for `cluster:monitor/health`;
     * 503: `cluster_manager_not_discovered_exception`; anything else: a generic OpenSearch error with that status.
     */
    inline std::string healthErrorBody(int httpStatus)
    {
        switch (httpStatus)
        {
            case 401: return "Unauthorized";
            case 403:
                return R"({"error":{"root_cause":[{"type":"security_exception","reason":"no permissions for )"
                       R"([cluster:monitor/health] and User [name=wazuh, backend_roles=[], requestedTenant=null]"}],)"
                       R"("type":"security_exception","reason":"no permissions for [cluster:monitor/health] and User )"
                       R"([name=wazuh, backend_roles=[], requestedTenant=null]"},"status":403})";
            case 503:
                return R"({"error":{"root_cause":[{"type":"cluster_manager_not_discovered_exception","reason":null}],)"
                       R"("type":"cluster_manager_not_discovered_exception","reason":null},"status":503})";
            default:
                return R"({"error":{"root_cause":[{"type":"exception","reason":"health failed"}],)"
                       R"("type":"exception","reason":"health failed"},"status":)" +
                       std::to_string(httpStatus) + "}";
        }
    }

    /// `GET /_cluster/health` ⇒ @p httpStatus with healthErrorBody(@p httpStatus).
    inline Rule healthStatusRule(int httpStatus)
    {
        auto rule = detail::healthOk(healthErrorBody(httpStatus));
        rule.status = httpStatus;
        return rule;
    }

    /// `GET /_cluster/health` ⇒ @p httpStatus with exactly @p body.
    inline Rule healthStatusRule(int httpStatus, std::string body)
    {
        auto rule = detail::healthOk(std::move(body));
        rule.status = httpStatus;
        return rule;
    }

    /// "TRANSIENT" or "PERMANENT".
    inline std::string durabilityName(Durability durability)
    {
        return durability == Durability::Permanent ? "PERMANENT" : "TRANSIENT";
    }

    /**
     * @brief OpenSearch's 429 body of a tripped parent circuit breaker.
     *
     * `status` at the top level is the number 429. @p inRootCause puts `durability` ONLY in `root_cause[0]`
     * (`error` then has none); otherwise it is in both `error` and `root_cause[0]`, as OpenSearch sends it.
     */
    inline std::string throttledBody(Durability durability, bool inRootCause)
    {
        static constexpr std::string_view REASON {
            "[parent] Data too large, data for [<http_request>] would be [1020054528/972.7mb], which is larger than "
            "the limit of [1020054323/972.7mb], real usage: [1020054528/972.7mb], new bytes reserved: [0/0b], "
            "usages [request=0/0b, fielddata=0/0b, in_flight_requests=0/0b]"};
        const std::string durable = R"("durability":")" + durabilityName(durability) + "\"";
        const std::string cause = R"("type":"circuit_breaking_exception","reason":")" + std::string(REASON) +
                                  R"(","bytes_wanted":1020054528,"bytes_limit":1020054323,)" + durable;
        std::string error = R"("type":"circuit_breaking_exception","reason":")" + std::string(REASON) +
                            R"(","bytes_wanted":1020054528,"bytes_limit":1020054323)";
        if (!inRootCause)
        {
            error += "," + durable;
        }
        return R"({"error":{"root_cause":[{)" + cause + "}]," + error + R"(},"status":429})";
    }

    /// `GET /_cluster/health` ⇒ 429 with throttledBody(@p durability, @p inRootCause).
    inline Rule throttledRule(Durability durability, bool inRootCause = false)
    {
        return healthStatusRule(429, throttledBody(durability, inRootCause));
    }

    /// healthRule(@p status) that holds its answer until FakeIndexer::releaseHeld() (or stop()).
    inline Rule heldHealthRule(std::string_view status)
    {
        auto rule = healthRule(status);
        rule.hold = true;
        return rule;
    }

    /// Whether @p request is a health probe: GET whose path (query excluded) is exactly HEALTH_PATH.
    inline bool isProbe(const RecordedRequest& request)
    {
        return request.method == "GET" && request.path == HEALTH_PATH;
    }

    /// Health probes the fake has received (recorded on arrival, before any hold or latency).
    inline std::size_t probeCount(const FakeIndexer& fake)
    {
        std::size_t count {0};
        for (const auto& request : fake.requests())
        {
            if (isProbe(request))
            {
                ++count;
            }
        }
        return count;
    }

    /**
     * @brief Query string (without '?') of the last health probe received (the probe sends none).
     *
     * @return Empty string if that probe had no query; nothing if no probe arrived.
     */
    inline std::optional<std::string> lastProbeQuery(const FakeIndexer& fake)
    {
        const auto requests = fake.requests();
        for (auto it = requests.rbegin(); it != requests.rend(); ++it)
        {
            if (isProbe(*it))
            {
                const auto mark = it->target.find('?');
                return mark == std::string::npos ? std::string {} : it->target.substr(mark + 1);
            }
        }
        return std::nullopt;
    }

    /**
     * @brief Waits until probeCount(@p fake) >= @p count (polls every millisecond).
     *
     * @return Whether the count was reached within @p timeout.
     */
    inline bool waitForProbes(const FakeIndexer& fake, std::size_t count, std::chrono::milliseconds timeout)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (probeCount(fake) < count)
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return true;
    }
} // namespace indexer_client::testing

#endif // _INDEXER_CLIENT_TESTS_FAKE_HEALTH_RULES_HPP
