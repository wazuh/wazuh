/*
 * Wazuh Indexer Connector - health-probe test doubles
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _HEALTH_BODY_HPP
#define _HEALTH_BODY_HPP

#include "mocks/MockHTTPRequest.hpp"
#include <exception>
#include <string>
#include <variant>

/*
 * HEADER-ONLY ON PURPOSE: tests/unit/CMakeLists.txt globs the sources with
 * `file(GLOB SOURCES *.cpp)` and no CONFIGURE_DEPENDS, so a new .cpp here would be invisible to an
 * already-configured build tree. A header is picked up by the compiler, not by the glob.
 *
 * It is also the SINGLE PLACE that knows the shape of a /_cat/health answer. Every test that needs
 * one builds it through healthBody()/healthBodyWithoutStatus(), so a change of probe endpoint --
 * and with it, of the response shape -- is one edit here instead of 33 scattered literals.
 */
namespace probe_test
{
    /**
     * @brief The body of a successful health probe, parameterized by cluster status.
     *
     * @param status Cluster status to report ("green", "yellow", "red", ...).
     * @param extraFields Optional extra JSON fields, written as a leading-comma fragment
     *                    (e.g. `R"(,"cluster":"test")"`).
     * @return The response body the indexer would send.
     */
    inline std::string healthBody(const std::string& status, const std::string& extraFields = "")
    {
        return R"([{"status":")" + status + R"(")" + extraFields + "}]";
    }

    /**
     * @brief A successful health probe answer that carries no status field at all.
     *
     * Same shape as healthBody(), minus the one field the monitor reads: the input for the
     * "the probe answered, but not with what we parse" path.
     *
     * @return The response body the indexer would send.
     */
    inline std::string healthBodyWithoutStatus()
    {
        return R"([{"cluster":"test","node.total":"1"}])";
    }

    /// A canned health-check answer: 200 goes to onSuccess with the body, anything else to onError.
    struct ProbeAnswer
    {
        long statusCode;
        std::string body;
    };

    inline const ProbeAnswer GREEN {200, healthBody("green")};
    inline const ProbeAnswer UNAVAILABLE {503, ""};
    inline const ProbeAnswer BREAKER {
        429,
        R"({"error":{"root_cause":[{"type":"circuit_breaking_exception","reason":"[parent] Data too large",)"
        R"("durability":"TRANSIENT"}],"type":"circuit_breaking_exception","reason":"[parent] Data too large",)"
        R"("durability":"TRANSIENT"},"status":429})"};
    inline const ProbeAnswer PERMANENT_BREAKER {
        429,
        R"({"error":{"type":"circuit_breaking_exception","reason":"[parent] Data too large",)"
        R"("durability":"PERMANENT"},"status":429})"};

    /// What HTTPRequest reports as the status code when the failure was not an HTTP one
    /// (`NOT_USED` in src/shared_modules/http-request/src/urlRequest.hpp).
    constexpr long NO_HTTP_STATUS {-1};

    /// What HTTPRequest puts in the error body when the success callback itself threw
    /// (`INTERNAL_ERROR_MESSAGE` in src/shared_modules/http-request/src/HTTPRequest.cpp).
    inline const std::string INTERNAL_ERROR_BODY {"Internal error in HTTPRequest module."};

    /**
     * @brief Feeds a canned answer to a mocked HTTP request the way HTTPRequest::get would.
     *
     * The emulated part that matters is the error funnel: HTTPRequest::get wraps the whole request
     * -- the onSuccess call included -- in try/catch and turns any std::exception escaping it into
     * `onError(ex.what(), NOT_USED, INTERNAL_ERROR_MESSAGE)`
     * (src/shared_modules/http-request/src/HTTPRequest.cpp:239-289). A bare MOCK_METHOD does not:
     * an exception thrown by the monitor's parser would propagate out of get(), out of the
     * constructor and into the test, which is a behaviour production never exhibits. Anything
     * asserted through this helper is therefore asserted against the real contract.
     *
     * @param postParams The mock's post-request parameter variant.
     * @param probeAnswer The answer to deliver.
     */
    template<typename TPostParams>
    void answer(const TPostParams& postParams, const ProbeAnswer& probeAnswer)
    {
        if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
        {
            const auto& params = std::get<TPostRequestParameters<const std::string&>>(postParams);
            if (probeAnswer.statusCode != 200)
            {
                params.onError("Client error", probeAnswer.statusCode, probeAnswer.body);
                return;
            }
            try
            {
                params.onSuccess(probeAnswer.body);
            }
            catch (const std::exception& ex)
            {
                params.onError(ex.what(), NO_HTTP_STATUS, INTERNAL_ERROR_BODY);
            }
        }
        else
        {
            const auto& params = std::get<TPostRequestParameters<std::string&&>>(postParams);
            if (probeAnswer.statusCode != 200)
            {
                params.onError("Client error", probeAnswer.statusCode, probeAnswer.body);
                return;
            }
            try
            {
                params.onSuccess(std::string {probeAnswer.body});
            }
            catch (const std::exception& ex)
            {
                params.onError(ex.what(), NO_HTTP_STATUS, INTERNAL_ERROR_BODY);
            }
        }
    }
} // namespace probe_test

#endif // _HEALTH_BODY_HPP
