/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "httpResultMapper.hpp"

#include <json.hpp>

namespace
{
    /// @brief Parse a body that may be absent, truncated or malformed. All three are the same
    ///        thing to the caller: no detail available.
    nlohmann::json parseBody(const std::string& body)
    {
        if (body.empty())
        {
            return nlohmann::json {};
        }
        return nlohmann::json::parse(body, nullptr, false); // never throws; yields discarded
    }

    std::string detailFrom(const nlohmann::json& parsed)
    {
        if (parsed.is_discarded() || !parsed.is_object())
        {
            return "no detail";
        }

        const auto it {parsed.find("error")};
        if (it == parsed.end() || !it->is_string())
        {
            return "no detail";
        }
        return it->get<std::string>();
    }

    bool bodySaysRetryable(const nlohmann::json& parsed)
    {
        if (parsed.is_discarded() || !parsed.is_object())
        {
            return false;
        }

        const auto it {parsed.find("retryable")};
        return it != parsed.end() && it->is_boolean() && it->get<bool>();
    }
} // namespace

namespace task_manager::registry
{
    HandlerResult classifyTransportResult(const TransportResult& result, const bool allowTerminalFailure)
    {
        if (result.returnCode == 0)
        {
            return HandlerResult::ok();
        }

        // The "request was never sent" sentinel: a return of -1 with the result struct untouched.
        // It fires only on LOCAL error paths -- a null client, null data with a positive length, a
        // failed setopt -- so it is a dispatcher bug, not a consumer that is down. Telling it apart
        // from -CURLE_UNSUPPORTED_PROTOCOL is safe only because the URL and socket are fixed
        // constants, and only because the caller zero-initialises the struct.
        if (result.returnCode == -1 && result.curlCode == 0 && result.httpStatus == 0)
        {
            return HandlerResult::of(Outcome::Terminal, "request was never sent (dispatcher bug)");
        }

        if (result.returnCode < 0)
        {
            switch (-result.returnCode)
            {
                case CURLE_COULDNT_CONNECT_CODE:
                    // The socket is missing, or present with nothing listening. Classifying this
                    // as a generic transport error would burn the whole retry budget on a boot
                    // race that resolves in seconds.
                    return HandlerResult::of(Outcome::NotReady, "consumer not listening");

                case CURLE_OPERATION_TIMEDOUT_CODE:
                    return HandlerResult::of(Outcome::Timeout, "consumer did not answer before the deadline");

                default:
                    // Everything else reachable over a Unix socket is mid-transfer: RECV_ERROR,
                    // SEND_ERROR or GOT_NOTHING, i.e. the peer died with the request in flight.
                    return HandlerResult::of(Outcome::Retryable,
                                             "transport error " + std::to_string(-result.returnCode));
            }
        }

        const auto parsed = parseBody(result.body);

        if (result.returnCode == 409)
        {
            // Busy whatever the body says, INCLUDING when there is no readable body at all.
            return HandlerResult::of(Outcome::Busy, "consumer busy: " + detailFrom(parsed));
        }

        Outcome outcome {Outcome::Retryable};

        if (result.returnCode >= 500 || result.returnCode == 408 || result.returnCode == 429)
        {
            outcome = Outcome::Retryable;
        }
        else if (result.returnCode >= 400)
        {
            // A 4xx is the consumer saying the request itself is wrong. For a type carrying an
            // obligation nobody will raise again, that is a dispatcher bug or a transient
            // misconfiguration, and neither is a reason to abandon the work.
            outcome = allowTerminalFailure ? Outcome::Terminal : Outcome::Retryable;
        }
        else
        {
            // A non-2xx that is neither 4xx nor 5xx. The transport only reports a status here when
            // the call was not a success, so this is a redirect or something equally unexpected on
            // a local socket.
            outcome = Outcome::Retryable;
        }

        // A consumer may declare a failure worth retrying even when its status suggests otherwise.
        if (outcome == Outcome::Terminal && bodySaysRetryable(parsed))
        {
            outcome = Outcome::Retryable;
        }

        return HandlerResult::of(outcome, "HTTP " + std::to_string(result.returnCode) + ": " + detailFrom(parsed));
    }
} // namespace task_manager::registry
