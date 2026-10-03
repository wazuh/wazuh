/*
 * Wazuh indexer client
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "indexer_client/types.hpp"

namespace indexer_client
{
    const char* toString(Cause cause) noexcept
    {
        switch (cause)
        {
            case Cause::None: return "none";
            case Cause::TransportTimeout: return "transport_timeout";
            case Cause::TransportConnect: return "transport_connect";
            case Cause::TransportTls: return "transport_tls";
            case Cause::Throttled: return "throttled";
            case Cause::PayloadTooLarge: return "payload_too_large";
            case Cause::Server5xx: return "server_5xx";
            case Cause::Client4xx: return "client_4xx";
            case Cause::ItemRetryable: return "item_retryable";
            case Cause::ItemPermanent: return "item_permanent";
            case Cause::VersionConflict: return "version_conflict";
            case Cause::Unavailable: return "unavailable";
            case Cause::QueueFull: return "queue_full";
            case Cause::SubmitTimeout: return "submit_timeout";
            case Cause::WaitTimeout: return "wait_timeout";
            case Cause::GroupTooLarge: return "group_too_large";
            case Cause::RetryExhausted: return "retry_exhausted";
            case Cause::Shutdown: return "shutdown";
            case Cause::ClientClosed: return "client_closed";
            case Cause::Cancelled: return "cancelled";
            case Cause::Reentrancy: return "reentrancy";
            case Cause::PitExpired: return "pit_expired";
            case Cause::PitStaleGeneration: return "pit_stale_generation";
            case Cause::NotFound: return "not_found";
            case Cause::InvalidConfig: return "invalid_config";
            case Cause::InvalidArgument: return "invalid_argument";
            case Cause::InvalidState: return "invalid_state";
            case Cause::UsageError: return "usage_error";
        }
        return "unknown";
    }
} // namespace indexer_client
