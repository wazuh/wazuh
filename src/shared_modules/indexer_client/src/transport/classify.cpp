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

#include "transport/classify.hpp"

namespace indexer_client::detail
{
    const char* toString(TransportCause cause) noexcept
    {
        switch (cause)
        {
            case TransportCause::None: return "none";
            case TransportCause::Timeout: return "timeout";
            case TransportCause::Connect: return "connect";
            case TransportCause::SendError: return "send_error";
            case TransportCause::RecvError: return "recv_error";
            case TransportCause::PartialResponse: return "partial_response";
            case TransportCause::ResponseTooLarge: return "response_too_large";
            case TransportCause::LocalError: return "local_error";
            case TransportCause::Cancelled: return "cancelled";
            case TransportCause::Shutdown: return "shutdown";
        }
        return "unknown";
    }

    bool nodeAttributable(TransportCause cause) noexcept
    {
        switch (cause)
        {
            case TransportCause::Timeout:
            case TransportCause::Connect:
            case TransportCause::SendError:
            case TransportCause::RecvError:
            case TransportCause::PartialResponse: return true;
            default: return false;
        }
    }

    // Numeric CURLcode values (curl 8.20, include/curl/curl.h) so that this table needs no curl header.
    TransportCause classifyCurlCode(int curlCode, bool capTripped) noexcept
    {
        switch (curlCode)
        {
            case 0: return TransportCause::None;             // CURLE_OK
            case 28: return TransportCause::Timeout;         // CURLE_OPERATION_TIMEDOUT
            case 6:                                          // CURLE_COULDNT_RESOLVE_HOST
            case 7: return TransportCause::Connect;          // CURLE_COULDNT_CONNECT
            case 55: return TransportCause::SendError;       // CURLE_SEND_ERROR
            case 52:                                         // CURLE_GOT_NOTHING
            case 56: return TransportCause::RecvError;       // CURLE_RECV_ERROR
            case 18: return TransportCause::PartialResponse; // CURLE_PARTIAL_FILE
            case 23:                                         // CURLE_WRITE_ERROR: ours only if the cap fired
                return capTripped ? TransportCause::ResponseTooLarge : TransportCause::LocalError;
            default: return TransportCause::LocalError; // 2, 27 and everything else
        }
    }
} // namespace indexer_client::detail
