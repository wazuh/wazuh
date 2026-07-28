/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "IDownstreamClient.hpp"

namespace remoted::downstream
{

    const char* toString(DownstreamError error)
    {
        switch (error)
        {
            case DownstreamError::None: return "none";
            case DownstreamError::Connect: return "connect_failed";
            case DownstreamError::ConnectTimeout: return "connect_timeout";
            case DownstreamError::WriteTimeout: return "write_timeout";
            case DownstreamError::ResponseTimeout: return "response_timeout";
            case DownstreamError::Transport: return "transport_error";
            case DownstreamError::Protocol: return "protocol_error";
            case DownstreamError::ResponseTooLarge: return "response_too_large";
        }
        return "unknown";
    }

} // namespace remoted::downstream
