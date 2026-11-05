/*
 * Wazuh remoted module - test helper: the HTTP client for VD's socket
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_TEST_VD_HTTP_CLIENT_HPP
#define _REMOTED_TEST_VD_HTTP_CLIENT_HPP

#include "common/vdClient.hpp"
#include "downstream/asioUdsHttpClient.hpp"

#include <memory>

namespace remoted::test
{
    /// @brief A started client for VD's socket, configured as the facade configures it. VdClient and
    /// ScanVdHandlerImpl hold it, and its destructor stops it once the last of them is gone.
    inline std::shared_ptr<remoted::downstream::AsioUdsHttpClient> makeVdHttpClient()
    {
        auto client =
            std::make_shared<remoted::downstream::AsioUdsHttpClient>(remoted::common::VdClient::httpClientConfig());
        client->start();
        return client;
    }
} // namespace remoted::test

#endif // _REMOTED_TEST_VD_HTTP_CLIENT_HPP
