/*
 * Wazuh remoted module - test helpers: the HTTP clients for VD's socket
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
#include "downstream/IDownstreamClient.hpp"
#include "downstream/asioUdsHttpClient.hpp"

#include <memory>
#include <string>
#include <utility>

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

    /// @brief Records the request it is handed and answers 200 with @p answer at once, without touching a
    /// socket: what the caller put on the request, not what the client's configuration would fill in.
    class CapturingClient final : public remoted::downstream::IDownstreamClient
    {
    public:
        explicit CapturingClient(std::string answer = "{}")
            : m_answer {std::move(answer)}
        {
        }

        void sendAsync(remoted::downstream::DownstreamRequest req,
                       std::shared_ptr<const void>,
                       remoted::downstream::DownstreamCallback onComplete) override
        {
            body = std::string {req.body};
            request = std::move(req);
            request.body = {};
            remoted::downstream::DownstreamResponse response;
            response.status = 200;
            response.body = m_answer;
            onComplete(remoted::downstream::DownstreamError::None, std::move(response));
        }

        remoted::downstream::DownstreamRequest request;
        std::string body;

    private:
        std::string m_answer;
    };
} // namespace remoted::test

#endif // _REMOTED_TEST_VD_HTTP_CLIENT_HPP
