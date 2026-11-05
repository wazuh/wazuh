/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "blockingCall.hpp"

#include <future>
#include <utility>

namespace remoted::downstream
{

    BlockingResult sendBlocking(IDownstreamClient& client,
                                DownstreamRequest request,
                                std::shared_ptr<const void> bodyKeepAlive,
                                std::chrono::milliseconds backstop) noexcept
    {
        try
        {
            // The promise is owned by the callback alone -- moved into it, no copy left in this frame:
            // if the client destroys the callback without running it, the promise goes with it and
            // the future reports a broken promise instead of waiting forever. And if the backstop
            // gives up first, a late completion still has a live promise to set.
            auto promise = std::make_shared<std::promise<BlockingResult>>();
            auto future = promise->get_future();

            client.sendAsync(std::move(request),
                             std::move(bodyKeepAlive),
                             [promise = std::move(promise)](DownstreamError error, DownstreamResponse response)
                             { promise->set_value(BlockingResult {error, std::move(response)}); });

            if (future.wait_for(backstop) != std::future_status::ready)
            {
                return {};
            }
            return future.get();
        }
        catch (...)
        {
            // std::future_error (broken promise) or a failure inside sendAsync() itself.
            return {};
        }
    }

} // namespace remoted::downstream
