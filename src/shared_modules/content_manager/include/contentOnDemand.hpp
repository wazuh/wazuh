/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTENT_ON_DEMAND_HPP
#define _CONTENT_ON_DEMAND_HPP

#include "contentTypes.hpp"

#include <cstdint>
#include <functional>
#include <string>

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

namespace content_manager
{

/**
 * @brief Outcome of an on-demand update request.
 *
 * Deliberately transport-neutral: the library has no opinion on HTTP. The vulnerability scanner
 * maps these onto its `POST /ondemand` status codes (200/404/409/500/503) next to the route it
 * serves; the Engine maps the same values onto its own `httpsrv::Server` routes.
 */
enum class OnDemandCode : std::uint8_t
{
    Completed,    ///< The update ran to completion.
    UnknownTopic, ///< No such registered topic.
    AlreadyRunning, ///< An update for that topic was already in progress; this one was not run.
    QueueFull,    ///< The bounded lane has no free slot. Retryable.
    ShuttingDown, ///< The lane is stopping. Retryable.
    Failed        ///< The update ran and failed.
};

/**
 * @brief Result of an on-demand update request.
 */
struct OnDemandResult
{
    OnDemandCode code {OnDemandCode::Completed}; ///< Outcome class.
    std::string detail;                          ///< Human-readable context, safe to log or return.
};

/**
 * @brief Queue one on-demand content update.
 *
 * Never blocks: the request is either rejected inline (unknown topic, lane full, shutting down) or
 * queued on a short bounded lane and run by one of its workers. Safe to call from a transport I/O
 * thread.
 *
 * @param topic Registered content topic.
 * @param req What the update should do. `RunRequest::onDemand` is forced to true.
 * @param completion Invoked exactly once with the outcome — inline for an inline rejection, on a
 *                   lane worker otherwise. May be empty for fire-and-forget.
 */
EXPORTED void
requestOnDemand(const std::string& topic, RunRequest req, std::function<void(OnDemandResult)> completion) noexcept;

} // namespace content_manager

#endif // _CONTENT_ON_DEMAND_HPP
