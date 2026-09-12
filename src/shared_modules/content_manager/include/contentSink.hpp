/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTENT_SINK_HPP
#define _CONTENT_SINK_HPP

#include "contentTypes.hpp"
#include <string>

namespace content_manager
{

/**
 * @brief Where downloaded content goes, and who decides it is safe to keep.
 *
 * One instance per registered topic. The library drives it through exactly one sequence per cycle:
 *
 * @code
 *   beginSession(info)
 *     -> Proceed : acceptPage(page)*  then  commit(info)   [or abort(...) if the fetch failed]
 *     -> Skip    : nothing else is called; the stored token is untouched
 *     -> Abort   : nothing else is called; the stored token is untouched
 * @endcode
 *
 * `acceptPage` is called from at most one thread at a time even when the fetch is sliced — the
 * paginator serialises it — but it is not necessarily the *same* thread across calls, so a sink
 * whose state is thread-affine must not assume one.
 *
 * ### Why everything is `noexcept`
 *
 * A sink can live in a different DSO from the library that calls it, compiled against a different
 * libstdc++ (the Engine statically links its own). RTTI unification for `std::exception`
 * derivatives is not guaranteed across that boundary, so an exception thrown here and caught there
 * is undefined behaviour. Report failure through the return value instead: `PageStatus::Reject`,
 * `CommitStatus::Rejected*`, or `SessionDecision::Abort`. The library additionally wraps every call
 * in a `catch (...)` on its own side, but that is a backstop, not a licence to throw.
 */
class IContentSink
{
public:
    virtual ~IContentSink() = default;

    /**
     * @brief Announce a cycle and ask whether to run it.
     *
     * A `NoChange` session is still announced: a sink that needs to act on every cycle regardless of
     * whether the source moved (writing a readiness sentinel, notifying an observer) does it here
     * and returns `Proceed`; one that does not returns `Skip`.
     *
     * @param info Description of the cycle about to start.
     * @return Whether to proceed, skip or abort.
     */
    virtual SessionDecision beginSession(const SessionInfo& info) noexcept = 0;

    /**
     * @brief Consume one page of source documents.
     *
     * Return `PageStatus::Durable` only when everything up to and including `page.pageToken` is on
     * stable storage: the library persists that token immediately, and a crash right after must
     * resume correctly from it.
     *
     * @param page Page of raw hits. `page.hits` is only valid for the duration of this call.
     * @return How far the sink got with the page.
     */
    virtual PageAck acceptPage(const ContentPage& page) noexcept = 0;

    /**
     * @brief Promote everything accepted during this session.
     *
     * @param info Summary of the session.
     * @return Whether the content is live, and what should happen to the token.
     */
    virtual CommitResult commit(const CommitInfo& info) noexcept = 0;

    /**
     * @brief Discard everything accepted during this session.
     *
     * Called instead of `commit` when the cycle could not be completed. The sink must release any
     * staging resource it allocated in `beginSession`.
     *
     * @param reason Why the session was abandoned.
     * @param detail Human-readable context, safe to log.
     */
    virtual void abort(AbortReason reason, const std::string& detail) noexcept = 0;
};

} // namespace content_manager

#endif // _CONTENT_SINK_HPP
