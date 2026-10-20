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

#ifndef _INDEXER_CLIENT_SEAMS_HPP
#define _INDEXER_CLIENT_SEAMS_HPP

// Test seams (I45b). In the production objects (the .so) every seam is an empty inline function and nothing of the
// test machinery is compiled; with INDEXER_CLIENT_TESTING (the static library the component suite links) they call
// the hooks of src/testing/seams.cpp. VisibilityTest checks that the .so carries none of them.

#include <cstdint>
#include <optional>

#include <sys/types.h>

namespace indexer_client::detail::seams
{
#ifdef INDEXER_CLIENT_TESTING
    void afterAdmissionCheck();   ///< Between the admission check and the post.
    int injectMultiError(int rc); ///< Replaces curl_multi_socket_action's result.
    void throwOnAdd();            ///< Before curl_multi_add_handle.
    void beforeRetryAfterParse(); ///< On the CPU pool, before parsing Retry-After.
    void onTimerHandler(std::uint64_t generation, std::uint64_t current); ///< Every timer handler run.
    std::optional<int> openSocket();                                      ///< CURL_SOCKET_BAD forces a connect failure.
    void onRuntimeThreadStart(pid_t tid);                                 ///< Each runtime thread, at start.
    void onPostRejected();                                                ///< A post refused by a closed loop.
#else
    // always_inline: even at -O0 no out-of-line copy is emitted, so the .so carries no seams:: symbol (VisibilityTest).
    [[gnu::always_inline]] inline void afterAdmissionCheck() {}
    [[gnu::always_inline]] inline int injectMultiError(int rc)
    {
        return rc;
    }
    [[gnu::always_inline]] inline void throwOnAdd() {}
    [[gnu::always_inline]] inline void beforeRetryAfterParse() {}
    [[gnu::always_inline]] inline void onTimerHandler(std::uint64_t, std::uint64_t) {}
    [[gnu::always_inline]] inline std::optional<int> openSocket()
    {
        return std::nullopt;
    }
    [[gnu::always_inline]] inline void onRuntimeThreadStart(pid_t) {}
    [[gnu::always_inline]] inline void onPostRejected() {}
#endif
} // namespace indexer_client::detail::seams

#endif // _INDEXER_CLIENT_SEAMS_HPP
