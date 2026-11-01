/*
 * Wazuh shared UDS HTTP server library - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UDS_HTTP_SERVER_TEST_HOOKS_HPP
#define _UDS_HTTP_SERVER_TEST_HOOKS_HPP

#include <functional>

// Test-only seams. testHooks.cpp overrides the library's weak production defaults at link time, so
// they exist only in this test binary.
namespace wazuh::uds_http::test_hooks
{
    /**
     * @brief Called on the session strand when an interim "100 Continue" is about to be written.
     *
     * The argument starts the write; it posts back onto the session strand, so it may be called from
     * any thread. A hook that keeps it and calls it later holds the interim write in flight -- the
     * window in which a final response must be parked rather than written. A hook must eventually call
     * it: the session stays alive and unanswered until then.
     */
    using InterimWriteHook = std::function<void(std::function<void()> startWrite)>;

    /// Installs @p hook for every server in the process; an empty hook restores the immediate write.
    void setInterimWriteHook(InterimWriteHook hook);
} // namespace wazuh::uds_http::test_hooks

#endif // _UDS_HTTP_SERVER_TEST_HOOKS_HPP
