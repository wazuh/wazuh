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

#ifndef _INDEXER_CLIENT_RUNTIME_HPP
#define _INDEXER_CLIENT_RUNTIME_HPP

#include <cstdarg>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "client.hpp"
#include "iConfigSource.hpp"
#include "runtimeConfig.hpp"
#include "types.hpp"

namespace indexer_client
{
    namespace detail
    {
        struct RuntimeState;
    } // namespace detail

    /// Non-owning reference to the process runtime; valid until RuntimeOwner::shutdown() (I37). A reference taken from
    /// a previous runtime stays invalid after a restart.
    class INDEXER_CLIENT_API RuntimeRef final
    {
    public:
        RuntimeRef() = default;
        explicit RuntimeRef(std::weak_ptr<detail::RuntimeState> state, std::uint64_t epoch);

        /// Validates every BucketSpec (RF-2); Cause::InvalidArgument names the offending field.
        Outcome<std::shared_ptr<Client>> client(std::string_view consumer, std::vector<BucketSpec> buckets) const;
        MetricsSnapshot snapshot() const;
        std::optional<TimePoint> shutdownDeadline() const;
        bool valid() const;

    private:
        std::weak_ptr<detail::RuntimeState> m_state;
        std::uint64_t m_epoch {0};
    };

    /// The single owner of the process runtime (I37). All calls must come from the owner thread (the one that called
    /// start()); from any other thread they return Cause::UsageError.
    class INDEXER_CLIENT_API RuntimeOwner final
    {
    public:
        /// Creates K network threads and M CPU threads with every asynchronous signal blocked, then restores the
        /// calling thread's mask. A second start() while running is Cause::InvalidState and leaves the running runtime
        /// intact. An invalid configuration fails without leaving any thread behind.
        static Outcome<RuntimeRef> start(ProcessId process, const IConfigSource& source);

        /// Fixes the single shutdown deadline; later calls are ignored (the first deadline wins).
        static Cause beginShutdown(TimePoint deadline);

        /// Joins every runtime thread. A second call is a no-op (Cause::None). From a runtime thread:
        /// Cause::UsageError.
        static Cause shutdown();

        static bool running();
    };

    /// The process's log function, with the same signature indexer_connector takes (level, tag, file, line, function,
    /// format, arguments). Replaces the previous one; an empty function silences the library. Valid only while no
    /// runtime is running (before RuntimeOwner::start() or after shutdown()): with a runtime running the call is
    /// ignored and counted as a usage error (I56).
    using LogFunction =
        std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>;
    INDEXER_CLIENT_API void setLogFunction(LogFunction logFunction);

    namespace detail::testing
    {
        /// Test seams: run a task on a CPU-pool thread / on a network thread. False if the runtime is not running.
        INDEXER_CLIENT_API bool postToPool(std::function<void()> task);
        INDEXER_CLIENT_API bool postToIoLoop(std::function<void()> task, std::uint32_t loopIndex = 0);
        /// True on any runtime thread (the flag RF-27 relies on).
        INDEXER_CLIENT_API bool onRuntimeThread();
        /// Process-wide count of usage errors the library detected and survived (e.g. a Client destroyed on a
        /// runtime thread: logged, counted, closed without waiting; never an abort, not even in debug builds).
        INDEXER_CLIENT_API std::uint64_t usageErrors();
    } // namespace detail::testing
} // namespace indexer_client

#endif // _INDEXER_CLIENT_RUNTIME_HPP
