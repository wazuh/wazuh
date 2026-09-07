/*
 * Wazuh Syscheckd — the eBPF drain that feeds the container reconcile consumer
 * (#37532 / #37396).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Everything with a thread, a socket or a kernel in it. The decisions live in
 * the header-only pieces this drives — CgroupContainerMap, ContainerEventRouter,
 * ContainerEventStaging, ContainerReconcilePlan — precisely so that they are
 * testable and this is not.
 *
 * THREE threads, which deserves a justification since syscheckd is not short of
 * them:
 *
 *   drain     rt_poll() only. Must never block: an 8 MiB ring holds ~675
 *             12,416-byte records, about 2.4 s of a burst measured at 8,400
 *             events/s, and every kernel-side drop escalates a container to a
 *             full re-walk. It does one hash lookup per event and nothing else.
 *
 *   resolver  container_instances IPC. Its client's default timeout is 1 s —
 *             three orders of magnitude more than the drain can afford per
 *             event — so this cannot share the drain's thread. Even two
 *             resolves per poll cycle would risk 2 s of blocking against 2.4 s
 *             of ring capacity.
 *
 *   consumer  Re-reads files and re-walks containers, so it blocks on disk for
 *             as long as a walk takes. Folding it into the resolver would stall
 *             resolution for the length of a walk, during which every event
 *             from an unidentified cgroup keeps missing and the pending set
 *             fills — turning a slow walk into a whole-node re-baseline.
 *
 * The consumer starts PARKED and is released only after the baseline walk has
 * committed (see 12-blocking-decisions.md D5): a single-row upsert racing the
 * same container's open scoped transaction silently lost 502 of 504 rows on a
 * real node. The drain and resolver run from the start, so events that arrive
 * during the walk are staged rather than missed — that is the whole point of
 * subscribe-first.
 */

#ifndef _CONTAINER_EVENT_DRAIN_HPP
#define _CONTAINER_EVENT_DRAIN_HPP

#include "container_reconcile_plan.hpp"

#include <cstddef>
#include <functional>
#include <string>

namespace fim_container_events
{

struct DrainConfig
{
    /* Absolute path to rt_file.bpf.o. The engine falls back to a CWD-relative
     * lookup when this is empty, which is wrong for a daemonised agent whose CWD
     * is not its install directory — so the caller resolves it. */
    std::string bpf_object_path;

    /* container_instances IPC socket. */
    std::string connector_socket_path;

    std::size_t max_paths_per_container{4096};
    std::size_t max_containers{512};

    int poll_timeout_ms{200};
    int resolver_interval_ms{5000};

    /* D16's settle bound (12-blocking-decisions.md): how long a staged path is
     * held before it is re-read, when the pid that triggered it has not exited
     * first. RT_EV_FILE_OPEN fires BEFORE the write, so reconciling immediately
     * stores the pre-write file (C23).
     *
     * 500 ms because the common case does not use it at all — the writing pid is
     * usually already gone by the time the event is processed, which releases
     * the path immediately — so this only has to cover a burst held open by a
     * live writer. It is a bound, not a guarantee: a writer that outlives it is
     * still read mid-write, which no consumer-side option can prevent. */
    int settle_delay_ms{500};

    /* Resolves attempted per resolver cycle. Bounded because each one is its own
     * connect/send/recv/close against a 2-worker server. */
    std::size_t max_resolves_per_cycle{32};
};

/* Invoked on the consumer thread, once per batch, after release(). */
using ReconcileHandler = std::function<void(const ReconcileRequest&)>;

class ContainerEventDrain
{
    public:
        static ContainerEventDrain& instance();

        /* Opens the engine and starts the drain and resolver threads. Returns
         * false and changes nothing if the engine is unavailable, its ABI does
         * not match, or the host is cgroup v1 — all of which are degradations to
         * "no event-driven reconcile", never a reason to fail startup.
         *
         * The consumer thread starts here too, but parked. */
        bool start(const DrainConfig& config, ReconcileHandler handler);

        /* The baseline walk has committed; the consumer may now touch
         * file_entry. Safe to call when start() failed. */
        void release();

        /* Stops all three threads and closes the engine. Idempotent. */
        void stop();

        [[nodiscard]] bool running() const;

    private:
        ContainerEventDrain() = default;
        ~ContainerEventDrain();

        ContainerEventDrain(const ContainerEventDrain&) = delete;
        ContainerEventDrain& operator=(const ContainerEventDrain&) = delete;

        struct Impl;
        Impl* m_impl{nullptr};
};

} // namespace fim_container_events

#endif /* _CONTAINER_EVENT_DRAIN_HPP */
