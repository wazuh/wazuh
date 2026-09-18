/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 18, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_CA_RECORD_EVENTS_HPP
#define _REMOTED_HTTP_SERVER_CA_RECORD_EVENTS_HPP

/**
 * @file caRecordEvents.hpp
 * @brief What changed about the CA bundle's publication, as a value -- plus the bounded mailbox it
 *        waits in until someone with a logger takes it, and the one function that words it.
 *
 * The bundle's publication is noticed by the reader (CaCertificateSource) and it has to be SAID by
 * whoever owns a log function: the transport at start and on the daily tick, and the `GET /cacerts`
 * handler before it answers. Handing the verdict around inside the snapshot did not work (issue
 * #39319): a cached snapshot repeats its own event on every read, clearing it on read loses it for
 * the next caller, and a counter of "the last one logged" drops events generated out of order and
 * survives a stop()/start() that legitimately starts a new source.
 *
 * So the event is a value that is POSTED once and DRAINED once. The mailbox is created with the
 * source and lives exactly as long as it (a restart gets a new, empty one), post() is O(1) under
 * its OWN mutex -- never the source's hot-path mutex, which is why the source may post while
 * holding it -- and drain() returns what is queued, in order, and removes it. Whoever drains logs
 * it; nobody else will see it again. A guard that starts failing halfway through a day is
 * therefore visible in the very next request instead of at the next tick.
 *
 * describeRecordEvent() is PURE, and neither this header nor its .cpp pulls the module's logger
 * header in: Log::GLOBAL_LOG_FUNCTION has hidden visibility and only the .so defines it, so a
 * header that drags the logger along fails to link into the separately-linked test binary (the
 * same hard constraint common/logThrottle.hpp documents). The wording lives here, in one place,
 * and every one of the three call sites emits it identically.
 */

#include "ca_bundle/ca_bundle.hpp" // ca_bundle::GuardFailure

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace remoted::http
{
    /**
     * @brief What happened to the bundle's publication, from the record's point of view.
     *
     * Six values, and the four guards of ca_bundle::GuardFailure travel as DATA inside
     * `guard_failed` rather than as four kinds of their own (C25): to an operator they are one
     * question -- why is this bundle not published -- and to the log they are one line.
     */
    enum class RecordEvent
    {
        none,                   ///< Nothing to say: the publication is what the record already held.
        published_changed,      ///< A vouched bundle whose publication differs from the recorded one.
        first_time_unpublished, ///< A servable bundle with no publication block, and no record of it before.
        changed_outside_tool,   ///< The bundle lost its block or its bytes changed without the tool.
        guard_failed,           ///< A block is there but a guard refused to vouch for it.
        record_unwritable       ///< The record itself could not be persisted (or not durably so).
    };

    /**
     * @brief One thing to say about the bundle's publication, complete enough to be worded without
     *        asking anyone else anything.
     *
     * Both paths travel (the bundle's and the record's: a failure to persist must name the RECORD,
     * not the bundle) and both publications travel (the new one and the one the record held), so a
     * line can say "publication N (was M)" rather than half of it.
     */
    struct CaRecordEvent
    {
        RecordEvent kind {RecordEvent::none};
        std::string bundlePath;               ///< The CA bundle this is about (remote.https.ca_certificate).
        std::string recordPath;               ///< The publication record's own path; empty when there is none.
        std::int64_t previousPublication {0}; ///< What the record held before this event; 0 when it held nothing.
        std::int64_t publication {0};         ///< The publication now in effect; 0 means "not published".
        ca_bundle::GuardFailure guard {ca_bundle::GuardFailure::none}; ///< Which guard refused, for `guard_failed`.
        /// The value that guard measured, so the line names it: the certificate count for
        /// `too_many_certificates`, the serialised size for `too_many_bytes`, 0 for every other guard
        /// (whose refusal has nothing to count).
        std::size_t observed {0};
        int error {0}; ///< errno behind `record_unwritable`; 0 otherwise.
        /// `record_unwritable` only: false when nothing was written (the ordinary failure), true when
        /// the entry did land on the path but its directory could not be flushed -- the record is
        /// correct right now, only its survival across a power loss is uncertain.
        bool stored {false};
        std::uint64_t seq {0}; ///< Order of posting within one mailbox, assigned by post(). 1 for the first.
    };

    /**
     * @brief The bounded queue an event waits in between being noticed and being logged.
     *
     * Its own mutex, on purpose: the source posts while holding the mutex that guards its cached
     * snapshot, so this lock is always taken INSIDE that one and never the other way round. Bounded
     * to kCapacity because a mailbox nobody drains must not grow without limit; past it the OLDEST
     * event is dropped (the newest state of the bundle is the one worth saying) and the drop is
     * counted, so silence is never mistaken for "nothing happened".
     *
     * Thread-safe. Created with the source it belongs to: a stop()/start() gets a new one, which is
     * what keeps a previous listener's already-logged events from suppressing this one's.
     */
    class CaRecordEventMailbox final
    {
    public:
        /// How many undrained events are kept. No real sequence of events reaches this: it is the
        /// bound that makes an undrained mailbox harmless, not a working queue depth.
        static constexpr std::size_t kCapacity {32};

        /// Queues @p event, stamping its `seq`. O(1); drops the oldest when full.
        void post(CaRecordEvent event);

        /// Everything queued, in posting order, removed from the mailbox: a second call returns
        /// nothing new. This is what makes each event come out exactly once, at exactly one caller.
        std::vector<CaRecordEvent> drain();

        /// How many events were dropped because the mailbox was full. Only grows.
        std::uint64_t dropped() const;

    private:
        mutable std::mutex m_mutex;
        std::deque<CaRecordEvent> m_queue;
        std::uint64_t m_seq {0};
        std::uint64_t m_dropped {0};
    };

    /// How loud an event's line is. Deliberately not the module logger's own level type, so this
    /// header stays logger-free; the caller maps it to an INFO or a WARN of its own.
    enum class RecordEventLevel
    {
        info,
        warn
    };

    /**
     * @brief @p event as the line to log, or `nullopt` when there is nothing to say.
     *
     * Pure: no logging, no file access, no clock. `none` is the only kind that yields nothing --
     * every other one is an operator-visible change of what agents are told, and the text names the
     * path it is about, the value that decided it and the remedy where there is one.
     */
    std::optional<std::pair<RecordEventLevel, std::string>> describeRecordEvent(const CaRecordEvent& event);
} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_CA_RECORD_EVENTS_HPP
