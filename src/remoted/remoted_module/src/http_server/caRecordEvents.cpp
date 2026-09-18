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

#include "caRecordEvents.hpp"

#include <system_error>
#include <utility>

namespace remoted::http
{
    namespace
    {
        /// Thread-safe rendering of an errno, the same text strerror() would give (see
        /// describeReadFailure() in fileRead.cpp for why this one and not strerror()).
        std::string causeOf(int error)
        {
            return std::generic_category().message(error);
        }

        /// "agents are told this manager has no published bundle (0)" -- the consequence every
        /// refusal shares, so each line below states what it means for an agent, not only what
        /// happened.
        constexpr auto UNPUBLISHED_CONSEQUENCE {"agents are told this manager has no published bundle (0)"};

        /// The line a refused guard deserves: which guard, the value it measured and its limit.
        /// These texts are the ones the transport's own switch used to emit before the publication
        /// moved to this mailbox (issue #39319, C21b), so what an operator greps for is unchanged.
        std::string describeGuard(const CaRecordEvent& event)
        {
            const std::string bundle {"The CA bundle '" + event.bundlePath + "'"};

            switch (event.guard)
            {
                case ca_bundle::GuardFailure::hash_mismatch:
                    return "The publication block of the CA bundle '" + event.bundlePath +
                           "' does not describe the certificates next to it (Content-SHA256 mismatch); the bundle is "
                           "served as before and announced as unpublished (0) until it is stamped again.";

                case ca_bundle::GuardFailure::no_ca_signs_leaf:
                    return bundle + " is not published because no CA signs the served leaf certificate; " +
                           UNPUBLISHED_CONSEQUENCE + ".";

                case ca_bundle::GuardFailure::too_many_certificates:
                    return bundle + " is not published because it carries " + std::to_string(event.observed) +
                           " certificates (max " + std::to_string(ca_bundle::kMaxCertificates) + "); " +
                           UNPUBLISHED_CONSEQUENCE + ".";

                case ca_bundle::GuardFailure::too_many_bytes:
                    return bundle + " is not published because what it would serve is " +
                           std::to_string(event.observed) + " bytes (max " +
                           std::to_string(ca_bundle::kMaxSerializedBytes) + "); " + UNPUBLISHED_CONSEQUENCE + ".";

                // Neither of these reaches a `guard_failed` event: `no_block` is the unpublished
                // bundle (its own kinds), `no_certificates` is nothing servable (no event at all)
                // and `none` did not refuse. Worded generically rather than silently dropped, so a
                // future guard cannot go unsaid.
                case ca_bundle::GuardFailure::none:
                case ca_bundle::GuardFailure::no_block:
                case ca_bundle::GuardFailure::no_certificates: break;
            }

            return bundle + " is not published; " + UNPUBLISHED_CONSEQUENCE + ".";
        }
    } // namespace

    void CaRecordEventMailbox::post(CaRecordEvent event)
    {
        std::lock_guard<std::mutex> lock {m_mutex};

        event.seq = ++m_seq;
        m_queue.push_back(std::move(event));

        // Full: the OLDEST goes. What matters to an operator is the state the bundle is in now, and
        // the drop is counted so the gap is never silent.
        while (m_queue.size() > kCapacity)
        {
            m_queue.pop_front();
            ++m_dropped;
        }
    }

    std::vector<CaRecordEvent> CaRecordEventMailbox::drain()
    {
        std::deque<CaRecordEvent> taken;
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            taken.swap(m_queue);
        }

        // Moved out of the lock before being handed over: the caller logs (and may persist) with
        // nothing of ours held.
        return std::vector<CaRecordEvent> {std::make_move_iterator(taken.begin()),
                                           std::make_move_iterator(taken.end())};
    }

    std::uint64_t CaRecordEventMailbox::dropped() const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        return m_dropped;
    }

    void CaRecordEventMailbox::deliver(const Emit& emit)
    {
        if (!emit)
        {
            // Nowhere to say it: the events stay queued for a consumer that can, rather than being
            // drained into nothing.
            return;
        }

        // The delivery mutex, taken OUTSIDE the queue's own (drain() takes that one): the drain and
        // the emission are one step, so two consumers cannot publish generation N after N+1
        // (objection 4). Nothing under this lock touches a disk, and the queue's lock is never held
        // while emit() runs, so a source posting on the hot path never waits for a logger.
        std::lock_guard<std::mutex> delivery {m_deliveryMutex};

        for (const auto& event : drain())
        {
            if (const auto line = describeRecordEvent(event))
            {
                emit(line->first, line->second);
            }
        }

        reportDrops(emit);
    }

    void CaRecordEventMailbox::reportDrops(const Emit& emit)
    {
        const auto drops = dropped();
        if (drops <= m_reportedDrops)
        {
            // dropped() only grows, so without this the same overflow would be re-announced by
            // every delivery for the rest of the listener's life.
            return;
        }

        if (!m_dropThrottle.record())
        {
            // Not this window's turn. m_reportedDrops is deliberately left alone, so the next
            // delivery inside the window still owes the line and the one after it says it -- a
            // suppressed drop report is postponed, never lost.
            return;
        }

        const auto unreported = drops - m_reportedDrops;
        m_reportedDrops = drops;

        // What an operator cannot get anywhere else: how much of the story above is missing. The
        // lines that DID come out describe the bundle's newest state (the oldest events are the
        // ones dropped), so this is about completeness, not about what agents are told now.
        emit(RecordEventLevel::warn,
             "Dropped " + std::to_string(unreported) + " CA bundle publication event(s) before they could be logged (" +
                 std::to_string(drops) + " since this listener started): the mailbox holds " +
                 std::to_string(kCapacity) +
                 " and the oldest go first, so some intermediate changes were not reported. The lines above describe "
                 "the bundle's current state, and 'GET /cacerts' still reports the generation in force.");
    }

    std::optional<std::pair<RecordEventLevel, std::string>> describeRecordEvent(const CaRecordEvent& event)
    {
        switch (event.kind)
        {
            case RecordEvent::none: return std::nullopt;

            case RecordEvent::published_changed:
                // Both values, always: "published as N" alone leaves the operator unable to tell a
                // first publication from a rotation, which is the one thing this line is for.
                return std::make_pair(RecordEventLevel::info,
                                      "CA bundle '" + event.bundlePath + "' is published as generation " +
                                          std::to_string(event.publication) + " (was " +
                                          std::to_string(event.previousPublication) +
                                          "); that is the generation agents asking this manager are told about.");

            case RecordEvent::first_time_unpublished:
                // A fresh node's ordinary state, not a problem: INFO, with the command that changes
                // it. Only ever said once per bundle, which is what the record buys us.
                return std::make_pair(RecordEventLevel::info,
                                      "Unpublished CA bundle at '" + event.bundlePath + "'; " +
                                          UNPUBLISHED_CONSEQUENCE +
                                          ". Publish it with `wazuh-manager-certs stamp` or `add` on the master.");

            case RecordEvent::changed_outside_tool:
                // The bundle was published and now is not: either rewritten by hand or its block
                // removed. WARN, and it names the publication that was lost so the operator can tell
                // this apart from a node that never had one.
                return std::make_pair(RecordEventLevel::warn,
                                      "CA bundle '" + event.bundlePath +
                                          "' changed outside the tool and is not published; previous publication " +
                                          std::to_string(event.previousPublication) + "; " + UNPUBLISHED_CONSEQUENCE +
                                          " until `wazuh-manager-certs stamp` is run on the master.");

            case RecordEvent::guard_failed: return std::make_pair(RecordEventLevel::warn, describeGuard(event));

            case RecordEvent::record_unwritable:
                // The RECORD's path, never the bundle's (they are different files and different
                // fixes), and the errno. Serving and vouching are unaffected by design (C19): the
                // publication in memory is the real one, this is about remembering it across a
                // restart.
                return std::make_pair(
                    RecordEventLevel::warn,
                    event.stored
                        ? "The CA bundle publication record at '" + event.recordPath +
                              "' was written but its directory could not be flushed (" + causeOf(event.error) +
                              "); the record is correct now, but a power loss could bring the previous one back."
                        : "Cannot persist the CA bundle publication record at '" + event.recordPath +
                              "': " + causeOf(event.error) +
                              "; the publication is kept in memory and the write is retried, so serving and vouching "
                              "are unaffected -- but a restart before it succeeds reports this bundle as seen for the "
                              "first time again.");
        }

        return std::nullopt;
    }
} // namespace remoted::http
