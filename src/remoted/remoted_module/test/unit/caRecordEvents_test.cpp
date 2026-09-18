/*
 * Wazuh remoted module - CA bundle record events (mailbox + wording) unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 18, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Two things, kept apart from CaCertificateSource on purpose: describeRecordEvent() is PURE (no
 * logger, no clock, no file), so every line it can produce is pinned here from a CaRecordEvent
 * built by hand; CaRecordEventMailbox is a plain bounded queue, tested without any of the source's
 * hot-path machinery around it.
 */

#include <gtest/gtest.h>

#include "ca_bundle/ca_bundle.hpp"
#include "http_server/caRecordEvents.hpp"

#include <cstdint>
#include <future>
#include <optional>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

using remoted::http::CaRecordEvent;
using remoted::http::CaRecordEventMailbox;
using remoted::http::describeRecordEvent;
using remoted::http::RecordEvent;
using remoted::http::RecordEventLevel;

TEST(DescribeRecordEvent, FirstTimeUnpublishedNamesTheRemedy)
{
    CaRecordEvent event;
    event.kind = RecordEvent::first_time_unpublished;
    event.bundlePath = "/var/wazuh-manager/etc/certs/root-ca.pem";

    const auto line = describeRecordEvent(event);
    ASSERT_TRUE(line.has_value());
    EXPECT_EQ(line->first, RecordEventLevel::info);
    EXPECT_NE(line->second.find(event.bundlePath), std::string::npos) << line->second;
    EXPECT_NE(line->second.find("wazuh-manager-certs stamp"), std::string::npos) << line->second;
    EXPECT_NE(line->second.find("add"), std::string::npos) << line->second;
}

TEST(DescribeRecordEvent, ChangedOutsideToolNamesThePreviousPublication)
{
    CaRecordEvent event;
    event.kind = RecordEvent::changed_outside_tool;
    event.bundlePath = "/var/wazuh-manager/etc/certs/root-ca.pem";
    event.previousPublication = 1789000000;

    const auto line = describeRecordEvent(event);
    ASSERT_TRUE(line.has_value());
    EXPECT_EQ(line->first, RecordEventLevel::warn);
    EXPECT_NE(line->second.find(event.bundlePath), std::string::npos) << line->second;
    EXPECT_NE(line->second.find("previous publication 1789000000"), std::string::npos) << line->second;
}

TEST(DescribeRecordEvent, RecordFailureNamesRecordPath)
{
    // The ordinary failure: nothing landed, retried on the next call.
    {
        CaRecordEvent event;
        event.kind = RecordEvent::record_unwritable;
        event.bundlePath = "/var/wazuh-manager/etc/certs/root-ca.pem";
        event.recordPath = "/var/wazuh-manager/var/run/remoted-ca-bundle/record.json";
        event.error = EACCES;
        event.stored = false;

        const auto line = describeRecordEvent(event);
        ASSERT_TRUE(line.has_value());
        EXPECT_EQ(line->first, RecordEventLevel::warn);
        EXPECT_NE(line->second.find(event.recordPath), std::string::npos) << line->second;
        EXPECT_EQ(line->second.find(event.bundlePath), std::string::npos) << line->second; // never the bundle
        EXPECT_NE(line->second.find(std::generic_category().message(EACCES)), std::string::npos) << line->second;
    }

    // The uncertain-durability variant: written, but the directory's fsync failed.
    {
        CaRecordEvent event;
        event.kind = RecordEvent::record_unwritable;
        event.bundlePath = "/var/wazuh-manager/etc/certs/root-ca.pem";
        event.recordPath = "/var/wazuh-manager/var/run/remoted-ca-bundle/record.json";
        event.error = EIO;
        event.stored = true;

        const auto line = describeRecordEvent(event);
        ASSERT_TRUE(line.has_value());
        EXPECT_EQ(line->first, RecordEventLevel::warn);
        EXPECT_NE(line->second.find(event.recordPath), std::string::npos) << line->second;
        EXPECT_NE(line->second.find("power loss"), std::string::npos) << line->second;
    }
}

TEST(DescribeRecordEvent, GuardFailedNamesTheGuardAndTheObservedValue)
{
    {
        CaRecordEvent event;
        event.kind = RecordEvent::guard_failed;
        event.bundlePath = "/etc/certs/root-ca.pem";
        event.guard = ca_bundle::GuardFailure::hash_mismatch;

        const auto line = describeRecordEvent(event);
        ASSERT_TRUE(line.has_value());
        EXPECT_EQ(line->first, RecordEventLevel::warn);
        EXPECT_NE(line->second.find("Content-SHA256 mismatch"), std::string::npos) << line->second;
    }
    {
        CaRecordEvent event;
        event.kind = RecordEvent::guard_failed;
        event.bundlePath = "/etc/certs/root-ca.pem";
        event.guard = ca_bundle::GuardFailure::no_ca_signs_leaf;

        const auto line = describeRecordEvent(event);
        ASSERT_TRUE(line.has_value());
        EXPECT_NE(line->second.find("no CA signs the served leaf"), std::string::npos) << line->second;
    }
    {
        CaRecordEvent event;
        event.kind = RecordEvent::guard_failed;
        event.bundlePath = "/etc/certs/root-ca.pem";
        event.guard = ca_bundle::GuardFailure::too_many_certificates;
        event.observed = 7;

        const auto line = describeRecordEvent(event);
        ASSERT_TRUE(line.has_value());
        EXPECT_NE(line->second.find("7 certificates (max 6)"), std::string::npos) << line->second;
    }
    {
        CaRecordEvent event;
        event.kind = RecordEvent::guard_failed;
        event.bundlePath = "/etc/certs/root-ca.pem";
        event.guard = ca_bundle::GuardFailure::too_many_bytes;
        event.observed = 8402;

        const auto line = describeRecordEvent(event);
        ASSERT_TRUE(line.has_value());
        EXPECT_NE(line->second.find("8402 bytes (max 8191)"), std::string::npos) << line->second;
    }
}

TEST(DescribeRecordEvent, PublicationChangeNamesBothValues)
{
    CaRecordEvent event;
    event.kind = RecordEvent::published_changed;
    event.bundlePath = "/etc/certs/root-ca.pem";
    event.publication = 1789000600;
    event.previousPublication = 1789000000;

    const auto line = describeRecordEvent(event);
    ASSERT_TRUE(line.has_value());
    EXPECT_EQ(line->first, RecordEventLevel::info);
    EXPECT_NE(line->second.find("1789000600"), std::string::npos) << line->second;
    EXPECT_NE(line->second.find("1789000000"), std::string::npos) << line->second;
}

TEST(DescribeRecordEvent, NoneProducesNoLine)
{
    CaRecordEvent event; // kind defaults to RecordEvent::none
    EXPECT_EQ(describeRecordEvent(event), std::nullopt);
}

TEST(CaRecordEventMailbox, DrainReturnsEventsOnceAndInOrder)
{
    CaRecordEventMailbox mailbox;

    CaRecordEvent first;
    first.kind = RecordEvent::published_changed;
    first.publication = 1;
    CaRecordEvent second;
    second.kind = RecordEvent::guard_failed;
    second.publication = 2;
    CaRecordEvent third;
    third.kind = RecordEvent::record_unwritable;
    third.publication = 3;

    mailbox.post(first);
    mailbox.post(second);
    mailbox.post(third);

    const auto drained = mailbox.drain();
    ASSERT_EQ(drained.size(), 3U);
    EXPECT_EQ(drained[0].publication, 1);
    EXPECT_EQ(drained[1].publication, 2);
    EXPECT_EQ(drained[2].publication, 3);
    EXPECT_EQ(drained[0].seq, 1U);
    EXPECT_EQ(drained[1].seq, 2U);
    EXPECT_EQ(drained[2].seq, 3U);

    // A second drain is empty: every event comes out exactly once.
    EXPECT_TRUE(mailbox.drain().empty());
}

TEST(CaRecordEventMailbox, OverflowDropsTheOldestAndCounts)
{
    CaRecordEventMailbox mailbox;

    for (std::uint64_t i = 0; i < CaRecordEventMailbox::kCapacity + 1; ++i)
    {
        CaRecordEvent event;
        event.kind = RecordEvent::published_changed;
        event.publication = static_cast<std::int64_t>(i);
        mailbox.post(event);
    }

    EXPECT_EQ(mailbox.dropped(), 1U);

    const auto drained = mailbox.drain();
    ASSERT_EQ(drained.size(), CaRecordEventMailbox::kCapacity);
    // Event 0 (the oldest) was dropped to make room; 1..kCapacity survive, in order.
    EXPECT_EQ(drained.front().publication, 1);
    EXPECT_EQ(drained.back().publication, static_cast<std::int64_t>(CaRecordEventMailbox::kCapacity));
}

// ---------------------------------------------------------------------------
// deliver(): the one production way these events reach a log, and the reason it exists -- several
// consumers drain this mailbox (the daily tick, a GET /cacerts request, the notify provider), and
// draining and logging as two steps let one of them publish generation N after another published
// N+1 (issue #39319, C26, objection 4).
// ---------------------------------------------------------------------------

namespace
{
    /// An event with just enough in it to produce a line and be told apart in one.
    CaRecordEvent publicationEvent(std::int64_t publication)
    {
        CaRecordEvent event;
        event.kind = RecordEvent::published_changed;
        event.bundlePath = "/etc/certs/root-ca.pem";
        event.publication = publication;
        return event;
    }
} // namespace

TEST(CaRecordEventMailboxDeliver, SaysEveryEventOnceInPostingOrder)
{
    CaRecordEventMailbox mailbox;
    mailbox.post(publicationEvent(1));
    mailbox.post(publicationEvent(2));

    std::vector<std::string> said;
    const auto collect = [&said](RecordEventLevel, const std::string& line)
    {
        said.push_back(line);
    };

    mailbox.deliver(collect);
    ASSERT_EQ(said.size(), 2U);
    EXPECT_NE(said[0].find("generation 1"), std::string::npos) << said[0];
    EXPECT_NE(said[1].find("generation 2"), std::string::npos) << said[1];

    // Delivered means removed: a second consumer arriving afterwards says nothing, and neither
    // does a plain drain().
    said.clear();
    mailbox.deliver(collect);
    EXPECT_TRUE(said.empty());
    EXPECT_TRUE(mailbox.drain().empty());
}

TEST(CaRecordEventMailboxDeliver, AnEmptyEmitterKeepsTheEvents)
{
    // A consumer with nowhere to log must not be a way to lose events: nothing is drained.
    CaRecordEventMailbox mailbox;
    mailbox.post(publicationEvent(7));

    mailbox.deliver({});
    ASSERT_EQ(mailbox.drain().size(), 1U);
}

TEST(CaRecordEventMailboxDeliver, ConcurrentConsumersCannotPublishOutOfOrder)
{
    CaRecordEventMailbox mailbox;
    mailbox.post(publicationEvent(1));

    std::mutex saidMutex;
    std::vector<std::string> said;

    // Barriers, never sleeps: promises make each step wait for the exact event it depends on, so
    // the interleaving under test is reached deterministically and the test cannot be slow or
    // timing-dependent.
    std::promise<void> firstEmitEntered;
    std::promise<void> releaseFirstEmit;
    std::promise<void> secondConsumerStarted;
    auto firstEmitEnteredFuture = firstEmitEntered.get_future();
    auto releaseFirstEmitFuture = releaseFirstEmit.get_future();
    auto secondConsumerStartedFuture = secondConsumerStarted.get_future();

    // The consumer that is descheduled BETWEEN taking the event and saying it -- exactly where the
    // race lived. It records the line only after being released, so `said` is publication order.
    std::thread slow {[&]
                      {
                          bool parked = false;
                          mailbox.deliver(
                              [&](RecordEventLevel, const std::string& line)
                              {
                                  if (!parked)
                                  {
                                      parked = true;
                                      firstEmitEntered.set_value();
                                      releaseFirstEmitFuture.wait();
                                  }
                                  std::lock_guard<std::mutex> lock {saidMutex};
                                  said.push_back(line);
                              });
                      }};

    firstEmitEnteredFuture.wait();

    // A NEWER event arrives while the first consumer is parked mid-delivery, and a second consumer
    // goes for it. Without the delivery mutex it drains and logs generation 2 here, before the
    // parked one has said generation 1 -- so the last line an operator reads describes an EARLIER
    // publication.
    mailbox.post(publicationEvent(2));
    std::thread fast {[&]
                      {
                          secondConsumerStarted.set_value();
                          mailbox.deliver(
                              [&](RecordEventLevel, const std::string& line)
                              {
                                  std::lock_guard<std::mutex> lock {saidMutex};
                                  said.push_back(line);
                              });
                      }};

    secondConsumerStartedFuture.wait();
    releaseFirstEmit.set_value();

    slow.join();
    fast.join();

    std::lock_guard<std::mutex> lock {saidMutex};
    ASSERT_EQ(said.size(), 2U);
    EXPECT_NE(said[0].find("generation 1"), std::string::npos) << said[0];
    EXPECT_NE(said[1].find("generation 2"), std::string::npos) << said[1];
}

TEST(CaRecordEventMailboxDeliver, ReportsDroppedEventsOncePerOverflow)
{
    CaRecordEventMailbox mailbox;

    for (std::uint64_t i = 0; i < CaRecordEventMailbox::kCapacity + 2; ++i)
    {
        mailbox.post(publicationEvent(static_cast<std::int64_t>(i)));
    }
    ASSERT_EQ(mailbox.dropped(), 2U);

    std::vector<std::pair<RecordEventLevel, std::string>> said;
    const auto collect = [&said](RecordEventLevel level, const std::string& line)
    {
        said.emplace_back(level, line);
    };

    mailbox.deliver(collect);

    // The events that survived, and then ONE line about the gap: silence about a full mailbox is
    // indistinguishable from "nothing happened", which is what the counter exists to prevent.
    ASSERT_EQ(said.size(), CaRecordEventMailbox::kCapacity + 1);
    const auto& report = said.back();
    EXPECT_EQ(report.first, RecordEventLevel::warn);
    EXPECT_NE(report.second.find("Dropped 2 CA bundle publication event(s)"), std::string::npos) << report.second;

    // A total that only grows is not re-announced: the next delivery, with no NEW drop, is silent.
    said.clear();
    mailbox.deliver(collect);
    EXPECT_TRUE(said.empty());
}
