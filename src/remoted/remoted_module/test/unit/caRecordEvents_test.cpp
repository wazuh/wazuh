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
#include <optional>
#include <string>
#include <system_error>

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
