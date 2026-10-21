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

#include <cctype>
#include <chrono>
#include <future>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include <gtest/gtest.h>

#include "indexer_client/runtime.hpp"
#include "runtime/runtimeInternal.hpp"

using namespace indexer_client;
using namespace std::chrono_literals;

namespace
{
    /// Test-owned configuration source: one network thread, one CPU thread, one indexer host.
    class SmallSource final : public IConfigSource
    {
    public:
        std::optional<std::string> raw(std::string_view key) const override
        {
            if (key == "analysisd.indexer_client_network_threads" || key == "analysisd.indexer_client_cpu_threads")
            {
                return std::string("1");
            }
            return std::nullopt;
        }

        std::vector<std::string> keysWithPrefix(std::string_view /*prefix*/) const override
        {
            return {"analysisd.indexer_client_network_threads", "analysisd.indexer_client_cpu_threads"};
        }

        std::string indexerSectionJson() const override
        {
            return R"({"hosts":["http://127.0.0.1:1"]})";
        }

        indexer_client::Credentials credentials() const override
        {
            return {"user", "pass"};
        }
    };

    Deadline soon()
    {
        return std::chrono::steady_clock::now() + 1s;
    }
} // namespace

class ClientTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        auto started = RuntimeOwner::start(ProcessId::Analysisd, SmallSource {});
        ASSERT_TRUE(started.ok()) << started.reason;
        m_ref = started.value;
        auto client = m_ref.client("client-test", {BucketSpec {"events"}});
        ASSERT_TRUE(client.ok()) << client.reason;
        m_client = client.value;
    }

    void TearDown() override
    {
        m_client.reset();
        RuntimeOwner::shutdown();
    }

    RuntimeRef m_ref;
    std::shared_ptr<Client> m_client;
};

TEST_F(ClientTest, QueryStubReturnsUnavailable)
{
    auto query = m_client->query();
    ASSERT_NE(query, nullptr);
    const QueryOptions options;
    EXPECT_EQ(query->search("idx", nlohmann::json::object(), options, soon()).cause, Cause::Unavailable);
    EXPECT_EQ(
        query->searchAfter(
                 "idx", nlohmann::json::object(), [](const nlohmann::json&) { return true; }, options, soon())
            .cause,
        Cause::Unavailable);
    EXPECT_EQ(query->pit({"idx"}, PitOptions {}, options, soon()).cause, Cause::Unavailable);
    EXPECT_EQ(query->deleteByQuery({"idx"}, nlohmann::json::object(), DbqOptions {}, options, soon()).cause,
              Cause::Unavailable);
    EXPECT_EQ(query->updateByQuery({"idx"}, nlohmann::json::object(), options, soon()).cause, Cause::Unavailable);
    const auto exists = query->indexExists("idx", options, soon());
    EXPECT_EQ(exists.cause, Cause::Unavailable) << "Unavailable is not 'false' (RF-14)";
}

TEST_F(ClientTest, HealthListsTheConfiguredHost)
{
    // One node per configured host from start() on (E2b); its state is the probe's business (component suite).
    const auto health = m_client->health();
    ASSERT_EQ(health.nodes.size(), 1U);
    EXPECT_EQ(health.nodes[0].url, "http://127.0.0.1:1");
}

TEST_F(ClientTest, AwaitClosedFromConsumerSucceeds)
{
    m_client->requestClose();
    const auto closed = m_client->awaitClosed(soon());
    ASSERT_TRUE(closed.ok()) << closed.reason;
    EXPECT_EQ(closed.value.callbacksInFlight, 0u);
    EXPECT_EQ(closed.value.droppedClientClosed, 0u);
    EXPECT_EQ(closed.value.droppedShutdown, 0u);
    EXPECT_EQ(m_ref.snapshot().clients, 0u) << "a closed client frees its consumer name";
    EXPECT_TRUE(m_ref.client("client-test", {}).ok());
}

TEST_F(ClientTest, DestructorReleasesName)
{
    EXPECT_EQ(m_ref.snapshot().clients, 1u);
    m_client.reset();
    EXPECT_EQ(m_ref.snapshot().clients, 0u);
}

TEST_F(ClientTest, MovedFromClientIsInert)
{
    Client moved(std::move(*m_client));
    EXPECT_TRUE(moved.valid());
    EXPECT_FALSE(m_client->valid());
    EXPECT_EQ(m_client->writer("events"), nullptr);
    EXPECT_EQ(m_client->query(), nullptr);
    EXPECT_EQ(m_client->awaitClosed(soon()).cause, Cause::InvalidState);
    EXPECT_NE(moved.writer("events"), nullptr);
}

TEST_F(ClientTest, WaitsFromRuntimeThreadAreReentrancy)
{
    auto writer = m_client->writer("events");
    ASSERT_NE(writer, nullptr);
    auto groupTicket = writer->group().commit();
    auto cancelTicket = writer->cancel("tag");

    std::promise<std::tuple<Cause, Cause, Cause>> result;
    ASSERT_TRUE(detail::testing::postToPool(
        [&]()
        {
            result.set_value(
                {groupTicket.wait(soon()).cause, cancelTicket.wait(soon()).cause, Ticket {}.wait(soon()).cause});
        }));
    const auto [group, cancel, ticket] = result.get_future().get();
    EXPECT_EQ(group, Cause::Reentrancy);
    EXPECT_EQ(cancel, Cause::Reentrancy);
    EXPECT_EQ(ticket, Cause::Reentrancy);

    // The same waits from the consumer thread: the empty group's commit is a success with no result; the cancel is
    // still the stub.
    const auto committed = groupTicket.wait(soon());
    EXPECT_TRUE(committed.ok()) << toString(committed.cause);
    EXPECT_TRUE(committed.value.empty());
    EXPECT_EQ(cancelTicket.wait(soon()).cause, Cause::Unavailable);
    EXPECT_EQ(Ticket {}.wait(soon()).cause, Cause::InvalidState);
}

TEST_F(ClientTest, NoHandlesAfterRequestClose)
{
    ASSERT_NE(m_client->writer("events"), nullptr);
    ASSERT_NE(m_client->query(), nullptr);
    m_client->requestClose();
    EXPECT_EQ(m_client->writer("events"), nullptr) << "a closing client hands out no writer";
    EXPECT_EQ(m_client->query(), nullptr) << "a closing client hands out no query";
    EXPECT_TRUE(m_client->awaitClosed(soon()).ok());
    EXPECT_EQ(m_client->writer("events"), nullptr);
    EXPECT_EQ(m_client->query(), nullptr);
}

TEST_F(ClientTest, GroupCommitTwiceIsInvalidState)
{
    auto writer = m_client->writer("events");
    ASSERT_NE(writer, nullptr);
    auto group = writer->group();
    const auto first = group.commit().wait(soon());
    EXPECT_TRUE(first.ok()) << toString(first.cause) << ": the empty commit succeeds";
    EXPECT_TRUE(first.value.empty());
    EXPECT_EQ(group.add(Op {}), Cause::InvalidState);
    EXPECT_FALSE(group.lastAddReason().empty());
    EXPECT_EQ(group.commit().wait(soon()).cause, Cause::InvalidState);
}

TEST_F(ClientTest, PitStubs)
{
    auto query = m_client->query();
    ASSERT_NE(query, nullptr);
    auto fromStub = query->pit({"idx"}, PitOptions {}, QueryOptions {}, soon());
    ASSERT_EQ(fromStub.cause, Cause::Unavailable);

    auto withState = Pit(std::make_shared<detail::PitState>());
    for (Pit* pit : {&fromStub.value, &withState})
    {
        EXPECT_EQ(pit->generation(), 0u);
        EXPECT_EQ(pit->search(nlohmann::json::object(), soon()).cause, Cause::Unavailable);

        auto cursor = pit->cursor(CursorQuery {});
        EXPECT_FALSE(cursor.exhausted()) << "a fresh cursor is not exhausted";
        EXPECT_EQ(cursor.next(soon()).cause, Cause::Unavailable);

        std::promise<std::tuple<Cause, Cause>> result;
        ASSERT_TRUE(detail::testing::postToPool(
            [&]()
            { result.set_value({cursor.next(soon()).cause, pit->search(nlohmann::json::object(), soon()).cause}); }));
        const auto [next, search] = result.get_future().get();
        EXPECT_EQ(next, Cause::Reentrancy);
        EXPECT_EQ(search, Cause::Reentrancy);
    }

    PitSession empty;
    EXPECT_TRUE(empty.exhausted()) << "an empty cursor is exhausted";
    EXPECT_EQ(empty.next(soon()).cause, Cause::InvalidState);
    EXPECT_EQ(Pit {}.generation(), 0u);
}

TEST_F(ClientTest, MoveAssignment)
{
    auto other = m_ref.client("client-test-2", {BucketSpec {"other"}});
    ASSERT_TRUE(other.ok()) << other.reason;
    EXPECT_EQ(m_ref.snapshot().clients, 2u);

    // The replaced handle closes as a destroyed one would: its consumer name is free again.
    *m_client = std::move(*other.value);
    EXPECT_TRUE(m_client->valid());
    EXPECT_FALSE(other.value->valid());
    EXPECT_EQ(m_ref.snapshot().clients, 1u);
    EXPECT_NE(m_client->writer("other"), nullptr);
    EXPECT_EQ(m_client->writer("events"), nullptr);
    EXPECT_TRUE(m_ref.client("client-test", {}).ok());

    // Self-assignment keeps the handle.
    auto& self = *m_client;
    *m_client = std::move(self);
    EXPECT_TRUE(m_client->valid());
    EXPECT_EQ(m_ref.snapshot().clients, 1u);
}

// The names end up in logs and metric labels (E5): every cause has its own stable, lowercase name.
TEST(TypesTest, CauseNamesStableAndUnique)
{
    std::set<std::string> names;
    const auto last = static_cast<int>(Cause::UsageError);
    for (int i = 0; i <= last; ++i)
    {
        const std::string name = toString(static_cast<Cause>(i));
        SCOPED_TRACE(i);
        EXPECT_NE(name, "unknown");
        EXPECT_FALSE(name.empty());
        for (const char c : name)
        {
            EXPECT_TRUE(std::islower(static_cast<unsigned char>(c)) || std::isdigit(static_cast<unsigned char>(c)) ||
                        c == '_')
                << name;
        }
        EXPECT_TRUE(names.insert(name).second) << "duplicated name " << name;
    }
    EXPECT_EQ(names.size(), static_cast<std::size_t>(last) + 1);
    EXPECT_STREQ(toString(Cause::None), "none");
    EXPECT_STREQ(toString(Cause::UsageError), "usage_error");
    EXPECT_STREQ(toString(static_cast<Cause>(last + 1)), "unknown");
}
