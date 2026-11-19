/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "indexer/IIndexerConnectorSync.hpp"
#include "indexer/indexerConnectorSyncAdapter.hpp"
#include "testIndexerConnectorFakes.hpp"

#include <json.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

/*
 * Pins the expanded IIndexerConnectorSync seam: every method the sync pipeline will use is
 * callable through the interface and observable on the fake's shared event record, because the
 * pipeline tests are built on top of both.
 *
 * The second half pins the production adapter's own behaviour, the translation of the connector's
 * exception into ConnectorError, by instantiating its template over a test connector. They live in
 * this file rather than in one of their own because the test sources are a configure-time GLOB.
 */

using invsync::indexer::IIndexerConnectorSync;
using invsync::test::ConnectorEvents;
using invsync::test::FakeIndexerConnectorSync;

TEST(IndexerSyncSeamTest, EverySeamMethodIsObservableThroughTheInterface)
{
    auto events = std::make_shared<ConnectorEvents>();
    events->m_searchResponse = nlohmann::json {{"hits", {{"total", {{"value", 1}}}}}};
    FakeIndexerConnectorSync fake {events, "sync"};
    IIndexerConnectorSync& seam = fake;

    seam.bulkIndex("id-1", "idx-a", R"({"k":1})");
    seam.bulkIndex("id-2", "idx-a", "{}", "7");
    seam.bulkDelete("id-3", "idx-b");
    seam.deleteByQuery("idx-b", "001", "cluster01");
    seam.executeUpdateByQuery({"idx-a", "idx-b"}, nlohmann::json {{"query", "q"}});
    const auto response = seam.executeSearchQuery("idx-a", nlohmann::json {{"size", 0}});
    seam.flush();

    EXPECT_EQ(events->searchResponse(), response);
    EXPECT_EQ(1, events->m_syncFlushes.load());

    const auto ops = events->syncOps();
    ASSERT_EQ(6U, ops.size());
    EXPECT_EQ(std::make_tuple(std::string {"bulkIndex"},
                              std::string {"id-1"},
                              std::string {"idx-a"},
                              std::string {R"({"k":1})"},
                              std::string {}),
              ops[0]);
    // The versioned overload lands with its version in the last column.
    EXPECT_EQ(std::make_tuple(std::string {"bulkIndex"},
                              std::string {"id-2"},
                              std::string {"idx-a"},
                              std::string {"{}"},
                              std::string {"7"}),
              ops[1]);
    EXPECT_EQ("bulkDelete", std::get<0>(ops[2]));
    EXPECT_EQ("id-3", std::get<1>(ops[2]));
    EXPECT_EQ("idx-b", std::get<2>(ops[2]));
    EXPECT_EQ(std::make_tuple(std::string {"deleteByQuery"},
                              std::string {"001"},
                              std::string {"idx-b"},
                              std::string {"cluster01"},
                              std::string {}),
              ops[3]);
    EXPECT_EQ("executeUpdateByQuery", std::get<0>(ops[4]));
    EXPECT_EQ("idx-a,idx-b", std::get<2>(ops[4]));
    EXPECT_EQ("executeSearchQuery", std::get<0>(ops[5]));
    EXPECT_EQ("idx-a", std::get<2>(ops[5]));
}

TEST(IndexerSyncSeamTest, AvailabilityFollowsTheSharedFlag)
{
    auto events = std::make_shared<ConnectorEvents>();
    FakeIndexerConnectorSync fake {events, "sync"};
    const IIndexerConnectorSync& seam = fake;

    EXPECT_TRUE(seam.isAvailable());
    events->m_syncAvailable.store(false);
    EXPECT_FALSE(seam.isAvailable());
}

TEST(IndexerSyncSeamTest, DestructionIsRecordedForTeardownOrdering)
{
    auto events = std::make_shared<ConnectorEvents>();
    {
        FakeIndexerConnectorSync fake {events, "sync"};
    }
    EXPECT_EQ(std::vector<std::string> {"sync"}, events->destroyed());
}

/*
 * The production adapter (TIndexerConnectorSyncAdapter) over a test connector.
 */

using invsync::indexer::ConnectorError;
using Category = IndexerConnectorException::Category;
using Cause = ConnectorError::Cause;

namespace
{
    /// What a test sets on, and reads back from, the connector the adapter owns (the adapter holds
    /// its connector privately, so the state is shared).
    struct State
    {
        std::function<void()> m_action;
        nlohmann::json m_response = nlohmann::json::object();
        std::string m_seenIndex;
        nlohmann::json m_seenQuery;
    };

    /// Inner connector of the adapter under test: every failing-capable operation runs the state's
    /// action, which the test uses to throw from inside the adapter's translation.
    class TestConnector
    {
    public:
        struct BulkStats
        {
            std::uint64_t requests {0};
            std::uint64_t bytes {0};
            std::uint64_t conflictRetries {0};
        };

        explicit TestConnector(std::shared_ptr<State> state)
            : m_state {std::move(state)}
        {
        }

        bool isAvailable() const
        {
            return true;
        }

        std::unique_lock<std::mutex> scopeLock()
        {
            return std::unique_lock<std::mutex> {m_mutex};
        }

        void bulkIndex(std::string_view, std::string_view, std::string_view) {}

        void bulkIndex(std::string_view, std::string_view, std::string_view, std::string_view) {}

        void bulkDelete(std::string_view, std::string_view) {}

        void deleteByQuery(const std::string&, const std::string&, const std::string&) {}

        void executeUpdateByQuery(const std::vector<std::string>&, const nlohmann::json&)
        {
            run();
        }

        nlohmann::json executeSearchQuery(const std::string& index, const nlohmann::json& query)
        {
            m_state->m_seenIndex = index;
            m_state->m_seenQuery = query;
            run();
            return m_state->m_response;
        }

        void flush()
        {
            run();
        }

        BulkStats takeBulkRequestStats()
        {
            return {};
        }

    private:
        void run()
        {
            if (m_state->m_action)
            {
                m_state->m_action();
            }
        }

        std::shared_ptr<State> m_state;
        std::mutex m_mutex;
    };

    using Adapter = invsync::indexer::TIndexerConnectorSyncAdapter<TestConnector>;

    std::function<void()> throwing(Category category, long status)
    {
        return [=]
        {
            throw IndexerConnectorException {"m", category, status};
        };
    }

    /// The cause of the ConnectorError that @p call throws; fails the test when it throws anything else.
    std::optional<Cause> causeOfFailure(const std::function<void()>& call)
    {
        try
        {
            call();
        }
        catch (const ConnectorError& e)
        {
            EXPECT_STREQ("m", e.what());
            return e.cause();
        }
        catch (...)
        {
            ADD_FAILURE() << "the failure was not translated to a ConnectorError";
            return std::nullopt;
        }
        ADD_FAILURE() << "nothing was thrown";
        return std::nullopt;
    }

    const nlohmann::json QUERY {{"query", {{"match_all", nlohmann::json::object()}}}};
} // namespace

TEST(IndexerConnectorSyncAdapterTest, SearchFailuresAreClassifiedByStatusThroughTheOverride)
{
    struct Row
    {
        Category category;
        long status;
        Cause expected;
    };
    const Row rows[] {
        {Category::Other, 500, Cause::IndexerUnavailable},
        {Category::Other, 503, Cause::IndexerUnavailable},
        {Category::Other, 599, Cause::IndexerUnavailable},
        {Category::Other, 499, Cause::Other},
        {Category::Other, 600, Cause::Other},
        {Category::Other, 400, Cause::Other},
        {Category::Other, 404, Cause::Other},
        {Category::Other, 0, Cause::Other},
        {Category::Other, -1, Cause::Other},
        {Category::RetryExhausted, 0, Cause::RetryExhausted},
        {Category::DocumentRejected, 0, Cause::DocumentRejected},
        {Category::RetryExhausted, 503, Cause::IndexerUnavailable},
    };

    for (const auto& row : rows)
    {
        SCOPED_TRACE("category " + std::to_string(static_cast<int>(row.category)) + ", status " +
                     std::to_string(row.status));
        auto state = std::make_shared<State>();
        state->m_action = throwing(row.category, row.status);
        Adapter adapter {state};
        IIndexerConnectorSync& seam = adapter;

        const auto cause = causeOfFailure([&] { seam.executeSearchQuery("idx", QUERY); });

        ASSERT_TRUE(cause.has_value());
        EXPECT_EQ(row.expected, *cause);
    }
}

TEST(IndexerConnectorSyncAdapterTest, AnUntypedSearchFailurePassesUntranslated)
{
    auto state = std::make_shared<State>();
    state->m_action = []
    {
        throw std::runtime_error {"untyped"};
    };
    Adapter adapter {state};
    IIndexerConnectorSync& seam = adapter;

    try
    {
        seam.executeSearchQuery("idx", QUERY);
        FAIL() << "nothing was thrown";
    }
    catch (const ConnectorError&)
    {
        FAIL() << "an untyped failure must not be translated to a ConnectorError";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_STREQ("untyped", e.what());
    }
}

TEST(IndexerConnectorSyncAdapterTest, WriteFailuresKeepTheirCategoryCause)
{
    struct Row
    {
        Category category;
        long status;
        Cause expected;
    };
    const Row rows[] {
        {Category::Other, 503, Cause::Other},
        {Category::ConflictsExhausted, 0, Cause::ConflictsExhausted},
        {Category::DocumentRejected, 0, Cause::DocumentRejected},
        {Category::RetryExhausted, 0, Cause::RetryExhausted},
    };

    for (const auto& row : rows)
    {
        SCOPED_TRACE("category " + std::to_string(static_cast<int>(row.category)) + ", status " +
                     std::to_string(row.status));
        auto state = std::make_shared<State>();
        state->m_action = throwing(row.category, row.status);
        Adapter adapter {state};
        IIndexerConnectorSync& seam = adapter;

        const auto flushCause = causeOfFailure([&] { seam.flush(); });
        ASSERT_TRUE(flushCause.has_value());
        EXPECT_EQ(row.expected, *flushCause) << "flush";

        const auto updateCause = causeOfFailure([&] { seam.executeUpdateByQuery({"idx"}, QUERY); });
        ASSERT_TRUE(updateCause.has_value());
        EXPECT_EQ(row.expected, *updateCause) << "executeUpdateByQuery";
    }
}

TEST(IndexerConnectorSyncAdapterTest, ASuccessfulSearchReturnsTheBodyUntouched)
{
    auto state = std::make_shared<State>();
    state->m_response = nlohmann::json::parse(R"({"hits":{"hits":[{"_id":"a","sort":["a"]}]},"timed_out":false})");
    Adapter adapter {state};
    IIndexerConnectorSync& seam = adapter;

    const auto body = seam.executeSearchQuery("wazuh-states-inventory-packages", QUERY);

    EXPECT_EQ(state->m_response, body);
    EXPECT_EQ("wazuh-states-inventory-packages", state->m_seenIndex);
    EXPECT_EQ(QUERY, state->m_seenQuery);
}
