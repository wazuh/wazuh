/*
 * Wazuh container_instances — query service refusal path (#37532 / #37203).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The store refuses a lookup made in the wrong key space. These cases pin what
 * the SERVICE does with that refusal, which is the half that decides whether
 * the refusal is worth anything: a refusal that then falls through to the cold
 * path has reinterpreted the caller's number in this host's key space, and the
 * answer is an unrelated container or an endless `pending` — the two outcomes
 * the typed key exists to prevent.
 */

#include "cache/metadata_store.hpp"
#include "ipc/query_service.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using namespace wazuh::container_instances;

namespace
{

    constexpr std::uint64_t kCgroupInode = 4242;
    constexpr std::uint64_t kMntNsInode = 4026532281;
    const SourceId kDocker {"docker"};

    /// Counts the cold path. The service must never reach it for a request made
    /// in a key space this host does not use.
    class CountingResolver final : public ICgroupResolver
    {
    public:
        mutable int scanOneCalls {0};

        [[nodiscard]] CgroupScan scan() const override
        {
            return {};
        }

        [[nodiscard]] std::optional<CgroupEntry> scanOne(std::uint64_t) const override
        {
            ++scanOneCalls;
            return std::nullopt;
        }
    };

    ContainerRecord MakeRecord(const std::string& id, std::uint64_t hostKey)
    {
        ContainerRecord record;
        record.runtime = ContainerRuntime::docker;
        record.containerId = id;
        record.containerName = id;
        record.image = "img";
        record.hostKey = hostKey;
        record.state = ContainerState::running;
        return record;
    }

    struct Fixture
    {
        CountingResolver resolver;
        MetadataStore store {[](LogLevel, const std::string&) {}, KeyKind::mntNsInode};

        QueryService Service()
        {
            return QueryService {store,
                                 {},
                                 resolver,
                                 RetryPolicy {1, std::chrono::milliseconds {0}, std::chrono::milliseconds {0}},
                                 "test",
                                 [](LogLevel, const std::string&) {},
                                 [](std::chrono::milliseconds) {}};
        }

        void SeedOneContainer()
        {
            store.applySnapshot(kDocker, {MakeRecord("alpha", kMntNsInode)}, {kMntNsInode},
                                std::chrono::steady_clock::now());
        }
    };

    QueryRequest Resolve(std::uint64_t hostKey, KeyKind kind)
    {
        QueryRequest request;
        request.version = 2;
        request.op = QueryRequest::Op::resolve;
        request.hostKey = hostKey;
        request.keyKind = kind;
        return request;
    }

} // namespace

TEST(QueryServiceTest, AResolveInTheWrongKeySpaceIsRefusedAndNeverColdResolved)
{
    Fixture fixture;
    fixture.SeedOneContainer();
    auto service = fixture.Service();

    const auto response = service.handle(Resolve(kMntNsInode, KeyKind::cgroupInode));

    EXPECT_EQ(QueryResponse::Status::error, response.status);
    ASSERT_TRUE(response.errorCode.has_value());
    EXPECT_EQ(QueryResponse::ErrorCode::keyKindMismatch, *response.errorCode);
    EXPECT_EQ(nullptr, response.record) << "no record may be invented for a question asked in the wrong space";
    EXPECT_EQ(0, fixture.resolver.scanOneCalls)
        << "falling through to the cold path reinterprets the caller's number in THIS host's key "
           "space, which is how a wrong-kind query ends up resolving to an unrelated container";
}

TEST(QueryServiceTest, TheRefusalDoesNotDependOnTheNumberBeingKnown)
{
    // The refusal is about the key SPACE, not about this particular value, so a
    // number nothing here has ever seen is refused just the same. Otherwise a
    // mismatched consumer would be refused only by luck.
    Fixture fixture;
    fixture.SeedOneContainer();
    auto service = fixture.Service();

    const auto response = service.handle(Resolve(kCgroupInode, KeyKind::cgroupInode));

    EXPECT_EQ(QueryResponse::Status::error, response.status);
    ASSERT_TRUE(response.errorCode.has_value());
    EXPECT_EQ(QueryResponse::ErrorCode::keyKindMismatch, *response.errorCode);
    EXPECT_EQ(0, fixture.resolver.scanOneCalls);
}

TEST(QueryServiceTest, AResolveInTheRightKeySpaceStillReachesTheColdPath)
{
    // The guard above must not have cost an ordinary miss its cold resolution:
    // an unknown number in the RIGHT space is exactly the case the cold path
    // exists for.
    Fixture fixture;
    fixture.SeedOneContainer();
    auto service = fixture.Service();

    const auto response = service.handle(Resolve(kMntNsInode + 1, KeyKind::mntNsInode));

    EXPECT_LT(0, fixture.resolver.scanOneCalls) << "an unknown key in the right space is still resolved";
    EXPECT_NE(QueryResponse::ErrorCode::keyKindMismatch,
              response.errorCode.value_or(QueryResponse::ErrorCode::internal));
}

TEST(QueryServiceTest, AResolveThatMatchesTheHostsKeySpaceIsAnswered)
{
    Fixture fixture;
    fixture.SeedOneContainer();
    auto service = fixture.Service();

    const auto response = service.handle(Resolve(kMntNsInode, KeyKind::mntNsInode));

    EXPECT_EQ(QueryResponse::Status::resolved, response.status);
    ASSERT_NE(nullptr, response.record);
    EXPECT_EQ("alpha", response.record->containerId);
    EXPECT_EQ(0, fixture.resolver.scanOneCalls) << "a store hit must not reach the cold path at all";
}
