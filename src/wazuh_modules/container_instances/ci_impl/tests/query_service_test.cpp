/*
 * Wazuh container_instances — query service refusal path (#37203).
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
 *
 * The second group covers what the cold path is allowed to do to a container it
 * finds already stored. A container running an init system occupies several
 * cgroups, so events arrive carrying keys the index does not hold; answering
 * those by re-filing the container under whichever one was asked about made its
 * key flap against the reconcile's choice, and a changed key is an identity
 * change — `changed` on the wire, a full re-walk at the consumer, every few
 * seconds, for a container that had not moved.
 */

#include "cache/metadata_store.hpp"
#include "core/i_on_demand_refresher.hpp"
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


/* --- the cold path against a container the store already holds -------------
 *
 * One container, two cgroups, which is what any systemd-in-container image
 * looks like: the reconcile files it under the one it picks (kInitScopeInode),
 * and an event from inside the container arrives carrying the other.
 */
namespace
{

    constexpr std::uint64_t kInitScopeInode = 9001;
    constexpr std::uint64_t kUnitServiceInode = 9002;

    /// Resolves the child cgroup to the container that owns it, which is what
    /// the real resolver does by scanning the path's components outwards.
    class ChildCgroupResolver final : public ICgroupResolver
    {
    public:
        mutable int scanOneCalls {0};

        [[nodiscard]] CgroupScan scan() const override
        {
            return {};
        }

        [[nodiscard]] std::optional<CgroupEntry> scanOne(std::uint64_t hostKey) const override
        {
            ++scanOneCalls;

            if (hostKey != kUnitServiceInode)
            {
                return std::nullopt;
            }

            CgroupEntry entry;
            entry.containerId = "alpha";
            entry.inode = hostKey;
            entry.hint = RuntimeHint::docker;
            entry.cgroupPath = "/docker/alpha/system.slice/app.service";
            return entry;
        }
    };

    /// Both real connectors' refreshOne() reduced to what matters here: fetch
    /// the container's metadata afresh and hand it to the store keyed by the
    /// inode the question was asked about.
    class StubRefresher final : public IOnDemandRefresher
    {
    public:
        explicit StubRefresher(IMetadataStore& store)
            : m_store(store)
        {
        }

        int calls {0};

        [[nodiscard]] RefreshOutcome refreshOne(const std::string& containerId, std::uint64_t cgroupInode) override
        {
            ++calls;
            m_store.upsertResolved(kDocker, MakeRecord(containerId, cgroupInode));
            return RefreshOutcome::resolved;
        }

    private:
        IMetadataStore& m_store;
    };

    struct ColdPathFixture
    {
        ChildCgroupResolver resolver;
        MetadataStore store {[](LogLevel, const std::string&) {}, KeyKind::cgroupInode};
        StubRefresher refresher {store};

        QueryService Service()
        {
            return QueryService {store,
                                 {RefresherBinding {true, &refresher}},
                                 resolver,
                                 RetryPolicy {1, std::chrono::milliseconds {0}, std::chrono::milliseconds {0}},
                                 "test",
                                 [](LogLevel, const std::string&) {},
                                 [](std::chrono::milliseconds) {}};
        }

        void Reconcile(std::uint64_t hostKey)
        {
            store.applySnapshot(
                kDocker, {MakeRecord("alpha", hostKey)}, {hostKey}, std::chrono::steady_clock::now());
        }
    };

} // namespace

TEST(QueryServiceColdPathTest, AChildCgroupIsAnsweredWithoutReKeyingTheContainer)
{
    ColdPathFixture fixture;
    fixture.Reconcile(kInitScopeInode);
    auto service = fixture.Service();

    const auto before = fixture.store.lifecycleCursor();
    const auto response = service.handle(Resolve(kUnitServiceInode, KeyKind::cgroupInode));

    ASSERT_EQ(QueryResponse::Status::resolved, response.status);
    ASSERT_NE(nullptr, response.record);
    EXPECT_EQ("alpha", response.record->containerId);
    EXPECT_EQ(kInitScopeInode, response.record->hostKey)
        << "the cold path answered, but by moving the container onto the cgroup it was asked about -- "
           "which the next reconcile moves straight back";

    EXPECT_EQ(LookupResult::Status::resolved, fixture.store.lookup(HostKey {KeyKind::cgroupInode, kInitScopeInode}).status)
        << "the key the reconcile chose must keep resolving";

    const auto delta = fixture.store.lifecycleSince(before);
    for (const auto& event : delta.events)
    {
        EXPECT_NE(LifecycleKind::changed, event.kind)
            << "answering an event from a second cgroup is not a change to the container: published as "
               "`changed`, it has FIM re-walk the whole container every time one arrives";
    }
}

TEST(QueryServiceColdPathTest, TheChildCgroupResolvesWarmAfterwards)
{
    // The alias has to be worth something: the second event from the same unit
    // must be answered out of the index, or every one of them pays a /proc scan
    // and a runtime round-trip.
    ColdPathFixture fixture;
    fixture.Reconcile(kInitScopeInode);
    auto service = fixture.Service();

    static_cast<void>(service.handle(Resolve(kUnitServiceInode, KeyKind::cgroupInode)));

    fixture.resolver.scanOneCalls = 0;
    fixture.refresher.calls = 0;

    const auto second = service.handle(Resolve(kUnitServiceInode, KeyKind::cgroupInode));

    ASSERT_EQ(QueryResponse::Status::resolved, second.status);
    EXPECT_EQ("alpha", second.record->containerId);
    EXPECT_EQ(0, fixture.resolver.scanOneCalls) << "a key the store has already been told about is not cold";
    EXPECT_EQ(0, fixture.refresher.calls);
}

TEST(QueryServiceColdPathTest, AReconcileStillMovesAContainerThatReallyMoved)
{
    // The other half of the guard. Keeping the stored key must not freeze it:
    // a restart puts the container in a new cgroup, and the reconcile -- which
    // owns the key -- has to be able to say so.
    ColdPathFixture fixture;
    fixture.Reconcile(kInitScopeInode);
    auto service = fixture.Service();
    static_cast<void>(service.handle(Resolve(kUnitServiceInode, KeyKind::cgroupInode)));

    constexpr std::uint64_t kNewInitScopeInode = 9101;
    fixture.Reconcile(kNewInitScopeInode);

    const auto moved = fixture.store.lookup(HostKey {KeyKind::cgroupInode, kNewInitScopeInode});
    ASSERT_EQ(LookupResult::Status::resolved, moved.status);
    EXPECT_EQ(kNewInitScopeInode, moved.record->hostKey);
    EXPECT_EQ(LookupResult::Status::miss, fixture.store.lookup(HostKey {KeyKind::cgroupInode, kInitScopeInode}).status)
        << "the key it no longer has must stop answering";
}

TEST(QueryServiceColdPathTest, AnAliasOutlivesNeitherItsCgroupNorItsContainer)
{
    // The cost of remembering a second key: cgroup inodes are reused, so an
    // alias kept after its cgroup has gone eventually answers for a container
    // that has nothing to do with it. Expired on the same liveness rule as a
    // verdict -- absent from the resolver scan for MISSED_SCANS_LIMIT passes.
    ColdPathFixture fixture;
    fixture.Reconcile(kInitScopeInode);
    auto service = fixture.Service();
    static_cast<void>(service.handle(Resolve(kUnitServiceInode, KeyKind::cgroupInode)));

    ASSERT_EQ(LookupResult::Status::resolved,
              fixture.store.lookup(HostKey {KeyKind::cgroupInode, kUnitServiceInode}).status);

    // Reconciles in which only the container's own key is observed: the unit
    // has exited, and its cgroup with it.
    for (int pass = 0; pass < MISSED_SCANS_LIMIT; ++pass)
    {
        fixture.Reconcile(kInitScopeInode);
    }

    EXPECT_EQ(LookupResult::Status::miss, fixture.store.lookup(HostKey {KeyKind::cgroupInode, kUnitServiceInode}).status)
        << "a cgroup that no longer exists must stop resolving, or the next container to be given that "
           "inode inherits this container's identity";
    EXPECT_EQ(LookupResult::Status::resolved, fixture.store.lookup(HostKey {KeyKind::cgroupInode, kInitScopeInode}).status)
        << "expiring an alias must not touch the container it pointed at";
}

TEST(QueryServiceColdPathTest, AnAliasDiesWhenItsInodeIsReusedElsewhereOnTheHost)
{
    /* The reuse case, which plain liveness cannot see.
     *
     * `allHostKeys` holds every key observed on the HOST, container or not. So
     * once the dead unit's inode is handed to some other cgroup -- a host
     * service, another container's child -- it reads as "live" on every pass,
     * the alias's missed-scan counter is reset forever, and the alias goes on
     * claiming events that are no longer its container's.
     *
     * Nothing displaces it either: the new owner is not a container keyed on
     * that inode, so no resolved entry ever overwrites the alias. Only the sweep
     * can end it, and under the old rule the sweep never did.
     *
     * The snapshot settles it directly, because a record now carries the
     * container's other cgroups: the store can ask whether the inode is still
     * one of THIS container's rather than merely present somewhere. */
    ColdPathFixture fixture;
    fixture.Reconcile(kInitScopeInode);
    auto service = fixture.Service();
    static_cast<void>(service.handle(Resolve(kUnitServiceInode, KeyKind::cgroupInode)));

    const auto aliased = fixture.store.lookup(HostKey {KeyKind::cgroupInode, kUnitServiceInode});
    ASSERT_EQ(LookupResult::Status::resolved, aliased.status);
    ASSERT_EQ("alpha", aliased.record->containerId);

    // alpha still runs and reports only its own cgroup. The unit's inode is
    // still observed on the host -- by whatever inherited it -- but it is not
    // alpha's any more.
    for (int pass = 0; pass < MISSED_SCANS_LIMIT; ++pass)
    {
        fixture.store.applySnapshot(kDocker,
                                    {MakeRecord("alpha", kInitScopeInode)},
                                    {kInitScopeInode, kUnitServiceInode},
                                    std::chrono::steady_clock::now());
    }

    EXPECT_EQ(LookupResult::Status::miss, fixture.store.lookup(HostKey {KeyKind::cgroupInode, kUnitServiceInode}).status)
        << "an inode the container no longer holds must stop resolving to it, however alive that inode "
           "is elsewhere on the host";

    EXPECT_EQ(LookupResult::Status::resolved, fixture.store.lookup(HostKey {KeyKind::cgroupInode, kInitScopeInode}).status)
        << "expiring the alias must not disturb the container it pointed at";
}

TEST(QueryServiceColdPathTest, AnAliasSurvivesWhileItsOwnContainerStillReportsTheCgroup)
{
    // The other half of the rule: an alias whose cgroup the container still
    // occupies must NOT be swept. Published in the record's extra keys, which is
    // how a reconcile says "this cgroup is still mine".
    ColdPathFixture fixture;
    fixture.Reconcile(kInitScopeInode);
    auto service = fixture.Service();
    static_cast<void>(service.handle(Resolve(kUnitServiceInode, KeyKind::cgroupInode)));

    for (int pass = 0; pass < MISSED_SCANS_LIMIT + 1; ++pass)
    {
        auto record = MakeRecord("alpha", kInitScopeInode);
        record.extraHostKeys = {kUnitServiceInode};
        fixture.store.applySnapshot(
            kDocker, {record}, {kInitScopeInode, kUnitServiceInode}, std::chrono::steady_clock::now());
    }

    const auto alias = fixture.store.lookup(HostKey {KeyKind::cgroupInode, kUnitServiceInode});
    ASSERT_EQ(LookupResult::Status::resolved, alias.status)
        << "a unit that is still running must keep resolving to its container";
    EXPECT_EQ("alpha", alias.record->containerId);
}

TEST(QueryServiceColdPathTest, AContainerTheStoreHasNeverSeenIsKeyedByWhatWasAsked)
{
    // Cold DISCOVERY, where there is no stored key to preserve. The asked-about
    // inode is all there is, so it must become the container's key -- otherwise
    // the record lands with key 0 and is withheld from `list` as unresolved.
    ColdPathFixture fixture;
    auto service = fixture.Service();

    const auto response = service.handle(Resolve(kUnitServiceInode, KeyKind::cgroupInode));

    ASSERT_EQ(QueryResponse::Status::resolved, response.status);
    ASSERT_NE(nullptr, response.record);
    EXPECT_EQ(kUnitServiceInode, response.record->hostKey);
    ASSERT_EQ(1u, fixture.store.listContainers().size()) << "a discovered container must be published";
}
