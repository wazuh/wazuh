#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <gtest/gtest.h>

#include <base/json.hpp>
#include <cmstore/datakvdb.hpp>
#include <cmstore/icmstore.hpp>
#include <cmstore/mockcmstore.hpp>

#include <kvdbstore/kvdbManager.hpp>

namespace
{
// Helper: run N parallel reads to the same (ns, db, key) and collect references.
inline std::vector<std::reference_wrapper<const json::Json>> parallelReadRefs(kvdbstore::KVDBManager& mgr,
                                                                              const cm::store::ICMStoreNSReader& ns,
                                                                              const std::string& db,
                                                                              const std::string& key,
                                                                              int threads)
{
    std::atomic<bool> start {false};
    static const json::Json kDummy {"null"};
    std::vector<std::reference_wrapper<const json::Json>> refs(threads, std::cref(kDummy));
    std::vector<std::thread> ths;
    ths.reserve(threads);

    for (int i = 0; i < threads; ++i)
    {
        ths.emplace_back(
            [&, i]
            {
                while (!start.load(std::memory_order_acquire))
                { /* spin */
                }
                auto h = mgr.getKVDBHandler(ns, db);
                ASSERT_NE(h, nullptr);
                const json::Json& v = h->get(key);
                refs[i] = std::cref(v);
            });
    }

    start.store(true, std::memory_order_release);
    for (auto& t : ths) t.join();
    return refs;
}
} // namespace

TEST(KVDB_Manager_Unit, CacheHitDoesNotFetchAgain)
{
    kvdbstore::KVDBManager mgr;

    cm::store::NamespaceId nsId {"ns"};
    cm::store::MockICMStoreNSReader seed, again;

    ON_CALL(seed, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));
    ON_CALL(again, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));

    EXPECT_CALL(seed, getKVDBByName("db"))
        .Times(::testing::Exactly(1))
        .WillOnce(::testing::Return(cm::store::dataType::KVDB {"id-1", "db", json::Json {R"({"k":"v1"})"}, true}));

    auto h1 = mgr.getKVDBHandler(seed, "db");
    ASSERT_NE(h1, nullptr);
    const json::Json& r1 = h1->get("k");
    EXPECT_EQ(r1, json::Json {"\"v1\""});

    EXPECT_CALL(again, getKVDBByName("db")).Times(0); // cache hit

    auto h2 = mgr.getKVDBHandler(again, "db");
    ASSERT_NE(h2, nullptr);
    const json::Json& r2 = h2->get("k");
    EXPECT_EQ(r2, json::Json {"\"v1\""});
    EXPECT_EQ(std::addressof(r1), std::addressof(r2));
}

// Cache hit reuses the existing map (same underlying buffer) and does not rebuild.
TEST(KVDB_Manager_Unit, CacheHitReusesExistingMap)
{
    kvdbstore::KVDBManager mgr;

    cm::store::NamespaceId nsId {"ns"};
    cm::store::MockICMStoreNSReader r1, r2;

    ON_CALL(r1, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));
    ON_CALL(r2, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));

    EXPECT_CALL(r1, getKVDBByName("db"))
        .Times(::testing::Exactly(1))
        .WillOnce(::testing::Return(cm::store::dataType::KVDB {"id-1", "db", json::Json {R"({"k":"v1"})"}, true}));
    EXPECT_CALL(r2, getKVDBByName("db")).Times(0); // cache hit → no fetch

    auto hA = mgr.getKVDBHandler(r1, "db");
    ASSERT_NE(hA, nullptr);
    const json::Json& a = hA->get("k");

    auto hB = mgr.getKVDBHandler(r2, "db");
    ASSERT_NE(hB, nullptr);
    const json::Json& b = hB->get("k");

    EXPECT_EQ(std::addressof(a), std::addressof(b));
}

// After all handlers expire, the manager rebuilds with the new content.
TEST(KVDB_Manager_Unit, RebuildsAfterAllHandlersExpire)
{
    kvdbstore::KVDBManager mgr;

    cm::store::NamespaceId nsId {"ns"};
    cm::store::MockICMStoreNSReader r1, r2;

    ON_CALL(r1, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));
    ON_CALL(r2, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));

    EXPECT_CALL(r1, getKVDBByName("db"))
        .Times(::testing::Exactly(1))
        .WillOnce(::testing::Return(cm::store::dataType::KVDB {"id-1", "db", json::Json {R"({"k":"v1"})"}, true}));

    auto h1 = mgr.getKVDBHandler(r1, "db");
    ASSERT_NE(h1, nullptr);
    h1.reset(); // drop the only handler to allow cache eviction

    EXPECT_CALL(r2, getKVDBByName("db"))
        .Times(::testing::Exactly(1))
        .WillOnce(::testing::Return(cm::store::dataType::KVDB {"id-2", "db", json::Json {R"({"k":"v2"})"}, true}));

    auto h2 = mgr.getKVDBHandler(r2, "db");
    ASSERT_NE(h2, nullptr);
    const json::Json& v2 = h2->get("k");
    EXPECT_EQ(v2, json::Json {"\"v2\""});
}

// Same namespace but different dbName entries must use different cached maps.
TEST(KVDB_Manager_Unit, DifferentDbNamesUseDifferentCachedMaps)
{
    kvdbstore::KVDBManager mgr;

    cm::store::NamespaceId nsId {"ns"};
    cm::store::MockICMStoreNSReader r;

    ON_CALL(r, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));

    EXPECT_CALL(r, getKVDBByName("countries"))
        .Times(::testing::Exactly(1))
        .WillOnce(::testing::Return(
            cm::store::dataType::KVDB {"id-countries", "countries", json::Json {R"({"k":"v"})"}, true}));
    EXPECT_CALL(r, getKVDBByName("cities"))
        .Times(::testing::Exactly(1))
        .WillOnce(
            ::testing::Return(cm::store::dataType::KVDB {"id-cities", "cities", json::Json {R"({"k":"v"})"}, true}));

    auto hA = mgr.getKVDBHandler(r, "countries");
    auto hB = mgr.getKVDBHandler(r, "cities");
    ASSERT_NE(hA, nullptr);
    ASSERT_NE(hB, nullptr);

    const json::Json& a = hA->get("k");
    const json::Json& b = hB->get("k");

    EXPECT_EQ(a, json::Json {"\"v\""});
    EXPECT_EQ(b, json::Json {"\"v\""});
    EXPECT_NE(std::addressof(a), std::addressof(b)); // different maps → different addresses
}

// Parallel requests for the same namespace and dbName must return the same pointer.
TEST(KVDB_Manager_Unit, ParallelWarm_NoRefetch_SamePointer)
{
    kvdbstore::KVDBManager mgr;
    cm::store::NamespaceId nsId {"ns"};
    ::testing::NiceMock<cm::store::MockICMStoreNSReader> ns;

    // Same namespace for all calls
    ON_CALL(ns, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));
    // Provide a single payload; only the warm-up should fetch
    ON_CALL(ns, getKVDBByName("db"))
        .WillByDefault(
            ::testing::Invoke([&](const std::string&)
                              { return cm::store::dataType::KVDB {"id-1", "db", json::Json {R"({"k":"v"})"}, true}; }));

    // Warm the cache so concurrent calls hit the same cached map
    auto warm = mgr.getKVDBHandler(ns, "db");
    ASSERT_NE(warm, nullptr);
    const json::Json& winner = warm->get("k");

    // No further fetches are expected after warm-up
    ::testing::Mock::VerifyAndClearExpectations(&ns);
    EXPECT_CALL(ns, getKVDBByName("db")).Times(0);

    // Fan-out many threads reading the same entry at the same time
    constexpr int kThreads = 12;
    auto refs = parallelReadRefs(mgr, ns, "db", "k", kThreads);

    // Every reference must match the pre-warmed one
    for (int i = 0; i < kThreads; ++i) EXPECT_EQ(std::addressof(refs[i].get()), std::addressof(winner));
}

// Cold race where multiple threads request the same namespace and dbName
TEST(KVDB_Manager_Unit, ParallelColdRace_EventualConvergence)
{
    kvdbstore::KVDBManager mgr;
    cm::store::NamespaceId nsId {"ns"};
    ::testing::NiceMock<cm::store::MockICMStoreNSReader> ns;

    // All calls refer to the same namespace
    ON_CALL(ns, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));

    // Cold start: allow fetch during the race; we count how many happened
    std::atomic<int> fetches {0};
    ON_CALL(ns, getKVDBByName("db"))
        .WillByDefault(::testing::Invoke(
            [&](const std::string&)
            {
                fetches.fetch_add(1, std::memory_order_relaxed);
                return cm::store::dataType::KVDB {"id-n", "db", json::Json {R"({"k":"v"})"}, true};
            }));

    // Launch threads without pre-warming (true cold race)
    constexpr int kThreads = 12;
    auto refs = parallelReadRefs(mgr, ns, "db", "k", kThreads);

    // There may be multiple underlying buffers if multiple threads built before publishing
    std::unordered_set<const json::Json*> uniq;
    uniq.reserve(kThreads);
    for (const auto& rr : refs) uniq.insert(std::addressof(rr.get()));
    EXPECT_GE(uniq.size(), 1u);
    EXPECT_LE(uniq.size(), static_cast<size_t>(kThreads));
    EXPECT_GE(fetches.load(), 1);

    // After the dust settles, querying again should either reuse the last map
    // or, if everything expired, rebuild once. Both paths are valid.
    const auto before = fetches.load();

    auto after = mgr.getKVDBHandler(ns, "db");
    ASSERT_NE(after, nullptr);
    const json::Json& asv = after->get("k");
    EXPECT_EQ(asv, json::Json {"\"v\""});

    const auto after_fetches = fetches.load();
    if (after_fetches == before)
    {
        // Cache still alive: the address must belong to the set seen by the threads.
        EXPECT_EQ(uniq.count(std::addressof(asv)), 1u);
    }
    else
    {
        // Cache expired: a refetch/rebuild occurred, address can differ.
        EXPECT_GT(after_fetches, before);
    }
}

// Parallel requests for the same namespace and dbName must share the cached map.
TEST(KVDB_Manager_Unit, ParallelSameNsSameDb_SharedCachedMap)
{
    kvdbstore::KVDBManager mgr;

    cm::store::NamespaceId nsId {"ns"};
    ::testing::NiceMock<cm::store::MockICMStoreNSReader> ns;

    // All threads use identical namespace
    ON_CALL(ns, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));

    // Allow a single fetch during warm-up; block any later fetches
    std::atomic<int> fetches {0};
    ON_CALL(ns, getKVDBByName("db"))
        .WillByDefault(::testing::Invoke(
            [&](const std::string&)
            {
                fetches.fetch_add(1, std::memory_order_relaxed);
                return cm::store::dataType::KVDB {"id-1", "db", json::Json {R"({"k":"v"})"}, true};
            }));

    // Warm the cache once and capture the “winner” buffer
    auto warm = mgr.getKVDBHandler(ns, "db");
    ASSERT_NE(warm, nullptr);
    const json::Json& winner = warm->get("k");

    ::testing::Mock::VerifyAndClearExpectations(&ns);
    EXPECT_CALL(ns, getKVDBByName("db")).Times(0);

    // Many parallel reads, all should point to the same buffer
    constexpr int kThreads = 12;
    auto refs = parallelReadRefs(mgr, ns, "db", "k", kThreads);

    // Unblock and ensure everyone sees the same address
    for (int i = 0; i < kThreads; ++i)
    {
        EXPECT_EQ(std::addressof(refs[i].get()), std::addressof(winner));
    }

    EXPECT_GE(fetches.load(), 1);
}

// Parallel requests for different namespaces must be isolated.
TEST(KVDB_Manager_Unit, ParallelTwoNamespaces_Isolated)
{
    kvdbstore::KVDBManager mgr;
    cm::store::NamespaceId nsA {"A"}, nsB {"B"};
    ::testing::NiceMock<cm::store::MockICMStoreNSReader> rA, rB;

    // Distinct namespaces to distinct cache buckets
    ON_CALL(rA, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsA));
    ON_CALL(rB, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsB));
    ON_CALL(rA, getKVDBByName("db"))
        .WillByDefault(
            ::testing::Invoke([&](const std::string&)
                              { return cm::store::dataType::KVDB {"id-a", "db", json::Json {R"({"k":"a"})"}, true}; }));
    ON_CALL(rB, getKVDBByName("db"))
        .WillByDefault(
            ::testing::Invoke([&](const std::string&)
                              { return cm::store::dataType::KVDB {"id-b", "db", json::Json {R"({"k":"b"})"}, true}; }));

    // Seed both caches and record their buffer pointers
    auto hA0 = mgr.getKVDBHandler(rA, "db");
    auto hB0 = mgr.getKVDBHandler(rB, "db");
    ASSERT_NE(hA0, nullptr);
    ASSERT_NE(hB0, nullptr);
    const json::Json& a = hA0->get("k");
    const json::Json& b = hB0->get("k");

    // Freeze fetches; subsequent reads must be cache-only
    ::testing::Mock::VerifyAndClearExpectations(&rA);
    ::testing::Mock::VerifyAndClearExpectations(&rB);
    EXPECT_CALL(rA, getKVDBByName("db")).Times(0);
    EXPECT_CALL(rB, getKVDBByName("db")).Times(0);

    // Blast parallel reads into each namespace independently
    constexpr int kThreads = 8;
    auto refsA = parallelReadRefs(mgr, rA, "db", "k", kThreads);
    auto refsB = parallelReadRefs(mgr, rB, "db", "k", kThreads);

    // Verify independence: all A addresses equal &a, all B addresses equal &b, and &a != &b
    for (int i = 0; i < kThreads; ++i) EXPECT_EQ(std::addressof(refsA[i].get()), std::addressof(a));
    for (int i = 0; i < kThreads; ++i) EXPECT_EQ(std::addressof(refsB[i].get()), std::addressof(b));
    EXPECT_NE(std::addressof(a), std::addressof(b));
}

// Same namespace but different dbName entries must be isolated.
TEST(KVDB_Manager_Unit, ParallelSameNs_DifferentDb_Isolated)
{
    kvdbstore::KVDBManager mgr;
    cm::store::NamespaceId nsId {"ns"};
    ::testing::NiceMock<cm::store::MockICMStoreNSReader> r;

    // One namespace, two logical DBs → two independent cached maps
    ON_CALL(r, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));
    ON_CALL(r, getKVDBByName("countries"))
        .WillByDefault(::testing::Invoke(
            [&](const std::string&)
            { return cm::store::dataType::KVDB {"id-c", "countries", json::Json {R"({"k":"v"})"}, true}; }));
    ON_CALL(r, getKVDBByName("cities"))
        .WillByDefault(::testing::Invoke(
            [&](const std::string&)
            { return cm::store::dataType::KVDB {"id-t", "cities", json::Json {R"({"k":"v"})"}, true}; }));

    // Seed both DBs and capture distinct buffer pointers
    auto hC = mgr.getKVDBHandler(r, "countries");
    auto hT = mgr.getKVDBHandler(r, "cities");
    ASSERT_NE(hC, nullptr);
    ASSERT_NE(hT, nullptr);
    const json::Json& c = hC->get("k");
    const json::Json& t = hT->get("k");

    // Further fetches are disallowed; reads must hit the cache
    ::testing::Mock::VerifyAndClearExpectations(&r);
    EXPECT_CALL(r, getKVDBByName("countries")).Times(0);
    EXPECT_CALL(r, getKVDBByName("cities")).Times(0);

    // Parallel reads for each DB name
    constexpr int kThreads = 8;
    auto refsC = parallelReadRefs(mgr, r, "countries", "k", kThreads);
    auto refsT = parallelReadRefs(mgr, r, "cities", "k", kThreads);

    // Verify isolation: each group matches its own address, and both groups differ
    for (int i = 0; i < kThreads; ++i) EXPECT_EQ(std::addressof(refsC[i].get()), std::addressof(c));
    for (int i = 0; i < kThreads; ++i) EXPECT_EQ(std::addressof(refsT[i].get()), std::addressof(t));
    EXPECT_NE(std::addressof(c), std::addressof(t));
}
