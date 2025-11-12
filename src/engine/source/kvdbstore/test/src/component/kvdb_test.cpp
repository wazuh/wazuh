#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <gtest/gtest.h>

#include <base/json.hpp>
#include <cmstore/icmstore.hpp>
#include <cmstore/mockcmstore.hpp>
#include <cmstore/datakvdb.hpp>

#include <kvdb/kvdbManager.hpp>

namespace
{
// Helper: run N parallel reads to the same (ns, db, key) and collect pointers.
inline std::vector<std::reference_wrapper<const json::Json>> parallelReadRefs(kvdbStore::KVDBManager& mgr,
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
                // Spin barrier to align thread start
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

// Build once and then serve from the cache: no refetch, same pointer.
TEST(KVDB_Component, BuildOnceThenCache_NoRefetch_SamePointer)
{
    kvdbStore::KVDBManager mgr;
    cm::store::NamespaceId nsId {"ns"};
    ::testing::NiceMock<cm::store::MockICMStoreNSReader> seed, again;

    ON_CALL(seed, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));
    ON_CALL(again, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));

    EXPECT_CALL(seed, getKVDBByName("kv"))
        .Times(1)
        .WillOnce(::testing::Return(cm::store::dataType::KVDB::fromJson(json::Json {
            R"({"id":"00000000-0000-0000-0000-000000000001","title":"kv","content":{"k":"v1"},"enabled":true})"})));

    // First build
    auto h1 = mgr.getKVDBHandler(seed, "kv");
    ASSERT_NE(h1, nullptr);
    const json::Json& v1 = h1->get("k");
    EXPECT_EQ(v1, json::Json {"\"v1\""});

    // No refetch on cache hit
    ::testing::Mock::VerifyAndClearExpectations(&seed);
    EXPECT_CALL(again, getKVDBByName("kv")).Times(0);

    auto h2 = mgr.getKVDBHandler(again, "kv");
    ASSERT_NE(h2, nullptr);
    const json::Json& v2 = h2->get("k");

    EXPECT_EQ(v2, json::Json {"\"v1\""});
    EXPECT_EQ(std::addressof(v1), std::addressof(v2)); // same underlying pointer (same cached map)
}

// After all handlers are released, a subsequent request rebuilds with new content.
TEST(KVDB_Component, ExpireAllHandlers_RebuildWithNewContent)
{
    kvdbStore::KVDBManager mgr;
    cm::store::NamespaceId nsId {"ns"};
    ::testing::NiceMock<cm::store::MockICMStoreNSReader> r1, r2;

    ON_CALL(r1, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));
    ON_CALL(r2, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));

    EXPECT_CALL(r1, getKVDBByName("kv"))
        .Times(1)
        .WillOnce(::testing::Return(cm::store::dataType::KVDB::fromJson(json::Json {
            R"({"id":"00000000-0000-0000-0000-000000000001","title":"kv","content":{"k":"v1"},"enabled":true})"})));

    // Build and drop
    auto h1 = mgr.getKVDBHandler(r1, "kv");
    ASSERT_NE(h1, nullptr);
    h1.reset(); // all handlers gone → cache can expire

    // Next call must refetch with new payload
    EXPECT_CALL(r2, getKVDBByName("kv"))
        .Times(1)
        .WillOnce(::testing::Return(cm::store::dataType::KVDB::fromJson(json::Json {
            R"({"id":"00000000-0000-0000-0000-000000000001","title":"kv","content":{"k":"v2"},"enabled":true})"})));

    auto h2 = mgr.getKVDBHandler(r2, "kv");
    ASSERT_NE(h2, nullptr);
    const json::Json& v2 = h2->get("k");
    EXPECT_EQ(v2, json::Json {"\"v2\""});
}

// Different namespaces and db names are fully isolated (distinct caches).
TEST(KVDB_Component, CrossNamespaceAndDb_IsolatedCaches)
{
    kvdbStore::KVDBManager mgr;
    cm::store::NamespaceId nsA {"A"}, nsB {"B"};
    ::testing::NiceMock<cm::store::MockICMStoreNSReader> a1, a2, b1;

    ON_CALL(a1, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsA));
    ON_CALL(a2, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsA));
    ON_CALL(b1, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsB));

    EXPECT_CALL(a1, getKVDBByName("db1"))
        .Times(1)
        .WillOnce(::testing::Return(cm::store::dataType::KVDB::fromJson(json::Json {
            R"({"id":"00000000-0000-0000-0000-0000000000A1","title":"db1","content":{"k":"A1"},"enabled":true})"})));
    EXPECT_CALL(a2, getKVDBByName("db2"))
        .Times(1)
        .WillOnce(::testing::Return(cm::store::dataType::KVDB::fromJson(json::Json {
            R"({"id":"00000000-0000-0000-0000-0000000000A2","title":"db2","content":{"k":"A2"},"enabled":true})"})));
    EXPECT_CALL(b1, getKVDBByName("db1"))
        .Times(1)
        .WillOnce(::testing::Return(cm::store::dataType::KVDB::fromJson(json::Json {
            R"({"id":"00000000-0000-0000-0000-0000000000B1","title":"db1","content":{"k":"B1"},"enabled":true})"})));

    auto hA1 = mgr.getKVDBHandler(a1, "db1");
    auto hA2 = mgr.getKVDBHandler(a2, "db2");
    auto hB1 = mgr.getKVDBHandler(b1, "db1");
    ASSERT_NE(hA1, nullptr);
    ASSERT_NE(hA2, nullptr);
    ASSERT_NE(hB1, nullptr);

    const json::Json& vA1 = hA1->get("k");
    const json::Json& vA2 = hA2->get("k");
    const json::Json& vB1 = hB1->get("k");

    EXPECT_EQ(vA1, json::Json {"\"A1\""});
    EXPECT_EQ(vA2, json::Json {"\"A2\""});
    EXPECT_EQ(vB1, json::Json {"\"B1\""});

    // Distinct caches → distinct pointers across {ns,db}
    EXPECT_NE(std::addressof(vA1), std::addressof(vA2));
    EXPECT_NE(std::addressof(vA1), std::addressof(vB1));
    EXPECT_NE(std::addressof(vA2), std::addressof(vB1));
}

// Concurrent cold race on the same (ns, db) eventually converges to a stable cache.
TEST(KVDB_Component, ConcurrentColdRace_EventualConvergence)
{
    kvdbStore::KVDBManager mgr;
    cm::store::NamespaceId nsId {"ns"};
    ::testing::NiceMock<cm::store::MockICMStoreNSReader> ns;

    ON_CALL(ns, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));

    std::atomic<int> fetches {0};
    ON_CALL(ns, getKVDBByName("kv"))
        .WillByDefault(::testing::Invoke(
            [&](const std::string&)
            {
                fetches.fetch_add(1, std::memory_order_relaxed);
                return cm::store::dataType::KVDB::fromJson(json::Json {
                    R"({"id":"00000000-0000-0000-0000-0000000000FF","title":"kv","content":{"k":"v"},"enabled":true})"});
            }));

    // Parallel cold start (no pre-warm)
    constexpr int kThreads = 16;
    auto refs = parallelReadRefs(mgr, ns, "kv", "k", kThreads);

    // Multiple builds may happen before publish; we only require convergence afterwards.
    std::unordered_set<const json::Json*> uniq;
    uniq.reserve(refs.size());
    for (const auto& r : refs) uniq.insert(std::addressof(r.get()));
    EXPECT_GE(uniq.size(), 1u);
    EXPECT_LE(uniq.size(), static_cast<size_t>(kThreads));
    EXPECT_GE(fetches.load(), 1);

    // A follow-up call must either hit the existing cache (pointer in uniq)
    // or rebuild once if everything already expired.
    const auto before = fetches.load();

    auto h = mgr.getKVDBHandler(ns, "kv");
    ASSERT_NE(h, nullptr);
    const json::Json& v = h->get("k");
    EXPECT_EQ(v, json::Json {"\"v\""});

    const auto p = std::addressof(v);
    const auto after = fetches.load();
    if (after == before)
    {
        EXPECT_EQ(uniq.count(p), 1u);
    }
    else
    {
        EXPECT_GT(after, before);
    }
}

// Non-object payloads are invalid and must throw during build.
TEST(KVDB_Component, InvalidPayload_Throws)
{
    kvdbStore::KVDBManager mgr;
    cm::store::NamespaceId nsId {"ns"};
    ::testing::NiceMock<cm::store::MockICMStoreNSReader> badStr, badArr;

    ON_CALL(badStr, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));
    ON_CALL(badArr, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));

    EXPECT_CALL(badStr, getKVDBByName("kv"))
        .Times(1)
        .WillOnce(::testing::Return(cm::store::dataType::KVDB {
            "00000000-0000-0000-0000-00000000BAD1", "kv", json::Json {"\"not-an-object\""}, true }));
    EXPECT_CALL(badArr, getKVDBByName("kv"))
        .Times(1)
        .WillOnce(::testing::Return(cm::store::dataType::KVDB {
            "00000000-0000-0000-0000-00000000BAD2", "kv", json::Json {"[1,2,3]"}, true }));

    // Manager expects a JSON object to enumerate top-level keys.
    EXPECT_THROW({ (void)mgr.getKVDBHandler(badStr, "kv"); }, std::runtime_error);
    EXPECT_THROW({ (void)mgr.getKVDBHandler(badArr, "kv"); }, std::runtime_error);
}

// Mixed value types (object, array, number, boolean, string, null) are supported as values.
TEST(KVDB_Component, NestedValues_AccessAndEquality)
{
    kvdbStore::KVDBManager mgr;
    cm::store::NamespaceId nsId {"ns"};
    ::testing::NiceMock<cm::store::MockICMStoreNSReader> ns;

    ON_CALL(ns, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));
    EXPECT_CALL(ns, getKVDBByName("kv"))
        .Times(1)
        .WillOnce(::testing::Return(cm::store::dataType::KVDB::fromJson(json::Json {
            R"({
                "id":"00000000-0000-0000-0000-0000000000CC",
                "title":"kv",
                "enabled":true,
                "content":{
                    "obj":{"a":1,"b":[2,3]},
                    "arr":[10,20,30],
                    "num":42,
                    "boo":true,
                    "str":"text",
                    "nil":null
                }
            })"})));

    auto h = mgr.getKVDBHandler(ns, "kv");
    ASSERT_NE(h, nullptr);

    const json::Json& obj = h->get("obj");
    const json::Json& arr = h->get("arr");
    const json::Json& num = h->get("num");
    const json::Json& boo = h->get("boo");
    const json::Json& str = h->get("str");
    const json::Json& nil = h->get("nil");

    EXPECT_EQ(obj, json::Json {R"({"a":1,"b":[2,3]})"});
    EXPECT_EQ(arr, json::Json {"[10,20,30]"});
    EXPECT_EQ(num, json::Json {"42"});
    EXPECT_EQ(boo, json::Json {"true"});
    EXPECT_EQ(str, json::Json {"\"text\""});
    EXPECT_EQ(nil, json::Json {"null"});
}
