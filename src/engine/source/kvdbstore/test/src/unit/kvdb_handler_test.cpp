#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <gtest/gtest.h>

#include <base/json.hpp>
#include <kvdbstore/kvdbHandler.hpp>

namespace
{
// Helper: build a KVMapStore from an initializer (for test convenience)
std::shared_ptr<kvdbstore::KVMapStore> makeStore(std::initializer_list<std::pair<std::string, const char*>> entries)
{
    auto store = std::make_shared<kvdbstore::KVMapStore>();
    for (auto& [k, v] : entries)
    {
        store->entries.emplace(k, json::Json {v});
    }
    return store;
}
} // namespace

// Basic get() and contains() functionality
TEST(KVDB_Handler_Unit, GetAndContainsBasic)
{
    auto store = makeStore({{"s", "\"str\""}, {"n", "123"}, {"o", R"({"a":1})"}});

    kvdbstore::KVDBHandler h(store);

    EXPECT_TRUE(h.contains("s"));
    EXPECT_TRUE(h.contains("n"));
    EXPECT_TRUE(h.contains("o"));
    EXPECT_FALSE(h.contains("missing"));

    const json::Json& v1 = h.get("s");
    EXPECT_EQ(std::addressof(v1), &store->entries.at("s"));

    const json::Json& v2 = h.get("n");
    EXPECT_EQ(std::addressof(v2), &store->entries.at("n"));

    const json::Json& v3 = h.get("o");
    EXPECT_EQ(std::addressof(v3), &store->entries.at("o"));

    EXPECT_THROW((void)h.get("missing"), std::out_of_range);
}

// Views returned by different handlers over the same store point to the same data
TEST(KVDB_Handler_Unit, ViewsAreStableWhileMapLives)
{
    auto store = makeStore({{"k", "\"v\""}});

    kvdbstore::KVDBHandler h1(store);
    kvdbstore::KVDBHandler h2(store);

    const json::Json& r1 = h1.get("k");
    const json::Json& r2 = h2.get("k");

    EXPECT_EQ(std::addressof(r1), std::addressof(r2));
    EXPECT_EQ(std::addressof(r1), &store->entries.at("k"));
}

// Safe behavior with a null store
TEST(KVDB_Handler_Unit, NullMapIsSafe)
{
    std::shared_ptr<kvdbstore::KVMapStore> nullStore;
    kvdbstore::KVDBHandler h(nullStore);

    EXPECT_FALSE(h.contains("k"));
    EXPECT_THROW((void)h.get("k"), std::logic_error);
}

// Empty key and empty value are handled as regular entries
TEST(KVDB_Handler_Unit, SupportsEmptyKeyAndEmptyValue)
{
    auto store = makeStore({{"", "\"\""}});

    kvdbstore::KVDBHandler h(store);

    EXPECT_TRUE(h.contains(""));
    const json::Json& v = h.get("");
    EXPECT_EQ(std::addressof(v), &store->entries.at(""));
}

// Many concurrent readers on the same handler/key are safe
TEST(KVDB_Handler_Unit, ConcurrentReadersAreSafe)
{
    auto store = makeStore({{"k", "\"value\""}});
    kvdbstore::KVDBHandler h(store);

    constexpr int kThreads = 8;
    constexpr int kItersPerThread = 2000;

    const json::Json* expected = &store->entries.at("k");

    std::atomic<int> okCount {0};
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t)
    {
        threads.emplace_back(
            [&]
            {
                for (int i = 0; i < kItersPerThread; ++i)
                {
                    const json::Json& r = h.get("k");
                    if (std::addressof(r) == expected)
                    {
                        ++okCount;
                    }
                }
            });
    }
    for (auto& th : threads) th.join();

    EXPECT_EQ(okCount.load(), kThreads * kItersPerThread);
}

// Large values are returned verbatim (pointer to the stored Json)
TEST(KVDB_Handler_Unit, LargeValueIsReturnedVerbatim)
{
    auto store = std::make_shared<kvdbstore::KVMapStore>();
    std::string big(20000, 'x');
    const std::string json_text = "\"" + big + "\"";
    store->entries.emplace("big", json::Json {json_text.c_str()});
    kvdbstore::KVDBHandler h(store);

    const json::Json& r = h.get("big");
    EXPECT_EQ(std::addressof(r), &store->entries.at("big"));
}
