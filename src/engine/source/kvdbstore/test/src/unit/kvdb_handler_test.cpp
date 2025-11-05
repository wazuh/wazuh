#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <gtest/gtest.h>

#include <base/json.hpp>
#include <kvdb/kvdbHandler.hpp>

// Basic get() and contains() functionality
TEST(KVDB_Handler_Unit, GetAndContainsBasic)
{
    auto map = std::make_shared<kvdbStore::KVMap>();
    map->emplace("s", json::Json {"\"str\""});
    map->emplace("n", json::Json {"123"});
    map->emplace("o", json::Json {R"({"a":1})"});

    kvdbStore::KVDBHandler h(map);

    EXPECT_TRUE(h.contains("s"));
    EXPECT_TRUE(h.contains("n"));
    EXPECT_TRUE(h.contains("o"));
    EXPECT_FALSE(h.contains("missing"));

    const json::Json& v1 = h.get("s");
    EXPECT_EQ(std::addressof(v1), &map->at("s")); // no copy, direct reference to stored Json

    const json::Json& v2 = h.get("n");
    EXPECT_EQ(std::addressof(v2), &map->at("n"));

    const json::Json& v3 = h.get("o");
    EXPECT_EQ(std::addressof(v3), &map->at("o"));

    EXPECT_THROW((void)h.get("missing"), std::out_of_range);
}

// Views returned by different handlers over the same map point to the same data
TEST(KVDB_Handler_Unit, ViewsAreStableWhileMapLives)
{
    auto map = std::make_shared<kvdbStore::KVMap>();
    map->emplace("k", json::Json {"\"v\""});

    kvdbStore::KVDBHandler h1(map);
    kvdbStore::KVDBHandler h2(map);

    const json::Json& r1 = h1.get("k");
    const json::Json& r2 = h2.get("k");

    EXPECT_EQ(std::addressof(r1), std::addressof(r2));
    EXPECT_EQ(std::addressof(r1), &map->at("k"));
}

// Safe behavior with a null map
TEST(KVDB_Handler_Unit, NullMapIsSafe)
{
    std::shared_ptr<kvdbStore::KVMap> nullMap; // nullptr
    kvdbStore::KVDBHandler h(nullMap);

    EXPECT_FALSE(h.contains("k"));
    EXPECT_THROW((void)h.get("k"), std::logic_error);
}

// Empty key and empty value are handled as regular entries
TEST(KVDB_Handler_Unit, SupportsEmptyKeyAndEmptyValue)
{
    auto map = std::make_shared<kvdbStore::KVMap>();
    map->emplace("", json::Json {"\"\""});

    kvdbStore::KVDBHandler h(map);

    EXPECT_TRUE(h.contains(""));
    const json::Json& v = h.get("");
    EXPECT_EQ(std::addressof(v), &map->at(""));
}

// Many concurrent readers on the same handler/key are safe
TEST(KVDB_Handler_Unit, ConcurrentReadersAreSafe)
{
    auto map = std::make_shared<kvdbStore::KVMap>();
    map->emplace("k", json::Json {"\"value\""});
    kvdbStore::KVDBHandler h(map);

    constexpr int kThreads = 8;
    constexpr int kItersPerThread = 2000;

    const json::Json* expected = &map->at("k");

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
    auto map = std::make_shared<kvdbStore::KVMap>();
    std::string big(20000, 'x');
    const std::string json_text = "\"" + big + "\"";
    map->emplace("big", json::Json {json_text.c_str()});
    kvdbStore::KVDBHandler h(map);

    const json::Json& r = h.get("big");
    EXPECT_EQ(std::addressof(r), &map->at("big")); // same instance, no copy
}