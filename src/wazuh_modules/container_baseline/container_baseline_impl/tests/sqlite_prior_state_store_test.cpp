#include "reconcile/reconcile_types.hpp"
#include "reconcile/sqlite_prior_state_store.hpp"

#include <gtest/gtest.h>

using namespace wazuh::container_baseline;

namespace {

EmittedRow row(std::string id, std::string index, std::string json)
{
    return EmittedRow{std::move(id), kOperationCreate, std::move(index), std::move(json), 1};
}

} // namespace

TEST(SqlitePriorStateStore, ApplyLoadRoundTrip)
{
    SqlitePriorStateStore store(":memory:");
    RowDelta delta;
    delta.creates.push_back(row("c1:proc:1", "wazuh-states-inventory-processes", R"({"pid":1})"));
    delta.creates.push_back(row("c1:proc:2", "wazuh-states-inventory-processes", R"({"pid":2})"));
    store.applyDelta("c1", delta);

    const auto fingerprints = store.load("c1");

    ASSERT_EQ(fingerprints.size(), 2u);
    ASSERT_EQ(fingerprints.count("c1:proc:1"), 1u);
    EXPECT_EQ(fingerprints.at("c1:proc:1").index, "wazuh-states-inventory-processes");
    EXPECT_EQ(fingerprints.at("c1:proc:1").content_hash, contentHash(R"({"pid":1})"));
}

TEST(SqlitePriorStateStore, DeleteRemovesRow)
{
    SqlitePriorStateStore store(":memory:");
    RowDelta add;
    add.creates.push_back(row("c1:proc:1", "idx", "{}"));
    store.applyDelta("c1", add);

    RowDelta del;
    del.deletes.push_back(RowRef{"c1:proc:1", "idx"});
    store.applyDelta("c1", del);

    EXPECT_TRUE(store.load("c1").empty());
}

TEST(SqlitePriorStateStore, ModifyUpdatesHashAndVersion)
{
    SqlitePriorStateStore store(":memory:");
    RowDelta add;
    add.creates.push_back(row("c1:x", "idx", R"({"v":1})"));
    store.applyDelta("c1", add);

    RowDelta mod;
    EmittedRow changed = row("c1:x", "idx", R"({"v":2})");
    changed.version = 5;
    mod.modifies.push_back(changed);
    store.applyDelta("c1", mod);

    const auto fingerprints = store.load("c1");
    EXPECT_EQ(fingerprints.at("c1:x").content_hash, contentHash(R"({"v":2})"));
    EXPECT_EQ(fingerprints.at("c1:x").version, 5u);
}

TEST(SqlitePriorStateStore, KnownContainerIdsAndPurge)
{
    SqlitePriorStateStore store(":memory:");
    RowDelta a;
    a.creates.push_back(row("c1:x", "idx", "{}"));
    store.applyDelta("c1", a);
    RowDelta b;
    b.creates.push_back(row("c2:x", "idx", "{}"));
    store.applyDelta("c2", b);

    EXPECT_EQ(store.knownContainerIds().size(), 2u);

    store.purgeContainer("c1");
    const auto remaining = store.knownContainerIds();
    ASSERT_EQ(remaining.size(), 1u);
    EXPECT_EQ(remaining[0], "c2");
    EXPECT_TRUE(store.load("c1").empty());
}

TEST(SqlitePriorStateStore, CountByIndex)
{
    SqlitePriorStateStore store(":memory:");
    RowDelta delta;
    delta.creates.push_back(row("c1:a", "idxA", "{}"));
    delta.creates.push_back(row("c1:b", "idxA", "{}"));
    delta.creates.push_back(row("c1:c", "idxB", "{}"));
    store.applyDelta("c1", delta);

    const auto counts = store.countByIndex();
    EXPECT_EQ(counts.at("idxA"), 2u);
    EXPECT_EQ(counts.at("idxB"), 1u);
}
