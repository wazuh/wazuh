#include "reconcile/container_inventory_reconciler.hpp"
#include "reconcile/sqlite_prior_state_store.hpp"

#include <stdexcept>

#include <gtest/gtest.h>

using namespace wazuh::container_baseline;

namespace {

class FakeLister : public IContainerLister
{
public:
    ContainerListing listing;
    ContainerListing list() override { return listing; }
};

ContainerIdentity ident(std::string id)
{
    return ContainerIdentity{std::move(id), nullptr};
}

EmittedRow erow(std::string id, std::string index, std::string json)
{
    return EmittedRow{std::move(id), kOperationCreate, std::move(index), std::move(json), 1};
}

CollectorResult okDim(std::string index, std::vector<EmittedRow> rows)
{
    CollectorResult result;
    result.index  = std::move(index);
    result.status = CollectStatus::Ok;
    result.rows   = std::move(rows);
    return result;
}

int countOps(const std::vector<EmittedRow>& rows, int op)
{
    int n = 0;
    for (const auto& r : rows)
    {
        if (r.operation == op) ++n;
    }
    return n;
}

/// @brief Forwards every call to a real store except applyDelta(), which throws
/// once (simulating a crash between the sink call and persisting prior state)
/// instead of delegating. Used to verify emit-first ordering: the sink must have
/// already run by the time this throws, and prior state must be left exactly as
/// it was, so the next pass safely re-emits rather than losing the row.
class ThrowOnceDecoratorStore : public IPriorStateStore
{
public:
    explicit ThrowOnceDecoratorStore(IPriorStateStore& inner) : m_inner(inner) {}

    bool throwOnNextApply = false;

    FingerprintMap load(const std::string& container_id) override { return m_inner.load(container_id); }
    std::vector<std::string> knownContainerIds() override { return m_inner.knownContainerIds(); }
    std::unordered_map<std::string, std::size_t> countByIndex() override { return m_inner.countByIndex(); }
    void purgeContainer(const std::string& container_id) override { m_inner.purgeContainer(container_id); }

    void applyDelta(const std::string& container_id, const RowDelta& delta) override
    {
        if (throwOnNextApply)
        {
            throwOnNextApply = false;
            throw std::runtime_error("simulated crash before persisting prior state");
        }
        m_inner.applyDelta(container_id, delta);
    }

private:
    IPriorStateStore& m_inner;
};

} // namespace

TEST(ContainerInventoryReconciler, UnavailableListingSkipsPass)
{
    FakeLister lister;
    lister.listing.available = false;
    SqlitePriorStateStore store(":memory:");
    std::vector<EmittedRow> emitted;

    CollectFn collect = [](const ContainerIdentity&) -> std::optional<std::vector<CollectorResult>> {
        ADD_FAILURE() << "collect must not run when the module is unavailable";
        return std::nullopt;
    };
    ContainerInventoryReconciler rec(lister, store, collect, [&](const EmittedRow& r) { emitted.push_back(r); });

    const auto stats = rec.reconcile(ReconcileScope{});

    EXPECT_TRUE(stats.skipped_unavailable);
    EXPECT_TRUE(emitted.empty());
}

TEST(ContainerInventoryReconciler, FirstPassCreatesAndSuppressesDeletes)
{
    FakeLister lister;
    lister.listing.available  = true;
    lister.listing.identities = {ident("c1")};
    SqlitePriorStateStore store(":memory:");

    RowDelta seed;
    seed.creates.push_back(erow("c1:old", "idx", "{}"));
    store.applyDelta("c1", seed);

    std::vector<EmittedRow> emitted;
    CollectFn collect = [](const ContainerIdentity&) -> std::optional<std::vector<CollectorResult>> {
        return std::vector<CollectorResult>{okDim("idx", {erow("c1:new", "idx", R"({"a":1})")})};
    };
    ContainerInventoryReconciler rec(lister, store, collect, [&](const EmittedRow& r) { emitted.push_back(r); });

    const auto stats = rec.reconcile(ReconcileScope{});

    EXPECT_EQ(stats.creates, 1);
    EXPECT_EQ(stats.deletes, 0);
    EXPECT_EQ(countOps(emitted, kOperationDelete), 0);
}

TEST(ContainerInventoryReconciler, SecondPassDeletesVanishedRow)
{
    FakeLister lister;
    lister.listing.available  = true;
    lister.listing.identities = {ident("c1")};
    SqlitePriorStateStore store(":memory:");
    std::vector<EmittedRow> emitted;

    std::vector<CollectorResult> scan{okDim("idx", {erow("c1:a", "idx", "{}"), erow("c1:b", "idx", "{}")})};
    CollectFn collect = [&scan](const ContainerIdentity&) { return scan; };
    ContainerInventoryReconciler rec(lister, store, collect, [&](const EmittedRow& r) { emitted.push_back(r); });

    rec.reconcile(ReconcileScope{});

    emitted.clear();
    scan = {okDim("idx", {erow("c1:a", "idx", "{}")})};
    const auto stats = rec.reconcile(ReconcileScope{});

    EXPECT_EQ(stats.deletes, 1);
    ASSERT_EQ(countOps(emitted, kOperationDelete), 1);
    EXPECT_EQ(store.load("c1").count("c1:b"), 0u);
}

TEST(ContainerInventoryReconciler, ContainerExitDeletesAllRowsAndPurges)
{
    FakeLister lister;
    lister.listing.available  = true;
    lister.listing.identities = {ident("c1")};
    SqlitePriorStateStore store(":memory:");
    std::vector<EmittedRow> emitted;

    CollectFn collect = [](const ContainerIdentity&) -> std::optional<std::vector<CollectorResult>> {
        return std::vector<CollectorResult>{okDim("idx", {erow("c1:x", "idx", "{}"), erow("c1:y", "idx", "{}")})};
    };
    ContainerInventoryReconciler rec(lister, store, collect, [&](const EmittedRow& r) { emitted.push_back(r); });

    rec.reconcile(ReconcileScope{});

    emitted.clear();
    lister.listing.identities.clear();
    const auto stats = rec.reconcile(ReconcileScope{});

    EXPECT_EQ(stats.deletes, 2);
    EXPECT_EQ(countOps(emitted, kOperationDelete), 2);
    EXPECT_TRUE(store.knownContainerIds().empty());
}

TEST(ContainerInventoryReconciler, NotAddressableLeavesPriorStateIntact)
{
    FakeLister lister;
    lister.listing.available  = true;
    lister.listing.identities = {ident("c1")};
    SqlitePriorStateStore store(":memory:");

    RowDelta seed;
    seed.creates.push_back(erow("c1:keep", "idx", "{}"));
    store.applyDelta("c1", seed);

    std::vector<EmittedRow> emitted;
    CollectFn collect = [](const ContainerIdentity&) -> std::optional<std::vector<CollectorResult>> {
        return std::nullopt;
    };
    ContainerInventoryReconciler rec(lister, store, collect, [&](const EmittedRow& r) { emitted.push_back(r); });

    const auto stats = rec.reconcile(ReconcileScope{});

    EXPECT_EQ(stats.containers_scanned, 0);
    EXPECT_TRUE(emitted.empty());
    EXPECT_EQ(store.load("c1").count("c1:keep"), 1u);
}

TEST(ContainerInventoryReconciler, FailedDimIsNotDiffedToDelete)
{
    FakeLister lister;
    lister.listing.available  = true;
    lister.listing.identities = {ident("c1")};
    SqlitePriorStateStore store(":memory:");
    std::vector<EmittedRow> emitted;

    std::vector<CollectorResult> scan{okDim("idx", {erow("c1:x", "idx", "{}")})};
    CollectFn collect = [&scan](const ContainerIdentity&) { return scan; };
    ContainerInventoryReconciler rec(lister, store, collect, [&](const EmittedRow& r) { emitted.push_back(r); });

    rec.reconcile(ReconcileScope{});

    emitted.clear();
    CollectorResult failed;
    failed.index  = "idx";
    failed.status = CollectStatus::Failed;
    scan          = {failed};
    const auto stats = rec.reconcile(ReconcileScope{});

    EXPECT_EQ(stats.deletes, 0);
    EXPECT_EQ(store.load("c1").count("c1:x"), 1u);
}

TEST(ContainerInventoryReconciler, DocumentLimitSuppressesExcessCreates)
{
    FakeLister lister;
    lister.listing.available  = true;
    lister.listing.identities = {ident("c1")};
    SqlitePriorStateStore store(":memory:");
    std::vector<EmittedRow> emitted;

    CollectFn collect = [](const ContainerIdentity&) -> std::optional<std::vector<CollectorResult>> {
        return std::vector<CollectorResult>{
            okDim("idx", {erow("c1:1", "idx", "{}"), erow("c1:2", "idx", "{}"), erow("c1:3", "idx", "{}")})};
    };
    DocumentLimits limits{{"idx", 2}};
    ContainerInventoryReconciler rec(lister, store, collect, [&](const EmittedRow& r) { emitted.push_back(r); },
                                     limits);

    const auto stats = rec.reconcile(ReconcileScope{});

    EXPECT_EQ(stats.creates, 2);
    EXPECT_EQ(countOps(emitted, kOperationCreate), 2);
}

TEST(ContainerInventoryReconciler, TargetedScopeReconcilesOnlyOneContainer)
{
    FakeLister lister;
    lister.listing.available  = true;
    lister.listing.identities = {ident("c1"), ident("c2")};
    SqlitePriorStateStore store(":memory:");
    std::vector<std::string> scanned;

    CollectFn collect = [&scanned](const ContainerIdentity& id) -> std::optional<std::vector<CollectorResult>> {
        scanned.push_back(id.container_id);
        return std::vector<CollectorResult>{okDim("idx", {erow(id.container_id + ":x", "idx", "{}")})};
    };
    ContainerInventoryReconciler rec(lister, store, collect, [](const EmittedRow&) {});

    ReconcileScope scope;
    scope.single_container_id = "c2";
    const auto stats = rec.reconcile(scope);

    EXPECT_EQ(stats.containers_scanned, 1);
    ASSERT_EQ(scanned.size(), 1u);
    EXPECT_EQ(scanned[0], "c2");
}

TEST(ContainerInventoryReconciler, EmitFirstOrderingSurvivesCrashBeforeApplyDelta)
{
    FakeLister lister;
    lister.listing.available  = true;
    lister.listing.identities = {ident("c1")};
    SqlitePriorStateStore realStore(":memory:");
    ThrowOnceDecoratorStore store(realStore);
    std::vector<EmittedRow> emitted;

    CollectFn collect = [](const ContainerIdentity&) -> std::optional<std::vector<CollectorResult>> {
        return std::vector<CollectorResult>{okDim("idx", {erow("c1:new", "idx", R"({"a":1})")})};
    };
    ContainerInventoryReconciler rec(lister, store, collect, [&](const EmittedRow& r) { emitted.push_back(r); });

    store.throwOnNextApply = true;
    EXPECT_THROW(rec.reconcile(ReconcileScope{}), std::runtime_error);

    // Emit-first ordering: the sink already received the row before applyDelta()
    // "crashed", so the row was never actually lost from the caller's point of view.
    ASSERT_EQ(emitted.size(), 1u);
    EXPECT_EQ(emitted[0].id, "c1:new");

    // The crash happened before delegating to the real store, so prior state was
    // never written — the next pass must not have "already sent" this row and
    // must re-emit it, not silently drop it.
    emitted.clear();
    const auto stats = rec.reconcile(ReconcileScope{});

    EXPECT_EQ(stats.creates, 1);
    ASSERT_EQ(emitted.size(), 1u);
    EXPECT_EQ(emitted[0].id, "c1:new");
}
