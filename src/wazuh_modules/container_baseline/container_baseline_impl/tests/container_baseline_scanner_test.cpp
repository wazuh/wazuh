#include "baseline_rows.hpp"
#include "container_baseline_scanner.hpp"
#include "pid_resolver.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

using wazuh::container_baseline::ContainerContext;
using wazuh::container_baseline::ContainerIdentity;
using wazuh::container_baseline::ContainerStatus;
using wazuh::container_baseline::DbsyncRow;
using wazuh::container_baseline::MonitoredPath;
using wazuh::container_baseline::PidIndex;
using wazuh::container_baseline::RunFimDbsyncBaselineFrom;
using wazuh::container_baseline::RunSyscollectorDbsyncBaselineFrom;

namespace {

/// Records everything the orchestrator emitted, in order, so the ordering
/// contract the consumers rely on can be asserted.
struct Recorder
{
    // "row:<container_id>" / "status:<container_id>" in emission order.
    std::vector<std::string>     sequence;
    std::vector<DbsyncRow>       rows;
    std::vector<ContainerStatus> statuses;

    wazuh::container_baseline::DbsyncRowSink rowSink()
    {
        return [this](const DbsyncRow& row)
        {
            sequence.push_back("row:" + row.container_id);
            rows.push_back(row);
        };
    }

    wazuh::container_baseline::ContainerStatusSink statusSink()
    {
        return [this](const ContainerStatus& status)
        {
            sequence.push_back("status:" + status.container_id);
            statuses.push_back(status);
        };
    }

    [[nodiscard]] const ContainerStatus* statusFor(const std::string& id) const
    {
        for (const auto& status : statuses)
        {
            if (status.container_id == id) return &status;
        }
        return nullptr;
    }

    /// Every row for one container must sit in a single unbroken run that ends
    /// at that container's status callback. Both consumers open a scoped
    /// transaction on the first row and close it on the status, so an
    /// interleaving here would split a container's rows across transactions —
    /// and the tail would be seen as deletions.
    [[nodiscard]] bool rowsAreContiguousPerContainer() const
    {
        std::vector<std::string> finished;
        std::string current;

        for (const auto& event : sequence)
        {
            const auto colon = event.find(':');
            const auto kind = event.substr(0, colon);
            const auto id = event.substr(colon + 1);

            if (kind == "row")
            {
                if (id != current)
                {
                    for (const auto& done : finished)
                    {
                        if (done == id) return false; // reopened a finished container
                    }
                    if (!current.empty()) finished.push_back(current);
                    current = id;
                }
            }
            else // status
            {
                if (!current.empty() && current != id) return false;
                if (!current.empty()) finished.push_back(current);
                current.clear();
            }
        }
        return true;
    }
};

ContainerIdentity MakeIdentity(const std::string& id, const std::string& digest = {})
{
    auto ctx = std::make_shared<ContainerContext>();
    ctx->runtime      = "docker";
    ctx->name         = id + "-name";
    ctx->image_digest = digest;

    return ContainerIdentity{id, ctx};
}

/// A directory tree standing in for a container rootfs. WalkContainerPath()
/// prefixes /proc/<pid>/root, which for our own PID resolves back to the host,
/// so an absolute temp path is walkable without a real container.
class TempTree
{
    public:
        TempTree()
        {
            char tmpl[] = "/tmp/cbaseline_orch_test_XXXXXX";
            path_ = ::mkdtemp(tmpl);
        }

        ~TempTree()
        {
            if (!path_.empty()) (void)std::system(("rm -rf '" + path_ + "'").c_str());
        }

        TempTree(const TempTree&) = delete;
        TempTree& operator=(const TempTree&) = delete;

        void writeFile(const std::string& name, const std::string& contents) const
        {
            std::ofstream f(path_ + "/" + name);
            f << contents;
        }

        [[nodiscard]] const std::string& path() const { return path_; }

    private:
        std::string path_;
};

MonitoredPath PathFor(const std::string& dir, size_t maxFiles = 0)
{
    MonitoredPath mp;
    mp.internal_path   = dir;
    mp.recursion_level = -1;
    mp.max_files       = maxFiles;
    mp.max_hash_bytes  = 0;
    return mp;
}

} // namespace

// The contiguity assertion below is only worth anything if the checker can
// actually fail, so pin its behaviour on synthetic sequences first.
TEST(BaselineOrchestratorSelfCheck, ContiguityCheckerAcceptsAWellFormedSequence)
{
    Recorder rec;
    rec.sequence = {"row:c1", "row:c1", "status:c1", "row:c2", "status:c2"};
    EXPECT_TRUE(rec.rowsAreContiguousPerContainer());
}

TEST(BaselineOrchestratorSelfCheck, ContiguityCheckerRejectsInterleavedRows)
{
    Recorder rec;
    rec.sequence = {"row:c1", "row:c2", "row:c1", "status:c1", "status:c2"};
    EXPECT_FALSE(rec.rowsAreContiguousPerContainer());
}

TEST(BaselineOrchestratorSelfCheck, ContiguityCheckerRejectsRowsAfterTheContainersStatus)
{
    Recorder rec;
    rec.sequence = {"row:c1", "status:c1", "row:c1", "status:c1"};
    EXPECT_FALSE(rec.rowsAreContiguousPerContainer());
}

TEST(BaselineOrchestratorSelfCheck, ContiguityCheckerRejectsAStatusForTheWrongContainer)
{
    Recorder rec;
    rec.sequence = {"row:c1", "status:c2"};
    EXPECT_FALSE(rec.rowsAreContiguousPerContainer());
}

TEST(BaselineOrchestrator, ContainerWithNoLivePidIsSkippedEntirely)
{
    // The distinction the FIM consumer got wrong: a container that is known but
    // has no live PID must produce no rows AND no status, and must not be
    // counted — so the caller cannot mistake it for "scanned and empty", which
    // is what turned a container restart into a full delete sweep.
    TempTree tree;
    tree.writeFile("a.txt", "x");

    Recorder rec;
    const auto discover = []() -> std::vector<ContainerIdentity>
    {
        return {MakeIdentity("stopped-container")};
    };

    const auto pids = PidIndex::FromMap({}); // nothing running

    const int baselined = RunFimDbsyncBaselineFrom(discover, pids, {PathFor(tree.path())},
                                                   rec.rowSink(), rec.statusSink());

    EXPECT_EQ(baselined, 0);
    EXPECT_TRUE(rec.rows.empty());
    EXPECT_TRUE(rec.statuses.empty());
}

TEST(BaselineOrchestrator, CountsOnlyContainersItActuallyScanned)
{
    TempTree tree;
    tree.writeFile("a.txt", "x");

    Recorder rec;
    const auto discover = []() -> std::vector<ContainerIdentity>
    {
        return {MakeIdentity("live-1"), MakeIdentity("stopped"), MakeIdentity("live-2")};
    };

    const auto self = ::getpid();
    const auto pids = PidIndex::FromMap({{"live-1", {self}}, {"live-2", {self}}});

    const int baselined = RunFimDbsyncBaselineFrom(discover, pids, {PathFor(tree.path())},
                                                   rec.rowSink(), rec.statusSink());

    EXPECT_EQ(baselined, 2);
    ASSERT_EQ(rec.statuses.size(), 2U);
    EXPECT_EQ(rec.statusFor("stopped"), nullptr);
    EXPECT_NE(rec.statusFor("live-1"), nullptr);
    EXPECT_NE(rec.statusFor("live-2"), nullptr);
}

TEST(BaselineOrchestrator, FimRowsAreContiguousAndFollowedByThatContainersStatus)
{
    // The contract both consumers depend on for streaming: they open a scoped
    // transaction on a container's first row and finalise it on that
    // container's status callback.
    TempTree tree;
    tree.writeFile("a.txt", "1");
    tree.writeFile("b.txt", "2");
    tree.writeFile("c.txt", "3");

    Recorder rec;
    const auto discover = []() -> std::vector<ContainerIdentity>
    {
        return {MakeIdentity("c1"), MakeIdentity("c2")};
    };

    const auto self = ::getpid();
    const auto pids = PidIndex::FromMap({{"c1", {self}}, {"c2", {self}}});

    RunFimDbsyncBaselineFrom(discover, pids, {PathFor(tree.path())}, rec.rowSink(), rec.statusSink());

    EXPECT_TRUE(rec.rowsAreContiguousPerContainer()) << "a container's rows were interleaved or reopened";

    // Every emitted row must be attributed, and the last event must be a status.
    ASSERT_FALSE(rec.sequence.empty());
    EXPECT_EQ(rec.sequence.back().rfind("status:", 0), 0U);

    for (const auto& row : rec.rows)
    {
        EXPECT_FALSE(row.container_id.empty());
        EXPECT_EQ(row.table, "file_entry");
    }
}

TEST(BaselineOrchestrator, MissingMonitoredPathIsReportedAsAPartialScan)
{
    // root_missing was previously computed and discarded, so a configured path
    // absent from the image looked identical to "this container has no files"
    // and its stored rows were deleted.
    Recorder rec;
    const auto discover = []() -> std::vector<ContainerIdentity>
    {
        return {MakeIdentity("c1")};
    };

    const auto pids = PidIndex::FromMap({{"c1", {::getpid()}}});

    const int baselined = RunFimDbsyncBaselineFrom(
        discover, pids, {PathFor("/definitely/not/a/real/path")}, rec.rowSink(), rec.statusSink());

    EXPECT_EQ(baselined, 1);
    EXPECT_TRUE(rec.rows.empty());

    const auto* status = rec.statusFor("c1");
    ASSERT_NE(status, nullptr);
    EXPECT_TRUE(status->partial) << "an absent monitored path must not look like a complete empty scan";
}

TEST(BaselineOrchestrator, TruncatedWalkIsReportedAsAPartialScan)
{
    TempTree tree;
    for (int i = 0; i < 6; ++i)
    {
        tree.writeFile("f" + std::to_string(i) + ".txt", "x");
    }

    Recorder rec;
    const auto discover = []() -> std::vector<ContainerIdentity>
    {
        return {MakeIdentity("c1")};
    };

    const auto pids = PidIndex::FromMap({{"c1", {::getpid()}}});

    RunFimDbsyncBaselineFrom(discover, pids, {PathFor(tree.path(), /*maxFiles=*/2)},
                             rec.rowSink(), rec.statusSink());

    EXPECT_LE(rec.rows.size(), 2U);

    const auto* status = rec.statusFor("c1");
    ASSERT_NE(status, nullptr);
    EXPECT_TRUE(status->partial) << "hitting the row cap must suppress delete detection";
}

TEST(BaselineOrchestrator, CompleteWalkIsNotReportedAsPartial)
{
    TempTree tree;
    tree.writeFile("a.txt", "x");

    Recorder rec;
    const auto discover = []() -> std::vector<ContainerIdentity>
    {
        return {MakeIdentity("c1")};
    };

    const auto pids = PidIndex::FromMap({{"c1", {::getpid()}}});

    RunFimDbsyncBaselineFrom(discover, pids, {PathFor(tree.path())}, rec.rowSink(), rec.statusSink());

    const auto* status = rec.statusFor("c1");
    ASSERT_NE(status, nullptr);
    EXPECT_FALSE(status->partial) << "a complete scan must allow delete detection";
}

TEST(BaselineOrchestrator, StatusSinkIsOptional)
{
    TempTree tree;
    tree.writeFile("a.txt", "x");

    Recorder rec;
    const auto discover = []() -> std::vector<ContainerIdentity>
    {
        return {MakeIdentity("c1")};
    };

    const auto pids = PidIndex::FromMap({{"c1", {::getpid()}}});

    // Must not dereference an empty std::function.
    EXPECT_EQ(RunFimDbsyncBaselineFrom(discover, pids, {PathFor(tree.path())}, rec.rowSink()), 1);
    EXPECT_FALSE(rec.rows.empty());
}

TEST(BaselineOrchestrator, EmptyDiscoveryProducesNothing)
{
    Recorder rec;
    const auto discover = []() -> std::vector<ContainerIdentity> { return {}; };

    EXPECT_EQ(RunFimDbsyncBaselineFrom(discover, PidIndex::FromMap({}), {}, rec.rowSink(), rec.statusSink()), 0);
    EXPECT_TRUE(rec.sequence.empty());
}

TEST(BaselineOrchestrator, SyscollectorRowsAreContiguousAndAttributed)
{
    Recorder rec;
    const auto discover = []() -> std::vector<ContainerIdentity>
    {
        return {MakeIdentity("c1", "sha256:aaa"), MakeIdentity("c2", "sha256:aaa")};
    };

    const auto self = ::getpid();
    const auto pids = PidIndex::FromMap({{"c1", {self}}, {"c2", {self}}});

    const int baselined = RunSyscollectorDbsyncBaselineFrom(discover, pids, rec.rowSink(), rec.statusSink());

    EXPECT_EQ(baselined, 2);
    EXPECT_TRUE(rec.rowsAreContiguousPerContainer()) << "a container's rows were interleaved or reopened";
    ASSERT_EQ(rec.statuses.size(), 2U);

    for (const auto& row : rec.rows)
    {
        EXPECT_FALSE(row.container_id.empty());
        EXPECT_FALSE(row.table.empty());
        EXPECT_EQ(row.table.rfind("dbsync_", 0), 0U) << "unexpected table name: " << row.table;
    }
}

TEST(BaselineOrchestrator, ReplicasOfOneImageReportTheSameImageDerivedRows)
{
    // Two containers sharing an image digest and a rootfs must agree on the
    // image-derived classes, whether the second one was served from the cache
    // or scanned. This is the observable half of the dedup; the cache's own
    // hit/miss behaviour is covered in image_content_cache_test.cpp.
    Recorder rec;
    const auto discover = []() -> std::vector<ContainerIdentity>
    {
        return {MakeIdentity("c1", "sha256:same"), MakeIdentity("c2", "sha256:same")};
    };

    const auto self = ::getpid();
    const auto pids = PidIndex::FromMap({{"c1", {self}}, {"c2", {self}}});

    RunSyscollectorDbsyncBaselineFrom(discover, pids, rec.rowSink(), rec.statusSink());

    const auto countFor = [&rec](const std::string& id, const std::string& table)
    {
        size_t n = 0;
        for (const auto& row : rec.rows)
        {
            if (row.container_id == id && row.table == table) ++n;
        }
        return n;
    };

    for (const auto* table : {"dbsync_users", "dbsync_groups", "dbsync_packages", "dbsync_osinfo"})
    {
        EXPECT_EQ(countFor("c1", table), countFor("c2", table)) << "mismatch for " << table;
    }
}

TEST(BaselineOrchestrator, DiscoveryIsInvokedExactlyOncePerRun)
{
    // Re-discovering per container would reintroduce the 1+N IPC pattern.
    int calls = 0;
    Recorder rec;

    const auto discover = [&calls]() -> std::vector<ContainerIdentity>
    {
        ++calls;
        return {MakeIdentity("c1"), MakeIdentity("c2")};
    };

    const auto self = ::getpid();
    const auto pids = PidIndex::FromMap({{"c1", {self}}, {"c2", {self}}});

    RunSyscollectorDbsyncBaselineFrom(discover, pids, rec.rowSink(), rec.statusSink());

    EXPECT_EQ(calls, 1);
}

TEST(BaselineOrchestrator, DeadPidsInTheSnapshotDoNotBlockAScannableContainer)
{
    // The PID index is a point-in-time snapshot, so by scan time some entries
    // may have exited. Taking pids.front() blindly produced an empty scan for a
    // container that was perfectly alive under a later PID.
    TempTree tree;
    tree.writeFile("a.txt", "x");

    Recorder rec;
    const auto discover = []() -> std::vector<ContainerIdentity>
    {
        return {MakeIdentity("c1")};
    };

    // PID 0 has no /proc entry, so it stands in for "listed in the snapshot but
    // already gone"; getpid() is the live candidate further down the list.
    const auto pids = PidIndex::FromMap({{"c1", {0, ::getpid()}}});

    const int baselined = RunFimDbsyncBaselineFrom(discover, pids, {PathFor(tree.path())},
                                                   rec.rowSink(), rec.statusSink());

    EXPECT_EQ(baselined, 1);
    EXPECT_FALSE(rec.rows.empty()) << "a live PID later in the list was not used";

    const auto* status = rec.statusFor("c1");
    ASSERT_NE(status, nullptr);
    EXPECT_FALSE(status->partial);
}

TEST(BaselineOrchestrator, ContainerWhoseEveryPidIsGoneIsTreatedAsUnscanned)
{
    TempTree tree;
    tree.writeFile("a.txt", "x");

    Recorder rec;
    const auto discover = []() -> std::vector<ContainerIdentity>
    {
        return {MakeIdentity("c1")};
    };

    const auto pids = PidIndex::FromMap({{"c1", {0}}}); // listed, but unusable

    const int baselined = RunFimDbsyncBaselineFrom(discover, pids, {PathFor(tree.path())},
                                                   rec.rowSink(), rec.statusSink());

    // Same handling as "no live PID at all": no rows, no status, not counted —
    // so the caller cannot read it as a complete empty scan.
    EXPECT_EQ(baselined, 0);
    EXPECT_TRUE(rec.rows.empty());
    EXPECT_TRUE(rec.statuses.empty());
}
