#include "baseline_rows.hpp"
#include "container_baseline_scanner.hpp"
#include "pid_resolver.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
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

TEST(BaselineOrchestrator, MissingMonitoredPathIsReportedAsItsOwnFactNotAsIncompleteness)
{
    // D17 / C24. An absent configured root used to set `partial`, which
    // suppresses delete detection — and because the condition is STATIC (the
    // directory is simply not in the image), the suppression never lifted and
    // that container's deletions were never reported at all.
    //
    // The walk DID look, so this is a fact about the container, not a failure
    // to observe it. It is counted and reported, and `partial` stays clear.
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
    EXPECT_EQ(status->roots_missing, 1) << "an absent monitored path must be reported as absent";
    EXPECT_EQ(status->roots_scanned, 0);
    EXPECT_FALSE(status->partial) << "and must not suppress delete detection for the whole container (C24)";
    EXPECT_FALSE(status->rootfs_unreadable) << "the rootfs was addressable; only the root was not there";
    EXPECT_FALSE(status->row_cap_hit);
}

TEST(BaselineOrchestrator, AnAbsentRootDoesNotStopOtherRootsFromBeingScanned)
{
    // The shape C24 actually costs: one bad entry in <directories> switched
    // deletions off for every other entry too.
    TempTree tree;
    tree.writeFile("real.txt", "x");

    Recorder rec;
    const auto discover = []() -> std::vector<ContainerIdentity>
    {
        return {MakeIdentity("c1")};
    };

    const auto pids = PidIndex::FromMap({{"c1", {::getpid()}}});

    RunFimDbsyncBaselineFrom(discover,
                             pids,
                             {PathFor("/definitely/not/a/real/path"), PathFor(tree.path())},
                             rec.rowSink(),
                             rec.statusSink());

    EXPECT_FALSE(rec.rows.empty()) << "the root that does exist must still be walked";

    const auto* status = rec.statusFor("c1");
    ASSERT_NE(status, nullptr);
    EXPECT_EQ(status->roots_missing, 1);
    EXPECT_EQ(status->roots_scanned, 1);
    EXPECT_FALSE(status->partial);
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

// --- ListContainers: unavailability must not present as "nothing exists" ----
//
// These pin the contract the deletion paths depend on. Both consumers
// (syscollector's sweepContainerRowsNotIn, FIM's sweepStale) delete the rows of
// every container absent from this list, so a failed query that reported zero
// containers would delete every container's stored rows on a momentary
// connector blip and re-insert them on the next cycle.

TEST(ListContainers, UnreachableConnectorReportsFailureNotAnEmptyNode)
{
    int sinkCalls = 0;
    const auto sink = [&sinkCalls](const std::string&) { ++sinkCalls; };

    // A path with no listener: indistinguishable, at the wire level, from a
    // connector that is starting up, restarting, or wedged.
    const int listed = wazuh::container_baseline::ListContainers(
        "/tmp/container-baseline-test-no-such-socket.sock", sink);

    EXPECT_LT(listed, 0) << "an unreachable connector must not report 0 containers";
    EXPECT_EQ(sinkCalls, 0);
}

TEST(ListContainers, EmptySocketPathReportsFailure)
{
    const auto sink = [](const std::string&) {};

    EXPECT_LT(wazuh::container_baseline::ListContainers("", sink), 0);
}

TEST(ListContainers, TheWarmupRetryIsPaidOncePerProcessNotOnEveryCall)
{
    const auto sink = [](const std::string&) {};
    const char* socket = "/tmp/container-baseline-test-no-such-socket.sock";

    // Discovery retries a missing or still-warming connector for up to
    // kListRetryAttempts * kListRetryDelay (5s), which is what lets a
    // one-shot baseline outlast a connector's first enumeration. That budget
    // must be spent once, not on every call: this baseline also runs on
    // syscollector's recurring cycle, and a node that genuinely has no
    // containers would otherwise add the full 5s to every scan, forever,
    // because the "have we ever seen a container" latch never sets there.
    (void)wazuh::container_baseline::ListContainers(socket, sink);

    const auto start = std::chrono::steady_clock::now();
    (void)wazuh::container_baseline::ListContainers(socket, sink);
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    // Deliberately a loose bound with a large margin: the retrying path takes
    // ~5000ms and the non-retrying one takes ~0ms, so this cannot be flaky
    // without the behaviour having actually regressed. Only the second call is
    // asserted on, so the test does not depend on gtest's execution order.
    EXPECT_LT(elapsed, 1000) << "a later call re-paid the warm-up retry budget (" << elapsed << "ms)";
}

// ---------------------------------------------------------------------------
// Single-container baseline (#37532): the entry point the eBPF reconcile
// consumer drives. Exercised through the *From seam, so none of this needs a
// running connector or a real container.
// ---------------------------------------------------------------------------

namespace {

using wazuh::container_baseline::RunFimDbsyncBaselineForContainerFrom;

/// A MonitoredPath naming one file rather than a tree — what a path reconcile
/// passes. recursion_level is irrelevant for a non-directory, and 0 ("entry
/// only") is what a caller would naturally write.
MonitoredPath FilePathFor(const std::string& file)
{
    MonitoredPath mp;
    mp.internal_path   = file;
    mp.recursion_level = 0;
    return mp;
}

} // namespace

TEST(SingleContainerBaseline, BaselinesOnlyTheContainerItWasAskedFor)
{
    TempTree tree;
    tree.writeFile("f1", "one");

    Recorder rec;
    const auto discover = []
    { return std::vector<ContainerIdentity>{MakeIdentity("c1"), MakeIdentity("c2")}; };
    const auto self = ::getpid();
    const auto pids = PidIndex::FromMap({{"c1", {self}}, {"c2", {self}}});

    const int baselined = RunFimDbsyncBaselineForContainerFrom(
        discover, "c2", pids, {PathFor(tree.path())}, rec.rowSink(), rec.statusSink());

    EXPECT_EQ(1, baselined);
    ASSERT_EQ(1u, rec.statuses.size());
    EXPECT_EQ("c2", rec.statuses[0].container_id);

    for (const auto& row : rec.rows)
    {
        EXPECT_EQ("c2", row.container_id);
    }
    EXPECT_FALSE(rec.rows.empty());
}

TEST(SingleContainerBaseline, RereadingOneFileEmitsExactlyOneRow)
{
    TempTree tree;
    tree.writeFile("wanted", "x");
    tree.writeFile("ignored", "y");

    Recorder rec;
    const auto discover = [] { return std::vector<ContainerIdentity>{MakeIdentity("c1")}; };
    const auto pids     = PidIndex::FromMap({{"c1", {::getpid()}}});

    // This is what makes a separate "stat these paths" API unnecessary: a
    // MonitoredPath naming a file walks to exactly that file.
    const int baselined = RunFimDbsyncBaselineForContainerFrom(
        discover, "c1", pids, {FilePathFor(tree.path() + "/wanted")}, rec.rowSink(), rec.statusSink());

    EXPECT_EQ(1, baselined);
    ASSERT_EQ(1u, rec.rows.size());
    EXPECT_NE(std::string::npos, rec.rows[0].json.find("/wanted"));
    EXPECT_EQ(std::string::npos, rec.rows[0].json.find("/ignored"));
}

TEST(SingleContainerBaseline, AContainerTheConnectorDoesNotKnowIsNotBaselined)
{
    Recorder rec;
    const auto discover = [] { return std::vector<ContainerIdentity>{MakeIdentity("c1")}; };
    const auto pids     = PidIndex::FromMap({{"c1", {::getpid()}}});

    // 0, not an error: "gone" is the whole-node stale sweep's call to make,
    // against a list it has confirmed reachable. One absence proves nothing.
    EXPECT_EQ(0, RunFimDbsyncBaselineForContainerFrom(discover, "c-unknown", pids, {PathFor("/tmp")},
                                                      rec.rowSink(), rec.statusSink()));
    EXPECT_TRUE(rec.rows.empty());
    EXPECT_TRUE(rec.statuses.empty());
}

TEST(SingleContainerBaseline, AContainerWithNoLivePidIsNotBaselined)
{
    Recorder rec;
    const auto discover = [] { return std::vector<ContainerIdentity>{MakeIdentity("c1")}; };

    EXPECT_EQ(0, RunFimDbsyncBaselineForContainerFrom(discover, "c1", PidIndex::FromMap({}),
                                                      {PathFor("/tmp")}, rec.rowSink(), rec.statusSink()));
    EXPECT_TRUE(rec.statuses.empty());
}

TEST(SingleContainerBaseline, AnEmptyContainerIdIsNotBaselined)
{
    Recorder rec;
    const auto discover = [] { return std::vector<ContainerIdentity>{MakeIdentity("c1")}; };

    EXPECT_EQ(0, RunFimDbsyncBaselineForContainerFrom(discover, "", PidIndex::FromMap({{"c1", {::getpid()}}}),
                                                      {PathFor("/tmp")}, rec.rowSink(), rec.statusSink()));
    EXPECT_TRUE(rec.rows.empty());
}

TEST(SingleContainerBaseline, AnEscapingPathIsDroppedAndTheScanReportedPartial)
{
    TempTree tree;
    tree.writeFile("f1", "one");

    Recorder rec;
    const auto discover = [] { return std::vector<ContainerIdentity>{MakeIdentity("c1")}; };
    const auto pids     = PidIndex::FromMap({{"c1", {::getpid()}}});

    // The second path is what a container could put in an eBPF event. It must
    // not be resolved, and its absence must not read as a complete scan.
    const int baselined = RunFimDbsyncBaselineForContainerFrom(
        discover, "c1", pids, {PathFor(tree.path()), FilePathFor("/etc/../../../../root/.ssh/id_rsa")},
        rec.rowSink(), rec.statusSink());

    EXPECT_EQ(1, baselined);
    ASSERT_EQ(1u, rec.statuses.size());
    EXPECT_TRUE(rec.statuses[0].partial)
        << "a dropped path left the scan looking complete, so delete detection would run";

    for (const auto& row : rec.rows)
    {
        EXPECT_EQ(std::string::npos, row.json.find("id_rsa"));
    }
}

TEST(SingleContainerBaseline, AnEmptyPathIsAlsoDroppedAndReportedPartial)
{
    TempTree tree;
    tree.writeFile("f1", "one");

    Recorder rec;
    const auto discover = [] { return std::vector<ContainerIdentity>{MakeIdentity("c1")}; };
    const auto pids     = PidIndex::FromMap({{"c1", {::getpid()}}});

    RunFimDbsyncBaselineForContainerFrom(discover, "c1", pids, {PathFor(tree.path()), FilePathFor("")},
                                         rec.rowSink(), rec.statusSink());

    ASSERT_EQ(1u, rec.statuses.size());
    EXPECT_TRUE(rec.statuses[0].partial);
}

TEST(SingleContainerBaseline, AWellFormedPathSetIsNotReportedPartial)
{
    TempTree tree;
    tree.writeFile("f1", "one");

    Recorder rec;
    const auto discover = [] { return std::vector<ContainerIdentity>{MakeIdentity("c1")}; };
    const auto pids     = PidIndex::FromMap({{"c1", {::getpid()}}});

    // The control for the two tests above: without this, "partial" could be
    // stuck on and they would pass for the wrong reason.
    RunFimDbsyncBaselineForContainerFrom(discover, "c1", pids, {PathFor(tree.path())}, rec.rowSink(),
                                         rec.statusSink());

    ASSERT_EQ(1u, rec.statuses.size());
    EXPECT_FALSE(rec.statuses[0].partial);
}

TEST(SingleContainerBaseline, WhenEveryPathIsRejectedNothingIsBaselined)
{
    Recorder rec;
    const auto discover = [] { return std::vector<ContainerIdentity>{MakeIdentity("c1")}; };
    const auto pids     = PidIndex::FromMap({{"c1", {::getpid()}}});

    // Returning 1 here would announce a successful walk that emitted no rows,
    // which a caller doing delete detection reads as "this container has no
    // files" and acts on.
    EXPECT_EQ(0, RunFimDbsyncBaselineForContainerFrom(discover, "c1", pids, {FilePathFor("/etc/../root")},
                                                      rec.rowSink(), rec.statusSink()));
    EXPECT_TRUE(rec.rows.empty());
    EXPECT_TRUE(rec.statuses.empty());
}

TEST(SingleContainerBaseline, NoPathsAtAllMeansNothingIsBaselined)
{
    Recorder rec;
    const auto discover = [] { return std::vector<ContainerIdentity>{MakeIdentity("c1")}; };
    const auto pids     = PidIndex::FromMap({{"c1", {::getpid()}}});

    EXPECT_EQ(0, RunFimDbsyncBaselineForContainerFrom(discover, "c1", pids, {}, rec.rowSink(),
                                                      rec.statusSink()));
    EXPECT_TRUE(rec.statuses.empty());
}

TEST(SingleContainerBaseline, StatusSinkIsOptional)
{
    TempTree tree;
    tree.writeFile("f1", "one");

    Recorder rec;
    const auto discover = [] { return std::vector<ContainerIdentity>{MakeIdentity("c1")}; };
    const auto pids     = PidIndex::FromMap({{"c1", {::getpid()}}});

    // Including with a rejected path, where the partial-forcing wrapper must not
    // be installed over a null sink.
    EXPECT_EQ(1, RunFimDbsyncBaselineForContainerFrom(
                     discover, "c1", pids, {PathFor(tree.path()), FilePathFor("/a/../b")}, rec.rowSink()));
    EXPECT_FALSE(rec.rows.empty());
}
