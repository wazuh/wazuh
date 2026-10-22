#include "pid_resolver.hpp"

#include <algorithm>

#include <gtest/gtest.h>

using wazuh::container_baseline::ExtractContainerIdFromCgroupPath;
using wazuh::container_baseline::SelectCgroupPathFromProcCgroup;

TEST(ExtractContainerIdFromCgroupPath, ContainerdSystemdDriver)
{
    const std::string path =
        "/kubepods.slice/kubepods-burstable.slice/"
        "cri-containerd-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.scope";
    EXPECT_EQ(ExtractContainerIdFromCgroupPath(path),
              "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
}

TEST(ExtractContainerIdFromCgroupPath, CrioSystemdDriver)
{
    const std::string path = "/kubepods.slice/crio-abcdef1234567890abcdef1234567890abcdef12.scope";
    EXPECT_EQ(ExtractContainerIdFromCgroupPath(path), "abcdef1234567890abcdef1234567890abcdef12");
}

TEST(ExtractContainerIdFromCgroupPath, DockerViaCriDockerd)
{
    const std::string path = "/kubepods.slice/docker-fedcba0987654321fedcba0987654321fedcba09.scope";
    EXPECT_EQ(ExtractContainerIdFromCgroupPath(path), "fedcba0987654321fedcba0987654321fedcba09");
}

TEST(ExtractContainerIdFromCgroupPath, CgroupfsDriverBareHexLeaf)
{
    const std::string path = "/docker/1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    EXPECT_EQ(ExtractContainerIdFromCgroupPath(path),
              "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
}

TEST(ExtractContainerIdFromCgroupPath, OuterDockerWrapReadsLeafNotMiddleSegment)
{
    // kind/k3d nest a docker-*.scope segment ABOVE the real container leaf —
    // the extractor must key off the leaf, not any intermediate segment.
    const std::string path =
        "/docker/0000111122223333444455556666777788889999aaaabbbbccccdddd/"
        "kubepods.slice/cri-containerd-eeee111122223333444455556666777788889999aaaabbbb.scope";
    EXPECT_EQ(ExtractContainerIdFromCgroupPath(path),
              "eeee111122223333444455556666777788889999aaaabbbb");
}

TEST(ExtractContainerIdFromCgroupPath, InitSystemContainerIsFoundFromItsChildCgroup)
{
    // An image whose PID 1 is an init system puts every process in a CHILD
    // cgroup, so no process ever names the container's own cgroup. Reading only
    // the leaf found nothing and the container contributed no PIDs at all, so
    // the baseline reported zero containers scanned while the connector was
    // reporting one known. Must agree with container_instances'
    // extractContainerId(), which scans the same way.
    EXPECT_EQ(ExtractContainerIdFromCgroupPath(
                  "/system.slice/docker-b1b6ccc5c74210b8218705474216b5066936036017bb89d9fdaf1a1959425c5d.scope/"
                  "init.scope"),
              "b1b6ccc5c74210b8218705474216b5066936036017bb89d9fdaf1a1959425c5d");

    EXPECT_EQ(ExtractContainerIdFromCgroupPath(
                  "/docker/0000111122223333444455556666777788889999aaaabbbbccccdddd/system.slice/containerd.service"),
              "0000111122223333444455556666777788889999aaaabbbbccccdddd");
}

TEST(ExtractContainerIdFromCgroupPath, SystemSliceReturnsEmpty)
{
    EXPECT_EQ(ExtractContainerIdFromCgroupPath("/system.slice/kubelet.service"), "");
}

TEST(ExtractContainerIdFromCgroupPath, EmptyPathReturnsEmpty)
{
    EXPECT_EQ(ExtractContainerIdFromCgroupPath(""), "");
}

TEST(ExtractContainerIdFromCgroupPath, RejectsNonHexScopeBody)
{
    // A systemd scope whose body isn't a hex id is not a container leaf.
    EXPECT_EQ(ExtractContainerIdFromCgroupPath("/system.slice/docker-notahexid.scope"), "");
    EXPECT_EQ(ExtractContainerIdFromCgroupPath("/system.slice/session-42.scope"), "");
}

TEST(ExtractContainerIdFromCgroupPath, RejectsTooShortIds)
{
    // Scope-form ids need >= 12 hex chars, bare leaves >= 32.
    EXPECT_EQ(ExtractContainerIdFromCgroupPath("/kubepods.slice/docker-abc123.scope"), "");
    EXPECT_EQ(ExtractContainerIdFromCgroupPath("/docker/abcdef1234"), "");
}

TEST(ExtractContainerIdFromCgroupPath, RejectsUppercaseHex)
{
    // Runtimes emit lowercase; uppercase would be a different id space.
    EXPECT_EQ(ExtractContainerIdFromCgroupPath(
                  "/docker/ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"),
              "");
}

TEST(ResolvePidsForContainer, EmptyContainerIdReturnsEmpty)
{
    EXPECT_TRUE(wazuh::container_baseline::ResolvePidsForContainer("").empty());
}

TEST(ResolvePidsForContainer, UnknownContainerIdReturnsEmpty)
{
    // No real container on the test host will ever match this id.
    EXPECT_TRUE(wazuh::container_baseline::ResolvePidsForContainer(
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                    .empty());
}

TEST(PidIndex, BuildsWithoutThrowingAndAnswersMisses)
{
    const auto index = wazuh::container_baseline::PidIndex::Build();

    // Whether the test host runs containers is not knowable here; what must
    // hold either way is that a miss yields an empty vector rather than
    // fabricating PIDs, and that the accounting is self-consistent.
    EXPECT_TRUE(index.pidsFor("").empty());
    EXPECT_TRUE(index.pidsFor("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").empty());

    if (index.containerCount() == 0)
    {
        EXPECT_EQ(index.processCount(), 0U);
    }
    else
    {
        EXPECT_GE(index.processCount(), index.containerCount());
    }
}

TEST(PidIndex, EveryIndexedContainerHasAscendingPids)
{
    const auto index = wazuh::container_baseline::PidIndex::Build();
    if (index.containerCount() == 0) GTEST_SKIP() << "no containers running on this host";

    // front() is used as the container's representative PID, so the ordering is
    // load-bearing: it must be the lowest (longest-lived) PID, not whatever
    // readdir() happened to return first.
    for (const auto& [container_id, pids] : index.all())
    {
        EXPECT_FALSE(container_id.empty());
        ASSERT_FALSE(pids.empty()) << "indexed container with no PIDs: " << container_id;
        EXPECT_TRUE(std::is_sorted(pids.begin(), pids.end())) << "unsorted PIDs for " << container_id;
        EXPECT_EQ(pids.front(), *std::min_element(pids.begin(), pids.end()));

        // The index must agree with itself: a lookup returns the same list.
        EXPECT_EQ(index.pidsFor(container_id), pids);
    }
}


/* Which line of /proc/<pid>/cgroup the container id is read from.
 *
 * The regression these pin: a legacy host whose kernel emits a `0::/` line got
 * "/" back, which names no container, so NO process mapped to any container and
 * the baseline reported "0 container(s) scanned, 1 container(s) known". Whether
 * such a host emits that line is kernel-dependent -- absent on CentOS Stream 8
 * (4.18.0-326, measured) and on Ubuntu 22.04 forced to v1, present on a newer
 * one -- so neither shape may be assumed. */

TEST(SelectCgroupPathFromProcCgroup, AUnifiedLineThatNamesAPathWins)
{
    const std::string contents =
        "0::/system.slice/docker-fedcba0987654321fedcba0987654321fedcba09.scope\n";
    EXPECT_EQ(SelectCgroupPathFromProcCgroup(contents),
              "/system.slice/docker-fedcba0987654321fedcba0987654321fedcba09.scope");
}

TEST(SelectCgroupPathFromProcCgroup, ALegacyHostEmittingAUselessUnifiedLineFallsBackToAController)
{
    // The defect. Both lines are present and only the numbered one identifies
    // the container.
    const std::string contents =
        "0::/\n"
        "11:memory:/docker/fedcba0987654321fedcba0987654321fedcba09\n"
        "10:pids:/docker/fedcba0987654321fedcba0987654321fedcba09\n";
    EXPECT_EQ(SelectCgroupPathFromProcCgroup(contents),
              "/docker/fedcba0987654321fedcba0987654321fedcba09")
        << "a unified path of \"/\" identifies nothing, so it must not win";
}

TEST(SelectCgroupPathFromProcCgroup, APureLegacyHostWithNoUnifiedLineAtAll)
{
    // The shape measured on CentOS Stream 8 (4.18.0-326): every line numbered.
    const std::string contents =
        "12:hugetlb:/\n"
        "11:pids:/docker/fedcba0987654321fedcba0987654321fedcba09\n"
        "10:memory:/docker/fedcba0987654321fedcba0987654321fedcba09\n"
        "1:name=systemd:/docker/fedcba0987654321fedcba0987654321fedcba09\n";
    EXPECT_EQ(SelectCgroupPathFromProcCgroup(contents),
              "/docker/fedcba0987654321fedcba0987654321fedcba09");
}

TEST(SelectCgroupPathFromProcCgroup, TheControllerChosenFollowsTheSharedPriorityOrder)
{
    // memory outranks pids, and neither appears first. Keying on whichever line
    // came first would make this host's choice differ from the hierarchy the
    // resolver stats and the eBPF program reads.
    const std::string contents =
        "12:hugetlb:/hugetlb-path\n"
        "11:pids:/pids-path\n"
        "10:memory:/memory-path\n";
    EXPECT_EQ(SelectCgroupPathFromProcCgroup(contents), "/memory-path");
}

TEST(SelectCgroupPathFromProcCgroup, TheChoiceDoesNotDependOnTheOrderTheLinesAppear)
{
    const std::string forward = "10:memory:/memory-path\n11:pids:/pids-path\n";
    const std::string reversed = "11:pids:/pids-path\n10:memory:/memory-path\n";
    EXPECT_EQ(SelectCgroupPathFromProcCgroup(forward), SelectCgroupPathFromProcCgroup(reversed));
    EXPECT_EQ(SelectCgroupPathFromProcCgroup(reversed), "/memory-path");
}

TEST(SelectCgroupPathFromProcCgroup, AControllerIsMatchedAsAWholeElement)
{
    // "cpu" must not match inside "cpuacct", and a name= hierarchy is matched
    // on its bare name.
    const std::string contents = "2:cpu,cpuacct:/cpu-path\n1:name=systemd:/systemd-path\n";
    EXPECT_EQ(SelectCgroupPathFromProcCgroup(contents), "/cpu-path")
        << "cpuacct outranks name=systemd in the shared order";
}

TEST(SelectCgroupPathFromProcCgroup, AnUnrankedControllerIsStillBetterThanNothing)
{
    // Every v1 line carries the same container path, so a host mounting none of
    // the preferred controllers is still resolvable.
    const std::string contents = "12:hugetlb:/docker/abc\n9:freezer:/docker/abc\n";
    EXPECT_EQ(SelectCgroupPathFromProcCgroup(contents), "/docker/abc");
}

TEST(SelectCgroupPathFromProcCgroup, AHostProcessOnALegacyHostYieldsARootPath)
{
    const std::string contents = "0::/\n11:memory:/\n";
    const auto selected = SelectCgroupPathFromProcCgroup(contents);
    EXPECT_EQ(ExtractContainerIdFromCgroupPath(selected), "")
        << "a host process must not be attributed to a container";
}

TEST(SelectCgroupPathFromProcCgroup, EmptyOrGarbageYieldsNothingUsable)
{
    EXPECT_EQ(SelectCgroupPathFromProcCgroup(""), "");
    EXPECT_EQ(ExtractContainerIdFromCgroupPath(SelectCgroupPathFromProcCgroup("nonsense\n")), "");
}
