#include "pid_resolver.hpp"

#include <algorithm>

#include <gtest/gtest.h>

using wazuh::container_baseline::ExtractContainerIdFromCgroupPath;

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
