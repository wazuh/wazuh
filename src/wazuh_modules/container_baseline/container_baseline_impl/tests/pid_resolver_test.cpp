#include "pid_resolver.hpp"

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
