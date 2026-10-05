/*
 * Wazuh container_instances — /proc/<pid>/cgroup parsing (#37203 O4).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * This parser accepted exactly one shape — a line beginning `0::` — and
 * returned nothing for anything else. A pure cgroup v1 host has no such line,
 * so every line was rejected, every container got inode 0, and the module
 * reported no containers at all while looking perfectly healthy.
 *
 * Two things are pinned here. First, that the line parser reads the format
 * rather than one case of it. Second, and less obvious, that CHOOSING among v1
 * lines is deterministic: on v1 each controller is a separate mount with its
 * own inode, so a resolver that picked a different controller for two
 * processes of the same container would file them under keys that cannot be
 * compared, and nothing downstream would notice.
 */

#include "cgroup/cgroup_parse.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace wazuh::container_instances;

namespace
{

    /// A real pure-v1 /proc/<pid>/cgroup, as RHEL 8 and Amazon Linux 2 write it.
    std::vector<CgroupLine> ParseAll(const std::vector<std::string>& lines)
    {
        std::vector<CgroupLine> parsed;
        for (const auto& line : lines)
        {
            if (auto one = parseCgroupLine(line))
            {
                parsed.push_back(std::move(*one));
            }
        }
        return parsed;
    }

    const std::vector<std::string> kPureV1 {
        "11:devices:/docker/3f2abc9900112233445566778899aabbccddeeff00112233445566778899aabb",
        "10:memory:/docker/3f2abc9900112233445566778899aabbccddeeff00112233445566778899aabb",
        "9:pids:/docker/3f2abc9900112233445566778899aabbccddeeff00112233445566778899aabb",
        "8:cpu,cpuacct:/docker/3f2abc9900112233445566778899aabbccddeeff00112233445566778899aabb",
        "1:name=systemd:/docker/3f2abc9900112233445566778899aabbccddeeff00112233445566778899aabb",
    };

    const std::vector<std::string> kPureV2 {
        "0::/kubepods.slice/kubepods-besteffort.slice/cri-containerd-abc123def456.scope",
    };

    /// Hybrid: v1 controllers AND a unified line, which is what a host mid-migration
    /// actually writes.
    const std::vector<std::string> kHybrid {
        "10:memory:/docker/aabb",
        "1:name=systemd:/docker/aabb",
        "0::/docker/aabb",
    };

} // namespace

TEST(CgroupParseTest, TheUnifiedLineIsReadAsHierarchyZeroWithNoControllers)
{
    const auto line = parseCgroupLine(kPureV2.front());

    ASSERT_TRUE(line.has_value());
    EXPECT_EQ(0, line->hierarchyId);
    EXPECT_TRUE(line->controllers.empty());
    EXPECT_TRUE(line->isUnified());
    EXPECT_EQ("/kubepods.slice/kubepods-besteffort.slice/cri-containerd-abc123def456.scope", line->path);
}

TEST(CgroupParseTest, AV1ControllerLineIsReadRatherThanRejected)
{
    const auto line = parseCgroupLine("10:memory:/docker/abc");

    ASSERT_TRUE(line.has_value()) << "this is the line the old parser threw away, and with it every v1 host";
    EXPECT_EQ(10, line->hierarchyId);
    EXPECT_EQ("memory", line->controllers);
    EXPECT_EQ("/docker/abc", line->path);
    EXPECT_FALSE(line->isUnified());
}

TEST(CgroupParseTest, APathContainingAColonSurvives)
{
    // systemd scope and slice names contain ':' routinely. Splitting on every
    // colon instead of the first two truncates the path, and a truncated path
    // stats a DIFFERENT cgroup — a wrong inode rather than no inode, which is
    // the worse failure.
    const auto line = parseCgroupLine("0::/system.slice/run-docker-netns-a:b.mount");

    ASSERT_TRUE(line.has_value());
    EXPECT_EQ("/system.slice/run-docker-netns-a:b.mount", line->path);
}

TEST(CgroupParseTest, MalformedLinesAreRejectedRatherThanGuessed)
{
    EXPECT_FALSE(parseCgroupLine("").has_value());
    EXPECT_FALSE(parseCgroupLine("not a cgroup line").has_value());
    EXPECT_FALSE(parseCgroupLine("10:memory").has_value()) << "two fields, not three";
    EXPECT_FALSE(parseCgroupLine("x:memory:/docker/abc").has_value()) << "hierarchy id must be numeric";
    EXPECT_FALSE(parseCgroupLine("10:memory:").has_value()) << "empty path";
    EXPECT_FALSE(parseCgroupLine("10:memory:relative/path").has_value()) << "a cgroup path is absolute";
}

TEST(CgroupParseTest, ATrailingNewlineIsNotPartOfThePath)
{
    const auto line = parseCgroupLine("0::/docker/abc\n");

    ASSERT_TRUE(line.has_value());
    EXPECT_EQ("/docker/abc", line->path) << "a stray newline makes the stat path wrong and resolves nothing";
}

/* --- selection ------------------------------------------------------------ */

TEST(CgroupParseTest, OnAUnifiedHostTheUnifiedLineWinsAndIsRelativeToTheRoot)
{
    const auto selection = selectCanonicalCgroup(ParseAll(kPureV2), WZ_CGROUP_MODE_UNIFIED);

    ASSERT_TRUE(selection.has_value());
    EXPECT_EQ("/kubepods.slice/kubepods-besteffort.slice/cri-containerd-abc123def456.scope", selection->path);
    EXPECT_TRUE(selection->mountSubdir.empty());
    EXPECT_TRUE(selection->controller.empty());
}

TEST(CgroupParseTest, OnAHybridHostTheUnifiedHierarchyIsNotAtTheCgroupRoot)
{
    // The bug this prevents is silent: a hybrid host's `0::` path is relative to
    // <root>/unified, so statting <root><path> finds nothing, every container
    // gets inode 0, and the module reports none — the same symptom as pure v1,
    // on a host whose cgroup ids are perfectly usable.
    const auto selection = selectCanonicalCgroup(ParseAll(kHybrid), WZ_CGROUP_MODE_HYBRID);

    ASSERT_TRUE(selection.has_value());
    EXPECT_EQ("/docker/aabb", selection->path);
    EXPECT_EQ("unified", selection->mountSubdir);
}

TEST(CgroupParseTest, AUnifiedHostIgnoresV1LinesEvenWhenBothArePresent)
{
    // Choosing a v1 controller on a host whose events carry unified ids would
    // key the store on a number no event ever contains.
    const auto selection = selectCanonicalCgroup(ParseAll(kHybrid), WZ_CGROUP_MODE_UNIFIED);

    ASSERT_TRUE(selection.has_value());
    EXPECT_TRUE(selection->controller.empty());
    EXPECT_TRUE(selection->mountSubdir.empty());
}

TEST(CgroupParseTest, OnALegacyHostMemoryIsChosen)
{
    const auto selection = selectCanonicalCgroup(ParseAll(kPureV1), WZ_CGROUP_MODE_LEGACY);

    ASSERT_TRUE(selection.has_value());
    EXPECT_EQ("memory", selection->controller);
    EXPECT_EQ("memory", selection->mountSubdir);
    EXPECT_EQ("/docker/3f2abc9900112233445566778899aabbccddeeff00112233445566778899aabb", selection->path);
}

TEST(CgroupParseTest, TheChoiceFallsDownThePriorityListWhenAControllerIsAbsent)
{
    auto withoutMemory = kPureV1;
    withoutMemory.erase(withoutMemory.begin() + 1); // drop memory

    auto selection = selectCanonicalCgroup(ParseAll(withoutMemory), WZ_CGROUP_MODE_LEGACY);
    ASSERT_TRUE(selection.has_value());
    EXPECT_EQ("pids", selection->controller);

    withoutMemory.erase(withoutMemory.begin() + 1); // and pids
    selection = selectCanonicalCgroup(ParseAll(withoutMemory), WZ_CGROUP_MODE_LEGACY);
    ASSERT_TRUE(selection.has_value());
    EXPECT_EQ("cpuacct", selection->controller);
    EXPECT_EQ("cpu,cpuacct", selection->mountSubdir)
        << "the mount directory is the whole controller list, not the one controller matched";

    withoutMemory.erase(withoutMemory.begin() + 1); // and cpu,cpuacct
    selection = selectCanonicalCgroup(ParseAll(withoutMemory), WZ_CGROUP_MODE_LEGACY);
    ASSERT_TRUE(selection.has_value());
    EXPECT_EQ("systemd", selection->controller);
    EXPECT_EQ("systemd", selection->mountSubdir)
        << "name=systemd is mounted at <root>/systemd: the name= prefix is a mount option, not a directory";
}

TEST(CgroupParseTest, TheChoiceDoesNotDependOnTheOrderTheLinesAppear)
{
    // The kernel does not promise an order, and a selection that depended on one
    // would key two processes of the same container differently on two hosts.
    auto reversed = kPureV1;
    std::reverse(reversed.begin(), reversed.end());

    const auto forward = selectCanonicalCgroup(ParseAll(kPureV1), WZ_CGROUP_MODE_LEGACY);
    const auto backward = selectCanonicalCgroup(ParseAll(reversed), WZ_CGROUP_MODE_LEGACY);

    ASSERT_TRUE(forward.has_value());
    ASSERT_TRUE(backward.has_value());
    EXPECT_EQ(forward->controller, backward->controller);
    EXPECT_EQ(forward->mountSubdir, backward->mountSubdir);
}

TEST(CgroupParseTest, NoneOfThePriorityControllersMountedProducesNoKey)
{
    // Unlisted exactly as before rather than keyed on something arbitrary; the
    // startup mode log is what explains the emptiness.
    const auto selection =
        selectCanonicalCgroup(ParseAll({"11:devices:/docker/abc", "7:net_cls:/docker/abc"}), WZ_CGROUP_MODE_LEGACY);

    EXPECT_FALSE(selection.has_value());
}

TEST(CgroupParseTest, ALegacyHostWithOnlyAUnifiedLineProducesNoKey)
{
    EXPECT_FALSE(selectCanonicalCgroup(ParseAll(kPureV2), WZ_CGROUP_MODE_LEGACY).has_value());
}

TEST(CgroupParseTest, AControllerIsMatchedAsAWholeElementNotASubstring)
{
    // "cpuacct" must not match inside "blkio,cpuacct_fake", and "memory" must
    // not match "hugetlb,memory_like". A substring match would select the wrong
    // mount and stat a path that does not exist.
    EXPECT_TRUE(controllerListContains("cpu,cpuacct", "cpuacct"));
    EXPECT_TRUE(controllerListContains("name=systemd", "systemd"));
    EXPECT_FALSE(controllerListContains("memory_like", "memory"));
    EXPECT_FALSE(controllerListContains("cpuacct_fake", "cpuacct"));
}

/* --- the part that needed no change, asserted rather than assumed --------- */

TEST(CgroupParseTest, ContainerIdExtractionAlreadyWorksOnV1Leaves)
{
    // A v1 path differs from a v2 one only in its prefix; the LEAF is identical,
    // and leaf-only matching is why this generalises for free. Pinning it so a
    // later change to these regexes cannot quietly take v1 with it.
    struct Case
    {
        const char* path;
        const char* expectedId;
        RuntimeHint expectedHint;
    };

    const Case cases[] = {
        // systemd driver, v1 paths.
        {"/kubepods/burstable/podabc/cri-containerd-3f2a9900112233445566778899aabbcc.scope",
         "3f2a9900112233445566778899aabbcc",
         RuntimeHint::containerd},
        {"/kubepods/besteffort/podabc/crio-3f2a9900112233445566778899aabbcc.scope",
         "3f2a9900112233445566778899aabbcc",
         RuntimeHint::crio},
        {"/system.slice/docker-3f2a9900112233445566778899aabbcc.scope",
         "3f2a9900112233445566778899aabbcc",
         RuntimeHint::docker},
        // cgroupfs driver: a bare hex leaf, which is what Docker on v1 writes.
        {"/docker/3f2abc9900112233445566778899aabbccddeeff00112233445566778899aabb",
         "3f2abc9900112233445566778899aabbccddeeff00112233445566778899aabb",
         RuntimeHint::unknown},
    };

    for (const auto& one : cases)
    {
        const auto match = extractContainerId(one.path);
        ASSERT_TRUE(match.has_value()) << one.path;
        EXPECT_EQ(one.expectedId, match->containerId) << one.path;
        EXPECT_EQ(one.expectedHint, match->hint) << one.path;
    }
}

TEST(CgroupParseTest, AHostCgroupPathIsNotMistakenForAContainer)
{
    EXPECT_FALSE(extractContainerId("/system.slice/sshd.service").has_value());
    EXPECT_FALSE(extractContainerId("/user.slice/user-1000.slice").has_value());
    EXPECT_FALSE(extractContainerId("/").has_value());
}
