/*
 * Wazuh Syscheckd — unit tests for D15, the delete-inference ban
 * (#37532 / #37396).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * NoPathBatchMayEverAuthoriseDeletion is the reason this file exists. The rest
 * pin the mapping; that one pins the rule, across every shape of path batch
 * rather than a chosen example.
 */

#include "container_reconcile_plan.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace fim_container_events;

namespace
{

Batch PathBatch(const std::string& container_id, const std::vector<std::string>& paths)
{
    Batch batch;
    batch.container_id = container_id;
    batch.paths = paths;
    batch.suspect = false;
    return batch;
}

Batch SuspectBatch(const std::string& container_id)
{
    Batch batch;
    batch.container_id = container_id;
    batch.suspect = true;
    return batch;
}

} // namespace

TEST(ContainerReconcilePlanTest, APathBatchBecomesARereadOfExactlyThosePaths)
{
    const auto request = PlanFor(PathBatch("container-a", {"/etc/passwd", "/etc/hosts"}));

    EXPECT_EQ(ReconcileMode::rereadPaths, request.mode);
    EXPECT_EQ("container-a", request.container_id);
    ASSERT_EQ(2u, request.paths.size());
    EXPECT_EQ("/etc/passwd", request.paths[0]);
    EXPECT_EQ("/etc/hosts", request.paths[1]);
    EXPECT_FALSE(request.empty());
}

TEST(ContainerReconcilePlanTest, ASuspectContainerBecomesAWalkOfThatContainer)
{
    const auto request = PlanFor(SuspectBatch("container-a"));

    EXPECT_EQ(ReconcileMode::rewalkContainer, request.mode);
    EXPECT_EQ("container-a", request.container_id);
    EXPECT_TRUE(request.paths.empty());
}

TEST(ContainerReconcilePlanTest, AContainerlessSuspectBecomesAWholeNodeReBaseline)
{
    const auto request = PlanFor(SuspectBatch(""));

    EXPECT_EQ(ReconcileMode::rebaselineAll, request.mode);
    EXPECT_TRUE(request.container_id.empty());
}

TEST(ContainerReconcilePlanTest, OnlyAWalkMayAuthoriseDeletion)
{
    // A walk sees whole directories, so it can tell a deleted file from an
    // unreadable one. Nothing else can.
    EXPECT_TRUE(PlanFor(SuspectBatch("container-a")).may_detect_deletions);
    EXPECT_TRUE(PlanFor(SuspectBatch("")).may_detect_deletions);
    EXPECT_FALSE(PlanFor(PathBatch("container-a", {"/etc/passwd"})).may_detect_deletions);
}

TEST(ContainerReconcilePlanTest, NoPathBatchMayEverAuthoriseDeletion)
{
    // D15, pinned across shapes rather than one example: a staged path that
    // resolves to nothing may mean the file was deleted, or that it was a C22
    // host-form artifact, or that the container just restarted. Two of the
    // three make a DELETE a false positive, and nothing at the point of the
    // read can tell them apart.
    const std::vector<std::vector<std::string>> shapes = {
        {},
        {"/etc/passwd"},
        {"/a", "/b", "/c"},
        {"/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/117/fs/tmp/x"},
        {"/proc/1/task/1/attr/apparmor/exec"},
        {""},
    };

    for (const auto& container_id : {std::string("container-a"), std::string("")})
    {
        for (const auto& paths : shapes)
        {
            const auto request = PlanFor(PathBatch(container_id, paths));

            EXPECT_FALSE(request.may_detect_deletions)
                << "container='" << container_id << "' with " << paths.size() << " path(s)";
            EXPECT_EQ(ReconcileMode::rereadPaths, request.mode);
        }
    }
}

TEST(ContainerReconcilePlanTest, AnEmptyPathBatchIsANoOpAndNotPromotedToAWalk)
{
    const auto request = PlanFor(PathBatch("container-a", {}));

    // Promoting "nothing to reconcile" into a walk would quietly turn it into
    // "delete whatever I cannot find" — the inference D15 forbids, arriving
    // through a convenience.
    EXPECT_TRUE(request.empty());
    EXPECT_FALSE(request.may_detect_deletions);
    EXPECT_EQ(ReconcileMode::rereadPaths, request.mode);
}

TEST(ContainerReconcilePlanTest, AWalkIsNeverEmptyEvenWithNoPaths)
{
    // A Suspect batch carries no paths by construction; that must not read as
    // "nothing to do", or a container needing a re-walk would silently be
    // skipped.
    EXPECT_FALSE(PlanFor(SuspectBatch("container-a")).empty());
    EXPECT_FALSE(PlanFor(SuspectBatch("")).empty());
}
