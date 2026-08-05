#include "reconcile/container_lister.hpp"

#include <gtest/gtest.h>

using namespace wazuh::container_baseline;

// Covers the empty-list guard's decision logic: ContainerLister::list() calls
// ModuleUp() on the status() reply only when listContainers() came back empty,
// to tell "no containers" (available, safe to delete) from "module unreachable"
// (unavailable, skip the pass rather than reading it as a mass delete).

TEST(ModuleUpTest, StatusOkMeansModuleIsUp)
{
    EXPECT_TRUE(ModuleUp(R"({"status":"ok"})"));
}

TEST(ModuleUpTest, StatusOkAmongOtherFieldsStillMeansUp)
{
    EXPECT_TRUE(ModuleUp(R"({"version":1,"status":"ok","containers":0})"));
}

TEST(ModuleUpTest, OtherStatusValueMeansModuleIsDown)
{
    EXPECT_FALSE(ModuleUp(R"({"status":"error"})"));
}

TEST(ModuleUpTest, MissingStatusFieldMeansModuleIsDown)
{
    EXPECT_FALSE(ModuleUp(R"({"version":1})"));
}

TEST(ModuleUpTest, EmptyReplyMeansModuleIsDown)
{
    // What the IPC client returns on any connect/send/recv failure — the
    // exact case the empty-list guard exists to disambiguate.
    EXPECT_FALSE(ModuleUp(""));
}

TEST(ModuleUpTest, MalformedJsonMeansModuleIsDown)
{
    EXPECT_FALSE(ModuleUp("{not json"));
}

TEST(ModuleUpTest, NonObjectJsonMeansModuleIsDown)
{
    EXPECT_FALSE(ModuleUp(R"(["status","ok"])"));
}
