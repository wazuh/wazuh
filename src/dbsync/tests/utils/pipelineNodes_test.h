#pragma once
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class PipelineNodesTest : public ::testing::Test {

protected:

    PipelineNodesTest() = default;
    virtual ~PipelineNodesTest() = default;

    void SetUp() override;
    void TearDown() override;
};