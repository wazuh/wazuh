#pragma once
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class DBSyncPipelineFactoryTest : public ::testing::Test 
{
protected:

    DBSyncPipelineFactoryTest()
    : m_pipelineFactory{DbSync::PipelineFactory::instance()}
    {}
    virtual ~DBSyncPipelineFactoryTest() = default;

    void SetUp() override;
    void TearDown() override;
   	DbSync::PipelineFactory& m_pipelineFactory;
};