/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2021, Wazuh Inc.
 * July 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "pipelineNodes_test.h"
#include "pipelineNodesImp.h"

void PipelineNodesTest::SetUp() {};

void PipelineNodesTest::TearDown() {};

class FunctorWrapper
{
public:
    FunctorWrapper(){}
    ~FunctorWrapper(){}
    MOCK_METHOD(void, Operator, (const int), ());
    void operator()(const int value)
    {
        Operator(value);
    }
    void receive(const int& value)
    {
        Operator(value);
    }
};
using ReadIntNode = Utils::ReadNode<int, std::reference_wrapper<FunctorWrapper>>;
using ReadWriteNode = Utils::ReadWriteNode<std::string, int, ReadIntNode>;

TEST_F(PipelineNodesTest, ReadNodeAsync)
{
    FunctorWrapper functor;
    ReadIntNode rNode{ std::ref(functor) };
    for (int i = 0; i < 10; ++i)
    {
        EXPECT_CALL(functor, Operator(i));
    }
    for (int i = 0; i < 10; ++i)
    {
        rNode.receive(i);
    }
    rNode.rundown();
    EXPECT_TRUE(rNode.cancelled());
    EXPECT_EQ(0ul, rNode.size());
}

TEST_F(PipelineNodesTest, ReadWriteNodeAsync)
{
    FunctorWrapper functor;
    auto spReadNode
    {
        std::make_shared<ReadIntNode>(std::ref(functor))
    };
    auto spReadWriteNode
    {
        std::make_shared<ReadWriteNode>
        (
            [](const std::string& value)
            {
                return std::stoi(value);
            }
        )
    };
    Utils::connect(spReadWriteNode, spReadNode);
    for (int i = 0; i < 10; ++i)
    {
        EXPECT_CALL(functor, Operator(i));
    }
    for (int i = 0; i < 10; ++i)
    {
        spReadWriteNode->receive(std::to_string(i));
    }
    spReadWriteNode->rundown();
    EXPECT_EQ(0ul, spReadWriteNode->size());
    EXPECT_TRUE(spReadWriteNode->cancelled());
    spReadNode->rundown();
    EXPECT_EQ(0ul, spReadNode->size());
    EXPECT_TRUE(spReadNode->cancelled());
}

TEST_F(PipelineNodesTest, ConnectInvalidPtrs1)
{
    std::shared_ptr<Utils::ReadNode<int>> spReadNode;
    std::shared_ptr<Utils::ReadWriteNode<int, int, Utils::ReadNode<int>>> spReadWriteNode;
    EXPECT_NO_THROW(Utils::connect(spReadWriteNode, spReadNode));
}

TEST_F(PipelineNodesTest, ConnectInvalidPtrs2)
{
    const auto spReadNode
    {
        std::make_shared<Utils::ReadNode<int>>([](const int&){})
    };
    std::shared_ptr<Utils::ReadWriteNode<int, int, Utils::ReadNode<int>>> spReadWriteNode;
    EXPECT_NO_THROW(Utils::connect(spReadWriteNode, spReadNode));
}

TEST_F(PipelineNodesTest, ConnectInvalidPtrs3)
{
    std::shared_ptr<Utils::ReadNode<int>> spReadNode;
    const auto spReadWriteNode
    {
        std::make_shared<Utils::ReadWriteNode<int, int, Utils::ReadNode<int>>>([](const int&){return 0;})
    };
    EXPECT_NO_THROW(Utils::connect(spReadWriteNode, spReadNode));
}
