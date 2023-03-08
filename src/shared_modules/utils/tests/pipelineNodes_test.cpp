/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
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
        FunctorWrapper() = default;
        ~FunctorWrapper() = default;
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

template<typename R, typename RW>
static void ReadWriteNodeBehaviour(FunctorWrapper& functor, std::shared_ptr<R>& spReadNode, std::shared_ptr<RW>& spReadWriteNode);

template<typename T>
static void ReadNodeBehaviour(FunctorWrapper& functor, T& rNode);

using ReadIntNodeSync = Utils::ReadNode<int, std::reference_wrapper<FunctorWrapper>, Utils::SyncDispatcher>;
using ReadWriteNodeSync = Utils::ReadWriteNode<std::string, int, ReadIntNodeSync>;

using ReadIntNodeAsync = Utils::ReadNode<int, std::reference_wrapper<FunctorWrapper>, Utils::AsyncDispatcher>;
using ReadWriteNodeAsync = Utils::ReadWriteNode<std::string, int, ReadIntNodeAsync>;

TEST_F(PipelineNodesTest, ReadNodeAsync)
{
    FunctorWrapper functor;
    ReadIntNodeAsync rNode{ std::ref(functor) };

    ReadNodeBehaviour(functor, rNode);
}

TEST_F(PipelineNodesTest, ReadNodeAsyncMultiThread)
{
    FunctorWrapper functor;
    const unsigned int s_numberOfThreads{ 2 };
    ReadIntNodeAsync rNode{ std::ref(functor), s_numberOfThreads };

    ReadNodeBehaviour(functor, rNode);

    EXPECT_EQ(s_numberOfThreads, rNode.numberOfThreads());
}

TEST_F(PipelineNodesTest, ReadNodeSync)
{
    FunctorWrapper functor;
    ReadIntNodeSync rNode{ std::ref(functor) };

    ReadNodeBehaviour(functor, rNode);
}

TEST_F(PipelineNodesTest, ReadNodeSyncMultiThread)
{
    FunctorWrapper functor;
    const unsigned int s_numberOfThreads{ 2 };
    ReadIntNodeSync rNode{ std::ref(functor), s_numberOfThreads };

    ReadNodeBehaviour(functor, rNode);

    EXPECT_EQ(0u, rNode.numberOfThreads());
}

TEST_F(PipelineNodesTest, ReadWriteNodeAsync)
{
    FunctorWrapper functor;
    auto spReadNode
    {
        std::make_shared<ReadIntNodeAsync>(std::ref(functor))
    };
    auto spReadWriteNode
    {
        std::make_shared<ReadWriteNodeAsync>([](const std::string & value)
        {
            return std::stoi(value);
        })
    };

    ReadWriteNodeBehaviour(functor, spReadNode, spReadWriteNode);
}

TEST_F(PipelineNodesTest, ReadWriteNodeSync)
{
    FunctorWrapper functor;
    auto spReadNode
    {
        std::make_shared<ReadIntNodeSync>(std::ref(functor))
    };
    auto spReadWriteNode
    {
        std::make_shared<ReadWriteNodeSync>([](const std::string & value)
        {
            return std::stoi(value);
        })
    };

    ReadWriteNodeBehaviour(functor, spReadNode, spReadWriteNode);
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
        std::make_shared<Utils::ReadNode<int>>([](const int&) {})
    };
    std::shared_ptr<Utils::ReadWriteNode<int, int, Utils::ReadNode<int>>> spReadWriteNode;
    EXPECT_NO_THROW(Utils::connect(spReadWriteNode, spReadNode));
}

TEST_F(PipelineNodesTest, ConnectInvalidPtrs3)
{
    std::shared_ptr<Utils::ReadNode<int>> spReadNode;
    const auto spReadWriteNode
    {
        std::make_shared<Utils::ReadWriteNode<int, int, Utils::ReadNode<int>>>([](const int&)
        {
            return 0;
        })
    };
    EXPECT_NO_THROW(Utils::connect(spReadWriteNode, spReadNode));
}

template<typename T>
static void ReadNodeBehaviour(FunctorWrapper& functor, T& rNode)
{
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

template<typename R, typename RW>
static void ReadWriteNodeBehaviour(FunctorWrapper& functor, std::shared_ptr<R>& spReadNode, std::shared_ptr<RW>& spReadWriteNode)
{
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