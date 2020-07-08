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
        rNode.receive(i);
    }
    rNode.rundown();
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
        spReadWriteNode->receive(std::to_string(i));
    }
    spReadWriteNode->rundown();
    EXPECT_EQ(0ul, spReadWriteNode->size());
    spReadNode->rundown();
    EXPECT_EQ(0ul, spReadNode->size());
}
