#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include "baseTypes.hpp"
#include "builder/registry.hpp"
#include "opBuilderFileOutput.hpp"
#include "stageBuilderOutputs.hpp"

using namespace builder::internals;
using namespace builder::internals::builders;
using namespace json;
using namespace base;

class StageBuilderOutputsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        Registry::registerBuilder(opBuilderFileOutput, "output.file");
    }
    void TearDown() override
    {
        Registry::clear();
    }
};

TEST_F(StageBuilderOutputsTest, Builds)
{
    Json doc {R"([
            {"file":
                {"path": "/tmp/stageOutputsTest1.txt"}
            },
            {"file":
                {"path": "/tmp/stageOutputsTest2.txt"}
            }
    ])"};

    ASSERT_NO_THROW(builders::stageBuilderOutputs(doc));
}

TEST_F(StageBuilderOutputsTest, UnexpectedDefinition)
{
    Json doc {R"({
            "file":
                {"path": "/tmp/stageOutputsTest1.txt"}
    })"};

    ASSERT_THROW(builders::stageBuilderOutputs(doc), std::runtime_error);
}

TEST_F(StageBuilderOutputsTest, NotFoundOutput)
{
    Json doc {R"([
            {"nonExistingOutput":
                {"path": "/tmp/stageOutputsTest1.txt"}
            }
    ])"};

    ASSERT_THROW(builders::stageBuilderOutputs(doc), std::runtime_error);
}

TEST_F(StageBuilderOutputsTest, EmptyList)
{
    Json doc {R"([])"};

    ASSERT_THROW(builders::stageBuilderOutputs(doc), std::runtime_error);
}

TEST_F(StageBuilderOutputsTest, ArrayWrongSizeItem)
{
    Json doc {R"([
            {"file":
                {"path": "/tmp/stageOutputsTest1.txt"},
             "toManyItems": "value"
            }
    ])"};

    ASSERT_THROW(builders::stageBuilderOutputs(doc), std::runtime_error);
}

TEST_F(StageBuilderOutputsTest, BuildsCorrectExpression)
{
    Json doc {R"([
            {"file":
                {"path": "/tmp/stageOutputsTest1.txt"}
            },
            {"file":
                {"path": "/tmp/stageOutputsTest2.txt"}
            }
    ])"};

    auto expression = builders::stageBuilderOutputs(doc);

    ASSERT_TRUE(expression->isOperation());
    ASSERT_TRUE(expression->isBroadcast());
    ASSERT_EQ(expression->getPtr<Broadcast>()->getOperands().size(), 2);
    for (auto term : expression->getPtr<Broadcast>()->getOperands())
    {
        ASSERT_TRUE(term->isTerm());
    }
}
