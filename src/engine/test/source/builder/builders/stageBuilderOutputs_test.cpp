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

TEST(StageBuilderOutputsTest, Builds)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(opBuilderFileOutput, "output.file");
    Json doc {R"([
            {"file":
                {"path": "/tmp/stageOutputsTest1.txt"}
            },
            {"file":
                {"path": "/tmp/stageOutputsTest2.txt"}
            }
    ])"};

    ASSERT_NO_THROW(builders::getStageBuilderOutputs(registry)(doc));
}

TEST(StageBuilderOutputsTest, UnexpectedDefinition)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(opBuilderFileOutput, "output.file");
    Json doc {R"({
            "file":
                {"path": "/tmp/stageOutputsTest1.txt"}
    })"};

    ASSERT_THROW(builders::getStageBuilderOutputs(registry)(doc), std::runtime_error);
}

TEST(StageBuilderOutputsTest, NotFoundOutput)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(opBuilderFileOutput, "output.file");
    Json doc {R"([
            {"nonExistingOutput":
                {"path": "/tmp/stageOutputsTest1.txt"}
            }
    ])"};

    ASSERT_THROW(builders::getStageBuilderOutputs(registry)(doc), std::runtime_error);
}

TEST(StageBuilderOutputsTest, EmptyList)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(opBuilderFileOutput, "output.file");
    Json doc {R"([])"};

    ASSERT_THROW(builders::getStageBuilderOutputs(registry)(doc), std::runtime_error);
}

TEST(StageBuilderOutputsTest, ArrayWrongSizeItem)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(opBuilderFileOutput, "output.file");
    Json doc {R"([
            {"file":
                {"path": "/tmp/stageOutputsTest1.txt"},
             "toManyItems": "value"
            }
    ])"};

    ASSERT_THROW(builders::getStageBuilderOutputs(registry)(doc), std::runtime_error);
}

TEST(StageBuilderOutputsTest, BuildsCorrectExpression)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(opBuilderFileOutput, "output.file");
    Json doc {R"([
            {"file":
                {"path": "/tmp/stageOutputsTest1.txt"}
            },
            {"file":
                {"path": "/tmp/stageOutputsTest2.txt"}
            }
    ])"};

    auto expression = builders::getStageBuilderOutputs(registry)(doc);

    ASSERT_TRUE(expression->isOperation());
    ASSERT_TRUE(expression->isBroadcast());
    ASSERT_EQ(expression->getPtr<Broadcast>()->getOperands().size(), 2);
    for (auto term : expression->getPtr<Broadcast>()->getOperands())
    {
        ASSERT_TRUE(term->isTerm());
    }
}
