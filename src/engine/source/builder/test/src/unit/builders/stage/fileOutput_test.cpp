#include "builders/baseBuilders_test.hpp"
#include "builders/stage/fileOutput.hpp"

#include <streamlog/mockStreamlog.hpp>

using namespace builder::builders;

namespace
{
const streamlog::RotationConfig TEST_BASE_CONFIG {.basePath = "/tmp/test-logs",
                                                  .pattern = "${YYYY}/${MMM}/wazuh-${name}-${DD}.json",
                                                  .maxSize = 0,
                                                  .bufferSize = 1 << 20,
                                                  .shouldCompress = false,
                                                  .compressionLevel = 5};
} // namespace

class FileOutputBuilderTest : public BaseBuilderTest
{
};

// Helper class for handling lazy mock creation
class FileOutputTestHelper
{
public:
    static StageBuilder getBuilder(bool callExpectations = false)
    {
        return [callExpectations](const json::Json& definition,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx) -> base::Expression
        {
            // Create the mock only when needed
            auto logManager = std::make_shared<testing::NiceMock<streamlog::mocks::MockILogManager>>();

            if (callExpectations)
            {
                // ensureAndGetWriter is called on success
                EXPECT_CALL(*logManager, ensureAndGetWriter(testing::_, testing::_, testing::_)).Times(1);
            }
            else
            {
                EXPECT_CALL(*logManager, ensureAndGetWriter(testing::_, testing::_, testing::_)).Times(0);
            }

            return fileOutputBuilder(definition, buildCtx, logManager, TEST_BASE_CONFIG);
        };
    }
};

namespace stagebuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    StageBuilderTest,
    testing::Values(
        // Invalid definitions
        StageT(R"([])", FileOutputTestHelper::getBuilder(), FAILURE()),
        StageT(R"(1)", FileOutputTestHelper::getBuilder(), FAILURE()),
        StageT(R"(null)", FileOutputTestHelper::getBuilder(), FAILURE()),
        StageT(R"(true)", FileOutputTestHelper::getBuilder(), FAILURE()),
        StageT(R"({})", FileOutputTestHelper::getBuilder(), FAILURE()),
        StageT(R"("")", FileOutputTestHelper::getBuilder(), FAILURE()),
        // succeed
        StageT(R"("wazuh-events-v5")",
               FileOutputTestHelper::getBuilder(true),
               SUCCESS(base::Term<base::EngineOp>::create("write.output(file/test_space-wazuh-events-v5)", {})))
        // end
        ),
    testNameFormatter<StageBuilderTest>("FileOutput"));
} // namespace stagebuildtest

TEST_F(FileOutputBuilderTest, ThrowsWhenOriginSpaceIsEmpty)
{
    mocks->context.originSpace.clear();

    auto logManager = std::make_shared<testing::NiceMock<streamlog::mocks::MockILogManager>>();
    EXPECT_CALL(*logManager, ensureAndGetWriter(testing::_, testing::_, testing::_)).Times(0);

    EXPECT_THROW(fileOutputBuilder(json::Json("\"wazuh-events-v5\""), mocks->ctx, logManager, TEST_BASE_CONFIG),
                 std::runtime_error);
}

TEST_F(FileOutputBuilderTest, PropagatesInvalidComposedChannelName)
{
    mocks->context.originSpace = "invalid space";

    auto logManager = std::make_shared<testing::NiceMock<streamlog::mocks::MockILogManager>>();
    EXPECT_CALL(*logManager, ensureAndGetWriter("invalid space-wazuh-events-v5", testing::_, "json"))
        .WillOnce(testing::Throw(std::runtime_error("invalid channel name")));

    EXPECT_THROW(fileOutputBuilder(json::Json("\"wazuh-events-v5\""), mocks->ctx, logManager, TEST_BASE_CONFIG),
                 std::runtime_error);
}
