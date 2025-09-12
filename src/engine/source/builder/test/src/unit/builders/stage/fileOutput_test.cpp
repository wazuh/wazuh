#include "builders/baseBuilders_test.hpp"
#include "builders/stage/fileOutput.hpp"

#include <streamlog/mockStreamlog.hpp>

using namespace builder::builders;

// Clase helper para manejar la creación lazy de mocks
class FileOutputTestHelper
{
public:
    static StageBuilder getBuilder(bool callExpectations = false)
    {
        return [callExpectations](const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx) -> base::Expression
        {
            // Crear el mock solo cuando se necesita
            auto logManager = std::make_shared<testing::NiceMock<streamlog::mocks::MockILogManager>>();

            if (callExpectations)
            {
                // Poner expectativas si se indica
                EXPECT_CALL(*logManager, getWriter(testing::_)).Times(1);
            } else {
                EXPECT_CALL(*logManager, getWriter(testing::_)).Times(0);
            }
            // ON_CALL(*logManager, getWriter(testing::_))
            //     .WillByDefault(
            //         testing::Return(std::make_shared<testing::NiceMock<streamlog::mocks::MockWriterEvent>>()));

            return fileOutputBuilder(definition, buildCtx, logManager);
        };
    }
};

namespace stagebuildtest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         StageBuilderTest,
                         testing::Values(
                             // Invalid definitions
                             StageT(R"([])", FileOutputTestHelper::getBuilder(), FAILURE()),
                             StageT(R"(1)", FileOutputTestHelper::getBuilder(), FAILURE()),
                             StageT(R"(null)", FileOutputTestHelper::getBuilder(), FAILURE()),
                             StageT(R"(true)", FileOutputTestHelper::getBuilder(), FAILURE()),
                             StageT(R"({})", FileOutputTestHelper::getBuilder(), FAILURE()),
                             StageT(R"("")", FileOutputTestHelper::getBuilder(), FAILURE()),
                             StageT(R"("invalid_channel")", FileOutputTestHelper::getBuilder(), FAILURE()),
                             // suceed
                             StageT(R"("alerts")",
                                    FileOutputTestHelper::getBuilder(true),
                                    SUCCESS(base::Term<base::EngineOp>::create("write.output(alerts-file)", {})))
                             // end
                             ),
                         testNameFormatter<StageBuilderTest>("FileOutput"));
} // namespace stagebuildtest
