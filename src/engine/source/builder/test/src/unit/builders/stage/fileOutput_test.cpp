#include "builders/baseBuilders_test.hpp"
#include "builders/stage/fileOutput.hpp"

#include <streamlog/mockStreamlog.hpp>

using namespace builder::builders;



namespace stagebuildtest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         StageBuilderTest,
                         testing::Values(StageT(R"([])", fileOutputBuilder, FAILURE()),
                                         StageT(R"("notObject")", fileOutputBuilder, FAILURE()),
                                         StageT(R"(1)", fileOutputBuilder, FAILURE()),
                                         StageT(R"(null)", fileOutputBuilder, FAILURE()),
                                         StageT(R"(true)", fileOutputBuilder, FAILURE()),
                                         StageT(R"({})", fileOutputBuilder, FAILURE()),
                                         StageT(R"({"key": "val", "key2": "val2"})", fileOutputBuilder, FAILURE()),
                                         StageT(R"({"path": 1})", fileOutputBuilder, FAILURE()),
                                         StageT(R"({"path": "///"})", fileOutputBuilder, FAILURE()),
                                         StageT(R"({"path": "/tmp/path"})",
                                                fileOutputBuilder,
                                                SUCCESS(base::Term<base::EngineOp>::create("write.output(/tmp/path)",
                                                                                           {})))),
                         testNameFormatter<StageBuilderTest>("FileOutput"));
} // namespace stagebuildtest
