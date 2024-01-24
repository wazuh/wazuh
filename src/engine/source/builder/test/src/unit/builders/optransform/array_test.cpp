#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"

using namespace builder::builders;

namespace transformbuildtest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         TransformBuilderTest,
                         testing::Values(

                             ),
                         testNameFormatter<TransformBuilderTest>("ArrayAppendSplit"));
} // namespace transformbuildtest

namespace transformoperatestest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         TransformOperationTest,
                         testing::Values(

                             ),
                         testNameFormatter<TransformOperationTest>("ArrayAppendSplit"));
} // namespace transformoperatestest
