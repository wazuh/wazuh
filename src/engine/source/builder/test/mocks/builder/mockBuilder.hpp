#ifndef BUILDER2_TEST_SRC_MOCKS_MOCKBUILDER_HPP
#define BUILDER2_TEST_SRC_MOCKS_MOCKBUILDER_HPP

#include <gmock/gmock.h>

#include <builder/ibuilder.hpp>

namespace builder::mocks
{
class MockBuilder : public IBuilder
{
public:
    MOCK_METHOD(std::shared_ptr<IPolicy>,
                buildPolicy,
                (const base::Name& name, bool trace, bool sandbox, bool reverseOrderDecoders),
                (const, override));
    MOCK_METHOD(base::Expression, buildAsset, (const base::Name& name), (const, override));
};
} // namespace builder::mocks

#endif // BUILDER2_TEST_SRC_MOCKS_MOCKBUILDER_HPP