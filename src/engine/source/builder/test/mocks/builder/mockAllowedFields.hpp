#ifndef BUILDER_TEST_SRC_MOCKS_MOCKSALLOWEDFIELDS_HPP
#define BUILDER_TEST_SRC_MOCKS_MOCKSALLOWEDFIELDS_HPP

#include <gmock/gmock.h>

#include <builder/iallowedFields.hpp>

namespace builder::mocks
{
class MockAllowedFields : public IAllowedFields
{
public:
    MOCK_METHOD(bool, check, (const base::Name& assetType, const DotPath& field), (const, override));
};
} // namespace builder::mocks

#endif // BUILDER_TEST_SRC_MOCKS_MOCKSALLOWEDFIELDS_HPP
