#ifndef BUILDER_TEST_SRC_MOCKS_MOCKSDECODER_UNMODIFIABLE_FIELDS_HPP
#define BUILDER_TEST_SRC_MOCKS_MOCKSDECODER_UNMODIFIABLE_FIELDS_HPP

#include <gmock/gmock.h>

#include <builder/idecoderUnmodifiableFields.hpp>

namespace builder::mocks
{
class MockDecoderUnmodifiableFields : public IDecoderUnmodifiableFields
{
public:
    MOCK_METHOD(bool, check, (const base::Name& assetType, const DotPath& field), (const, override));
};
} // namespace builder::mocks

#endif // BUILDER_TEST_SRC_MOCKS_MOCKSDECODER_UNMODIFIABLE_FIELDS_HPP
