#ifndef _BUILDER_IDECODER_UNMODIFIABLE_FIELDS_HPP
#define _BUILDER_IDECODER_UNMODIFIABLE_FIELDS_HPP

#include <base/dotPath.hpp>
#include <base/name.hpp>

namespace builder
{

/**
 * @brief Interface for checking if a field is allowed to be written by a given asset type.
 *
 */
class IDecoderUnmodifiableFields
{
public:
    virtual ~IDecoderUnmodifiableFields() = default;

    /**
     * @brief Check if a field is allowed to be written by a given asset type.
     *
     * Decoders cannot write fields listed in the decoder unmodifiable fields document.
     *
     * @param assetType The asset type.
     * @param field The field to check.
     * @return true if the field is allowed to be modified, false otherwise.
     */
    virtual bool check(const base::Name& assetType, const DotPath& field) const = 0;
};
} // namespace builder

#endif // _BUILDER_IDECODER_UNMODIFIABLE_FIELDS_HPP
