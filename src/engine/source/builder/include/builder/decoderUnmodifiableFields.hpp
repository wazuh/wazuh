#ifndef BUILDER_DECODER_UNMODIFIABLE_FIELDS_HPP
#define BUILDER_DECODER_UNMODIFIABLE_FIELDS_HPP

#include <unordered_set>

#include <fmt/format.h>

#include <base/json.hpp>
#include <builder/idecoderUnmodifiableFields.hpp>

namespace builder
{

/**
 * @brief Concrete implementation of IDecoderUnmodifiableFields.
 *
 * Reads decoder unmodifiable field definitions from a JSON document and checks whether an asset can write a field.
 */
class DecoderUnmodifiableFields final : public IDecoderUnmodifiableFields
{
private:
    std::unordered_set<DotPath> m_decoderUnmodifiableFields; ///< Fields decoders cannot write.

public:
    DecoderUnmodifiableFields() = default;
    ~DecoderUnmodifiableFields() override = default;

    /**
     * @brief Construct a new Decoder Unmodifiable Fields object from a JSON definition.
     *
     * @param definition JSON document containing decoder_unmodifiable_fields.
     */
    DecoderUnmodifiableFields(const json::Json& definition);

    /**
     * @copydoc IDecoderUnmodifiableFields::check
     */
    bool check(const base::Name& assetType, const DotPath& field) const override;
};
} // namespace builder

#endif // BUILDER_DECODER_UNMODIFIABLE_FIELDS_HPP
