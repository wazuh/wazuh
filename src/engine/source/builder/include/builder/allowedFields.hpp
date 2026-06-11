#ifndef BUILDER_ALLOWEDFIELDS_HPP
#define BUILDER_ALLOWEDFIELDS_HPP

#include <unordered_set>

#include <fmt/format.h>

#include <base/json.hpp>
#include <builder/iallowedFields.hpp>

namespace builder
{

/**
 * @brief Concrete implementation of IAllowedFields.
 *
 * Reads decoder unmodifiable field definitions from a JSON document and checks whether an asset can write a field.
 */
class AllowedFields final : public IAllowedFields
{
private:
    std::unordered_set<DotPath> m_decoderUnmodifiableFields; ///< Fields decoders cannot write.

public:
    AllowedFields() = default;
    ~AllowedFields() override = default;

    /**
     * @brief Construct a new Allowed Fields object from a JSON definition.
     *
     * @param definition JSON document containing decoder_unmodifiable_fields.
     */
    AllowedFields(const json::Json& definition);

    /**
     * @copydoc IAllowedFields::check
     */
    bool check(const base::Name& assetType, const DotPath& field) const override;
};
} // namespace builder

#endif // BUILDER_ALLOWEDFIELDS_HPP
