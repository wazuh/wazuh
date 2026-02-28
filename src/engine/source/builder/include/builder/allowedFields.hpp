#ifndef BUILDER_ALLOWEDFIELDS_HPP
#define BUILDER_ALLOWEDFIELDS_HPP

#include <unordered_map>
#include <unordered_set>

#include <fmt/format.h>

#include <base/json.hpp>
#include <builder/iallowedFields.hpp>

namespace builder
{

/**
 * @brief Concrete implementation of IAllowedFields.
 *
 * Reads allowed-field definitions from a JSON document and performs per-asset-type field checks.
 */
class AllowedFields final : public IAllowedFields
{
private:
    std::unordered_map<base::Name, std::unordered_set<DotPath>> m_fields; ///< Map of asset types to allowed fields.

public:
    AllowedFields() = default;
    ~AllowedFields() override = default;

    /**
     * @brief Construct a new Allowed Fields object from a JSON definition.
     *
     * @param definition JSON document mapping asset types to their allowed fields.
     */
    AllowedFields(const json::Json& definition);

    /**
     * @copydoc IAllowedFields::check
     */
    bool check(const base::Name& assetType, const DotPath& field) const override;
};
} // namespace builder

#endif // BUILDER_ALLOWEDFIELDS_HPP
