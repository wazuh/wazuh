#ifndef BUILDER_ALLOWEDFIELDS_HPP
#define BUILDER_ALLOWEDFIELDS_HPP

#include <unordered_map>
#include <unordered_set>

#include <fmt/format.h>

#include <base/json.hpp>
#include <builder/iallowedFields.hpp>

namespace builder
{
class AllowedFields final : public IAllowedFields
{
private:
    std::unordered_map<base::Name, std::unordered_set<DotPath>> m_fields;

public:
    AllowedFields() = default;
    ~AllowedFields() override = default;

    AllowedFields(const json::Json& definition);

    bool check(const base::Name& assetType, const DotPath& field) const override;
};
} // namespace builder

#endif // BUILDER_ALLOWEDFIELDS_HPP
