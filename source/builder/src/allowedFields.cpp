#include <builder/allowedFields.hpp>

#include <fmt/format.h>

#include "syntax.hpp"

namespace builder
{
AllowedFields::AllowedFields(const json::Json& definition)
{
    if (!definition.isObject())
    {
        throw std::runtime_error {"Allowed fields definition must be an object"};
    }

    auto asObj = definition.getObject().value();
    for (auto [key, value] : asObj)
    {
        if (!syntax::name::isDecoder(base::Name {key}, false) && !syntax::name::isRule(base::Name {key}, false)
            && !syntax::name::isOutput(base::Name {key}, false) && !syntax::name::isFilter(base::Name {key}, false))
        {
            throw std::runtime_error {fmt::format("Unknown asset name '{}' in allowed fields definition", key)};
        }

        if (!value.isArray())
        {
            throw std::runtime_error {fmt::format("Allowed fields for asset '{}' must be an array", key)};
        }

        auto fields = value.getArray().value();
        for (const auto& field : fields)
        {
            if (!field.isString())
            {
                throw std::runtime_error {
                    fmt::format("Allowed field '{}' for asset '{}' must be a string", field.str(), key)};
            }

            m_fields[key].insert(field.getString().value());
        }
    }
}

bool AllowedFields::check(const base::Name& assetType, const DotPath& field) const
{
    auto it = m_fields.find(assetType);
    // No restrictions for this asset type
    if (it == m_fields.end())
    {
        return true;
    }

    if (it->second.find(field) == it->second.end())
    {
        return false;
    }

    return true;
}
} // namespace builder
