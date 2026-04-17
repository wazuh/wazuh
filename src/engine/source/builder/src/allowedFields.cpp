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

    std::string name;
    if (definition.getString(name, syntax::allowedfields::NAME_PATH) != json::RetGet::Success)
    {
        throw std::runtime_error {"Allowed fields definition must have a name"};
    }

    auto allowedFields = definition.getObject(syntax::allowedfields::ALLOWED_FIELDS_PATH);
    if (!allowedFields)
    {
        throw std::runtime_error {"Allowed fields definition must have allowed_fields entry"};
    }

    auto asObj = allowedFields.value();
    for (const auto& [key, value] : asObj)
    {
        if (!syntax::name::isDecoder(base::Name {key}, false) && !syntax::name::isOutput(base::Name {key}, false)
            && !syntax::name::isFilter(base::Name {key}, false))
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

            std::string fieldStr;
            field.getString(fieldStr);
            m_fields[key].insert(std::move(fieldStr));
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

    // Always allow root field
    if (field.isRoot())
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
