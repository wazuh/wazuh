#include <builder/allowedFields.hpp>

#include <fmt/format.h>

#include "syntax.hpp"

namespace builder
{
namespace
{
bool startsWithPathPrefix(const std::string& field, const std::string& prefix)
{
    return field.size() > prefix.size() && field.compare(0, prefix.size(), prefix) == 0 && field[prefix.size()] == '.';
}
} // namespace

AllowedFields::AllowedFields(const json::Json& definition)
{
    if (!definition.isObject())
    {
        throw std::runtime_error {"Decoder unmodifiable fields definition must be an object"};
    }

    std::string name;
    if (definition.getString(name, syntax::allowedfields::NAME_PATH) != json::RetGet::Success)
    {
        throw std::runtime_error {"Decoder unmodifiable fields definition must have a name"};
    }

    auto unmodifiableFields = definition.getArray(syntax::allowedfields::DECODER_UNMODIFIABLE_FIELDS_PATH);
    if (!unmodifiableFields)
    {
        throw std::runtime_error {"Decoder unmodifiable fields definition must have decoder_unmodifiable_fields entry"};
    }

    for (const auto& field : unmodifiableFields.value())
    {
        if (!field.isString())
        {
            throw std::runtime_error {
                fmt::format("Decoder unmodifiable field entry '{}' must be a string", field.str())};
        }

        std::string fieldStr;
        field.getString(fieldStr);
        m_decoderUnmodifiableFields.insert(std::move(fieldStr));
    }
}

bool AllowedFields::check(const base::Name& assetType, const DotPath& field) const
{
    // Only decoders have protected write targets.
    if (!syntax::name::isDecoder(assetType, false))
    {
        return true;
    }

    // Always allow root field
    if (field.isRoot())
    {
        return true;
    }

    const auto fieldStr = field.str();
    for (const auto& unmodifiableField : m_decoderUnmodifiableFields)
    {
        const auto unmodifiableFieldStr = unmodifiableField.str();
        if (fieldStr == unmodifiableFieldStr || startsWithPathPrefix(fieldStr, unmodifiableFieldStr))
        {
            return false;
        }
    }

    return true;
}
} // namespace builder
