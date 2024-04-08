#include "schema.hpp"
#include "validator.hpp"

#include <stdexcept>

#include <fmt/format.h>

namespace schemf
{

Schema::Schema()
    : m_validator(std::make_unique<Validator>(*this))
{
}

Schema::~Schema() = default;

void Schema::addField(const DotPath& name, const Field& field)
{
    if (name.parts().empty())
    {
        throw std::invalid_argument("name cannot be empty");
    }

    // Add the field, iterating through the parts and adding parent fields as needed
    auto* current = &m_fields;
    decltype(current->begin()) entry;
    for (auto it = name.cbegin(); it != name.cend() - 1; ++it)
    {
        entry = current->find(*it);
        // If the field doesn't exist, add it as an empty object
        if (entry == current->end())
        {
            current->emplace(*it, Field({.type = Type::OBJECT}));
            current = &current->at(*it).properties();
        }
        else
        {
            if (!hasProperties(entry->second.type()))
            {
                throw std::runtime_error(fmt::format("Field '{}' is not an object in '{}", *it, name.str()));
            }
            current = &entry->second.properties();
        }
    }

    // Add the field to the last part
    entry = current->find(name.parts().back());
    if (entry != current->end())
    {
        throw std::runtime_error(fmt::format("Field '{}' already exists", name.str()));
    }

    current->emplace(name.parts().back(), field);
}

void Schema::removeField(const DotPath& name)
{
    if (name.parts().empty())
    {
        throw std::runtime_error("name cannot be empty");
    }

    auto* current = &m_fields;
    decltype(current->begin()) entry;

    for (auto it = name.cbegin(); it != name.cend() - 1; ++it)
    {
        entry = current->find(*it);
        if (entry == current->end())
        {
            throw std::runtime_error(fmt::format("Field '{}' does not exist in '{}'", *it, name.str()));
        }
        current = &entry->second.properties();
    }

    entry = current->find(name.parts().back());
    if (entry == current->end())
    {
        throw std::runtime_error(fmt::format("Field '{}' does not exist in '{}'", name.parts().back(), name.str()));
    }

    current->erase(entry);
}

Field Schema::get(const DotPath& name) const
{
    const auto* current = &m_fields;
    const Field* target = nullptr;

    for (auto it = name.cbegin(); it != name.cend(); ++it)
    {
        auto entry = current->find(*it);
        if (entry == current->end())
        {
            throw std::runtime_error(fmt::format("Field '{}' does not exist in '{}'", it->data(), name.str()));
        }

        if (it != name.cend() - 1)
        {
            // Handle arrays e.g. "field/0"
            // If the field is an array and the next part is the last one and a number, return a new field with the
            // array type
            if (entry->second.isArray() && (it + 1) == (name.cend() - 1))
            {
                auto arrayIndex = *(it + 1);
                auto isIndex = true;
                for (const auto& c : arrayIndex)
                {
                    if (!std::isdigit(c))
                    {
                        isIndex = false;
                        break;
                    }
                }
                if (isIndex)
                {
                    return Field({.type = entry->second.type(), .isArray = false});
                }
            }
            current = &entry->second.properties();
        }
        else
        {
            target = &entry->second;
        }
    }

    if (!target)
    {
        throw std::runtime_error(fmt::format("Field '{}' does not exist in '{}'", name.str()));
    }

    return *target;
}

bool Schema::hasField(const DotPath& name) const
{
    const auto* current = &m_fields;
    auto isParentSchema = false;
    for (auto it = name.cbegin(); it != name.cend(); ++it)
    {
        auto entry = current->find(*it);
        if (entry == current->end())
        {
            if (!isParentSchema)
            {
                return false;
            }

            throw std::runtime_error(fmt::format("Field '{}' does not exist in '{}'", it->data(), name.str()));
        }

        isParentSchema = true;

        if (it != name.cend() - 1)
        {
            // Handle arrays e.g. "field/0"
            // If the field is an array and the next part is the last one and a number, return true
            if (entry->second.isArray() && it + 1 == name.cend() - 1)
            {
                auto arrayIndex = *(it + 1);
                auto isIndex = true;
                for (const auto& c : arrayIndex)
                {
                    if (!std::isdigit(c))
                    {
                        isIndex = false;
                    }
                }

                if (isIndex)
                {
                    return true;
                }
            }

            if (entry->second.type() != Type::OBJECT && entry->second.type() != Type::NESTED)
            {
                return false;
            }
            current = &entry->second.properties();
        }
    }

    return true;
}

Field Schema::entryToField(const std::string& name, const json::Json& entry) const
{
    if (entry.type() != json::Json::Type::Object)
    {
        throw std::runtime_error(fmt::format("Entry for Field '{}' must be an object", name));
    }

    Field::Parameters params;

    auto type = entry.getString("/type");
    if (!type)
    {
        throw std::runtime_error(fmt::format("Field '{}' must have a type", name));
    }
    params.type = strToType(type.value());
    params.isArray = entry.getBool("/array").value_or(false);

    Field field;
    try
    {
        field = Field(params);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("Field '{}' cannot be built from entry '{}', error: '{}'", name, entry.prettyStr(), e.what()));
    }

    return field;
}

void Schema::load(const json::Json& json)
{
    if (json.type() != json::Json::Type::Object)
    {
        throw std::runtime_error("Schema json must be an object");
    }

    auto fields = json.getObject("/fields");
    if (!fields)
    {
        throw std::runtime_error("Schema json must have a 'fields' object");
    }

    for (const auto& [key, value] : fields.value())
    {
        auto field = entryToField(key, value);
        addField(key, field);
    }
}

base::RespOrError<ValidationResult> Schema::validate(const DotPath& name, const ValidationToken& token) const
{
    return m_validator->validate(name, token);
}
} // namespace schemf
