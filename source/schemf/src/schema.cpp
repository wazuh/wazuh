#include "schema.hpp"

#include <stdexcept>

#include <fmt/format.h>

namespace schemf
{
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
            current->emplace(*it, Field({.type = json::Json::Type::Object}));
            current = &current->at(*it).properties();
        }
        else
        {
            if (entry->second.type() != json::Json::Type::Object
                && (entry->second.type() == json::Json::Type::Array
                    && entry->second.itemsType() != json::Json::Type::Object))
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

const Field& Schema::get(const DotPath& name) const
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

json::Json::Type Schema::getType(const DotPath& name) const
{
    auto type = get(name).type();
    return type;
}

bool Schema::hasField(const DotPath& name) const
{
    const auto* current = &m_fields;
    for (auto it = name.cbegin(); it != name.cend(); ++it)
    {
        auto entry = current->find(*it);
        if (entry == current->end())
        {
            return false;
        }

        if (it != name.cend() - 1)
        {
            current = &entry->second.properties();
        }
    }

    return true;
}

std::optional<base::Error> Schema::validate(const DotPath& target, const json::Json& value) const
{
    auto field = get(target);
    auto valueField = Field(value);

    if (field != valueField)
    {
        return base::Error {"Type mismatch"};
    }

    return std::nullopt;
}

std::optional<base::Error> Schema::validate(const DotPath& target, const DotPath& reference) const
{
    auto field = get(target);
    auto ref = get(reference);

    if (field != ref)
    {
        return base::Error {"Type mismatch"};
    }

    return std::nullopt;
}

ISchema::RuntimeValidator Schema::getRuntimeValidator(const DotPath& target) const
{
    auto field = get(target);
    return [field](const json::Json& value) -> std::optional<base::Error>
    {
        if (field.type() != value.type())
        {
            return base::Error {"Type mismatch"};
        }

        return std::nullopt;
    };
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

    if (entry.getBool("/array").value_or(false))
    {
        params.itemsType = json::Json::strToType(type.value().c_str());
        params.type = json::Json::Type::Array;
    }
    else
    {
        params.type = json::Json::strToType(type.value().c_str());
    }

    return Field(params);
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

} // namespace schemf
