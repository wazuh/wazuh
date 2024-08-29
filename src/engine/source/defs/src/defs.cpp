#include "defs.hpp"

#include <algorithm>
#include <stdexcept>

#include <fmt/format.h>

namespace defs
{
Definitions::Definitions(const json::Json& definitions)
{
    if (!definitions.isObject())
    {
        throw std::runtime_error(fmt::format("Definitions must be an object, got {}", definitions.typeName()));
    }

    auto defVars = definitions.getObject().value();
    for (const auto& [name, value] : defVars)
    {
        // TODO check definitions don't have the same name as schema fields when implemented
        // TODO move syntax from the builder to base
        if (name[0] == '$')
        {
            throw std::runtime_error(fmt::format("Definition name '{}' cannot start with '$'", name));
        }
    }

    m_definitions = std::make_unique<json::Json>(definitions);
}

json::Json Definitions::get(std::string_view name) const
{
    auto val = m_definitions->getJson(name);
    if (!val)
    {
        throw std::runtime_error(fmt::format("Definition '{}' not found", name));
    }

    return val.value();
}

bool Definitions::contains(std::string_view name) const
{
    return m_definitions && m_definitions->exists(name);
}

std::string Definitions::replace(std::string_view input) const
{
    if (!m_definitions)
    {
        return std::string(input);
    }

    // Replace in inverse order of definition declaration, so that definitions can reference each other
    // without causing infinite recursion
    auto replaced = std::string(input);
    auto defObj = m_definitions->getObject().value();

    for (auto def = defObj.rbegin(); def != defObj.rend(); ++def)
    {
        // Find and replace every occurrence of the definition name in the input string
        std::string defName = "$" + std::get<0>(*def);
        std::string defValue = std::get<1>(*def).getString().value_or(std::get<1>(*def).str());

        size_t pos = 0;
        while ((pos = replaced.find(defName, pos)) != std::string::npos)
        {
            // Check if the found $ is escaped with '\'
            if (pos > 0 && replaced[pos - 1] == '\\')
            {
                replaced.erase(pos - 1, 1);  // Remove the escape character '\'
                pos += defName.length() - 1; // Counter the erase and move over the name
            }
            else
            {
                replaced.replace(pos, defName.length(), defValue);
                pos += defValue.length(); // Move forward to avoid infinite loop
            }
        }
    }

    return replaced;
}
} // namespace defs
