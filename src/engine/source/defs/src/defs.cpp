#include "defs.hpp"

#include <stdexcept>
#include <vector>

#include <fmt/format.h>

namespace defs
{
Definitions::Definitions(const json::Json& definitions)
{
    if (!definitions.isObject())
    {
        throw std::runtime_error(fmt::format("Definitions must be an object, got {}", definitions.typeName()));
    }

    if (definitions.size() < 1)
    {
        throw std::runtime_error("Definitions must not be empty");
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
    return m_definitions->getJson(name).value();
}

bool Definitions::contains(std::string_view name) const
{
    return m_definitions && m_definitions->exists(name);
}
} // namespace defs
