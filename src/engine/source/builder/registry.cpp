#include "registry.hpp"

namespace builder::internals
{

Builder Registry::getBuilder(const std::string& name)
{
    if (m_builders.find(name) == m_builders.end())
    {
        throw std::runtime_error(
            fmt::format("Builder name \"{}\" could not be found in the registry", name));
    }
    return m_builders.at(name);
}

void Registry::clear()
{
    m_builders.clear();
}

} // namespace builder::internals
