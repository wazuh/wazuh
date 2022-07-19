#include "registry.hpp"

namespace builder::internals
{

using Builder = std::function<base::Expression(std::any)>;

Registry& Registry::instance()
{
    static Registry instance;
    return instance;
}

Builder& Registry::getBuilder(const std::string& name)
{
    if (Registry::instance().m_builders.find(name)
        == Registry::instance().m_builders.end())
    {
        throw std::runtime_error(fmt::format(
            "[getBuilder(name)] name not found in the registry: [{}]", name));
    }
    return Registry::instance().m_builders.at(name);
}

void Registry::clear()
{
    Registry::instance().m_builders.clear();
}

} // namespace builder::internals
