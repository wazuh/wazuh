#include "registry.hpp"

namespace builder::internals
{

std::map<std::string, Registry::BuildType> Registry::m_registry;

void Registry::registerBuilder(const std::string & builderName, const Registry::BuildType & builder)
{
    if (Registry::m_registry.count(builderName) > 0)
    {
        LOG(ERROR) << "Tried to register duplicate builder " << builderName << std::endl;
        throw std::invalid_argument("Tried to register duplicate builder " + builderName);
    }
    else
    {
        Registry::m_registry[builderName] = builder;
    }
}

Registry::BuildType Registry::getBuilder(const std::string & builderName)
{
    if (Registry::m_registry.count(builderName) == 0)
    {
        LOG(ERROR) << "Tried to obtain not registered builder " << builderName << std::endl;
        throw std::invalid_argument("Tried to obtain not registered builder " + builderName);
    }
    else
    {
        return Registry::m_registry[builderName];
    }
}

} // namespace builder::internals
