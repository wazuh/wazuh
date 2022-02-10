#include "registry.hpp"

namespace builder::internals
{

void Registry::registerBuilder(const std::string & builderName, const Registry::BuildType & builder)
{
    if (this->m_registry.count(builderName) > 0)
    {
        LOG(ERROR) << "Tried to register duplicate builder " << builderName << std::endl;
        throw std::invalid_argument("Tried to register duplicate builder " + builderName);
    }
    else
    {
        this->m_registry[builderName] = builder;
    }
}

Registry::BuildType Registry::getBuilder(const std::string & builderName)
{
    if (this->m_registry.count(builderName) == 0)
    {
        LOG(ERROR) << "Tried to obtain not registered builder " << builderName << std::endl;
        throw std::invalid_argument("Tried to obtain not registered builder " + builderName);
    }
    else
    {
        return this->m_registry[builderName];
    }
}

} // namespace builder::internals
