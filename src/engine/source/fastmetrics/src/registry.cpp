#include <fastmetrics/registry.hpp>

#include <base/utils/singletonLocator.hpp>
#include <base/utils/singletonLocatorStrategies.hpp>

#include <fastmetrics/manager.hpp>

namespace fastmetrics
{

void registerManager()
{
    SingletonLocator::registerManager<IManager, base::PtrSingleton<IManager, Manager>>();
}

IManager& manager()
{
    return SingletonLocator::instance<IManager>();
}

} // namespace fastmetrics
