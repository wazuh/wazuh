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

Manager& manager()
{
    // Return concrete Manager& so registerPullMetric template is accessible
    return static_cast<Manager&>(SingletonLocator::instance<IManager>());
}

} // namespace fastmetrics
