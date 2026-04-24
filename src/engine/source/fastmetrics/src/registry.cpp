#include <fastmetrics/registry.hpp>
#include <fastmetrics/manager.hpp>

namespace fastmetrics
{
void registerManager()
{
    SingletonLocator::registerManager<IManager, base::PtrSingleton<IManager, Manager>>();
}

} // namespace fastmetrics
