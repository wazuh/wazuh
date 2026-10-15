// SPDX-License-Identifier: AGPL-3.0-or-later
#include <fastmetrics/manager.hpp>
#include <fastmetrics/registry.hpp>

namespace fastmetrics
{
void registerManager()
{
    SingletonLocator::registerManager<IManager, base::PtrSingleton<IManager, Manager>>();
}

} // namespace fastmetrics
