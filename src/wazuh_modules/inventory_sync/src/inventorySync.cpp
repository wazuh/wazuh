#include "inventorySync.hpp"
#include "inventorySyncFacade.hpp"

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};

void InventorySync::start(
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction,
    const nlohmann::json& configuration) const
{

    InventorySyncFacade::instance().start(logFunction, configuration);
}

void InventorySync::stop() const
{
    InventorySyncFacade::instance().stop();
}
