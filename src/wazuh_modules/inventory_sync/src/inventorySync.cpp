#include "inventorySync.hpp"
#include "cjsonSmartDeleter.hpp"
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

#ifdef __cplusplus
extern "C"
{
#endif
    void inventory_sync_start(full_log_fnc_t callbackLog, const cJSON* configuration)
    {
        nlohmann::json configurationNlohmann;
        if (configuration)
        {
            const std::unique_ptr<char, CJsonSmartFree> spJsonBytes {cJSON_Print(configuration)};
            configurationNlohmann = nlohmann::json::parse(spJsonBytes.get());
        }

        InventorySync::instance().start(
            [callbackLog](const int logLevel,
                          const std::string& tag,
                          const std::string& file,
                          const int line,
                          const std::string& func,
                          const std::string& logMessage,
                          va_list args)
            { callbackLog(logLevel, tag.c_str(), file.c_str(), line, func.c_str(), logMessage.c_str(), args); },
            configurationNlohmann);
    }

    void inventory_sync_stop()
    {
        InventorySync::instance().stop();
    }

#ifdef __cplusplus
}
#endif
