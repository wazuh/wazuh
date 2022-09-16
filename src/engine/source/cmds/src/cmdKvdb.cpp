#include "cmds/cmdKvdb.hpp"

#include <fstream>

#include <fmt/format.h>

#include <catalog/catalog.hpp>
#include <json/json.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>

#include "base/utils/getExceptionStack.hpp"

namespace cmd
{

InputType stringToInputType(std::string const& inputType)
{
    if (inputType == "json")
    {
        return InputType::JSON;
    }
    else
    {
        throw std::runtime_error(fmt::format("Invalid input type: {}", inputType));
    }
}

void kvdb(const std::string& kvdbPath,
          const std::string& kvdbName,
          const std::string& inputFile,
          InputType inputType)
{
    // Init logging
    logging::LoggingConfig logConfig;
    logConfig.logLevel = logging::LogLevel::Debug;
    logging::loggingInit(logConfig);

    try
    {
        KVDBManager::init(kvdbPath);
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Error initializing KVDBManager: {}",
                        utils::getExceptionStack(e));
        return;
    }

    // Open file and read content
    std::string contents;
    std::ifstream in(inputFile, std::ios::in | std::ios::binary);
    if (in)
    {
        in.seekg(0, std::ios::end);
        contents.resize(in.tellg());
        in.seekg(0, std::ios::beg);
        in.read(&contents[0], contents.size());
        in.close();
    }
    else
    {
        WAZUH_LOG_ERROR("Error while opening file [{}]. Error [{}]", inputFile, errno);
        return;
    }

    switch (inputType)
    {
        case InputType::JSON:
        {
            json::Json jKv;
            try
            {
                jKv = json::Json {contents.c_str()};
            }
            catch (const std::exception& e)
            {
                WAZUH_LOG_ERROR("Error parsing JSON: {}", utils::getExceptionStack(e));
                return;
            }

            if (!jKv.isObject())
            {
                WAZUH_LOG_ERROR("Error while parsing JSON file [{}]. Expected object",
                                inputFile);
                return;
            }
            auto entries = jKv.getObject();
            KVDBManager& kvdbManager = KVDBManager::get();
            kvdbManager.addDb(kvdbName);
            auto kvdbHandle = kvdbManager.getDB(kvdbName);
            for (const auto& [key, value] : entries.value())
            {

                try
                {
                    auto jsValue = value.str();
                    kvdbHandle->write(key, jsValue);
                }
                catch (const std::exception& e)
                {
                    WAZUH_LOG_ERROR("Error while writing key [{}] to KVDB [{}]: {}",
                                    key,
                                    kvdbName,
                                    utils::getExceptionStack(e));
                }
            }

            // TODO: Remove closing DB when KVDBManager destructor core dump is fixed
            kvdbHandle->close();
        }
        break;
        default: WAZUH_LOG_ERROR("Invalid input type"); return;
    }
    WAZUH_LOG_INFO("KVDB [{}] created successfully", kvdbName);
}

} // namespace cmd
