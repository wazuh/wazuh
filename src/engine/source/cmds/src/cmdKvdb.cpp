#include "cmds/cmdKvdb.hpp"

#include <fstream>

#include <fmt/format.h>

#include <json/json.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>

#include "base/utils/getExceptionStack.hpp"

namespace cmd
{

InputType stringToInputType(std::string const& inputType)
{
    if ("json" == inputType)
    {
        return InputType::JSON;
    }
    else
    {
        throw std::runtime_error(fmt::format(
            "Engine \"kvdb\" command: Invalid input type \"{}\".", inputType));
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
    std::shared_ptr<KVDBManager> kvdbManager;
    try
    {
        kvdbManager = std::make_shared<KVDBManager>(kvdbPath);
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Engine \"kvdb\" command: An error occurred while initializing "
                        "KVDBManager: {}",
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
        WAZUH_LOG_ERROR("Engine \"kvdb\" command: An error occurred while opening the "
                        "file \"{}\": {} ({})",
                        inputFile,
                        strerror(errno),
                        errno);
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
                WAZUH_LOG_ERROR("Engine \"kvdb\" command: An error occurred while "
                                "parsing the JSON file \"{}\": {}",
                                inputFile,
                                utils::getExceptionStack(e));
                return;
            }

            if (!jKv.isObject())
            {
                WAZUH_LOG_ERROR("Engine \"kvdb\" command: An error occurred while "
                                "parsing the JSON file \"{}\": JSON is not an object.",
                                inputFile);
                return;
            }
            auto entries = jKv.getObject();
            kvdbManager->addDb(kvdbName);
            auto kvdbHandle = kvdbManager->getDB(kvdbName);
            for (const auto& [key, value] : entries.value())
            {

                try
                {
                    auto jsValue = value.str();
                    kvdbHandle->write(key, jsValue);
                }
                catch (const std::exception& e)
                {
                    WAZUH_LOG_ERROR("Engine \"kvdb\" command: An error occurred while "
                                    "writing the key \"{}\" to the database \"{}\": {}",
                                    key,
                                    kvdbName,
                                    utils::getExceptionStack(e));
                }
            }

            // TODO: Remove closing DB when KVDBManager destructor core dump is fixed
            kvdbHandle->close();
        }
        break;
        default:
            WAZUH_LOG_ERROR(
                "Engine \"kvdb\" command: Invalid input type, only JSON is supported.");
            return;
    }
    WAZUH_LOG_INFO("Engine \"kvdb\" command: Database \"{}\" successfully created.",
                   kvdbName);
}

} // namespace cmd
