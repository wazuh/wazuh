#include "cmds/cmdApiCatalog.hpp"
#include "apiclnt/connection.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <system_error>

#include <api/wazuhRequest.hpp>
#include <api/wazuhResponse.hpp>
#include <json/json.hpp>
#include <name.hpp>
#include <variant>

namespace
{
constexpr auto INVALID_NAME_FOR_ACTION =
    "Engine API Catalog: Invalid name \"{}\" for action \"{}\", the name must have the "
    "following format: \"{}\".";

constexpr auto CONTENT_SHOULD_BE_EMPTY =
    "Engine API Catalog: Content should be empty for action \"{}\".";

constexpr auto CONTENT_CANNOT_BE_EMPTY =
    "Engine API Catalog: Content cannot be empty for action \"{}\".";
} // namespace

namespace cmd
{

namespace catalog_details
{

void singleRequest(const std::string& socketPath,
                   const std::string& actionStr,
                   const std::string& nameStr,
                   const std::string& format,
                   const std::string& content)
{
    api::WazuhRequest request;

    WAZUH_LOG_DEBUG("Engine API Catalog: \"{}\" method: Request parameters: socket path: "
                    "\"{}\", action: \"{}\", type: \"{}\", format: \"{}\".",
                    __func__,
                    socketPath,
                    actionStr,
                    nameStr,
                    format);

    auto action = catalog_details::stringToAction(actionStr.c_str());
    if (action == catalog_details::Action::ERROR_ACTION)
    {
        WAZUH_LOG_ERROR("Engine API Catalog: Invalid action \"{}\".", actionStr);
        return;
    }

    // Prepare command and assert name is valid for the action
    std::string command;
    base::Name name;
    try
    {
        name = base::Name {nameStr};
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR(
            "Engine API Catalog: Invalid name \"{}\": {}.", nameStr, e.what());
        return;
    }

    switch (action)
    {
        case catalog_details::Action::LIST:
            if (name.parts().size() != 1 && name.parts().size() != 2)
            {
                // TODO: Check this message
                WAZUH_LOG_ERROR(
                    INVALID_NAME_FOR_ACTION, nameStr, actionStr, "<type>[/<item-id>]");
                return;
            }
            if (!content.empty())
            {
                WAZUH_LOG_ERROR(CONTENT_SHOULD_BE_EMPTY, actionStr);
                return;
            }
            command = "get";
            break;
        case catalog_details::Action::GET:
            if (name.parts().size() != 3)
            {
                WAZUH_LOG_ERROR(INVALID_NAME_FOR_ACTION,
                                nameStr,
                                actionStr,
                                "<type>/<item-id>/<ver>");
                return;
            }
            if (!content.empty())
            {
                WAZUH_LOG_ERROR(CONTENT_SHOULD_BE_EMPTY, actionStr);
                return;
            }
            command = "get";
            break;
        case catalog_details::Action::UPDATE:
            if (name.parts().size() != 3)
            {
                WAZUH_LOG_ERROR(INVALID_NAME_FOR_ACTION,
                                nameStr,
                                actionStr,
                                "<type>/<item-id>/<ver>");
                return;
            }
            if (content.empty())
            {
                WAZUH_LOG_ERROR(CONTENT_CANNOT_BE_EMPTY, actionStr);
                return;
            }
            command = "put";
            break;
        case catalog_details::Action::CREATE:
            if (name.parts().size() != 1)
            {
                WAZUH_LOG_ERROR(INVALID_NAME_FOR_ACTION, nameStr, actionStr, "<type>");
                return;
            }
            if (content.empty())
            {
                WAZUH_LOG_ERROR(CONTENT_CANNOT_BE_EMPTY, actionStr);
                return;
            }
            command = "post";
            break;
        case catalog_details::Action::DELETE:
            if (!content.empty())
            {
                WAZUH_LOG_ERROR(CONTENT_SHOULD_BE_EMPTY, actionStr);
                return;
            }
            command = "delete";
            break;
        case catalog_details::Action::VALIDATE:
            if (name.parts().size() != 3)
            {
                WAZUH_LOG_ERROR(INVALID_NAME_FOR_ACTION,
                                nameStr,
                                actionStr,
                                "<type>/<item-id>/<ver>");
                return;
            }
            if (content.empty())
            {
                WAZUH_LOG_ERROR(CONTENT_CANNOT_BE_EMPTY, actionStr);
                return;
            }
            command = "validate";
            break;
        default:
            throw std::runtime_error(
                fmt::format("Invalid action \"{}\" for a single request", actionStr));
    }
    command += "_catalog";

    json::Json params;
    params.setObject();
    params.setString(format, "/format");
    params.setString(name.fullName(), "/name");
    params.setString(content, "/content");

    request = api::WazuhRequest::create(command, "api", params);
    if (!request.isValid())
    {
        // TODO: check this message
        WAZUH_LOG_ERROR("Engine API Catalog: Malformed request: \"{}\".",
                        request.toStr());
        return;
    }

    const auto requestStr = request.toStr();
    std::string responseStr {};
    try
    {
        responseStr = apiclnt::connection(socketPath, requestStr);
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR(
            "Engine API Catalog: An error occurred while sending a request: {}.",
            e.what());

        return;
    }

    if (responseStr.empty())
    {
        WAZUH_LOG_ERROR("Engine API Catalog: Request response is empty.");
        return;
    }

    try
    {
        // Assert response is valid
        json::Json responseJson {responseStr.c_str()};
        const auto errorCode = responseJson.getInt("/error");
        if (!errorCode)
        {
            WAZUH_LOG_ERROR("Engine API Catalog: Malformed response, no return code "
                            "(\"error\") field found.");
        }
        const auto message = responseJson.getString("/message");
        if (!message)
        {
            WAZUH_LOG_ERROR(
                "Engine API Catalog: Malformed response, no \"message\" field found.",
                responseStr);
        }
        const auto data = responseJson.getJson("/data");
        if (!data)
        {
            WAZUH_LOG_ERROR(
                "Engine API Catalog: Malformed response, no \"data\" field found.",
                responseStr);
        }

        // Print friendly response
        if (errorCode.value() != 200)
        {
            WAZUH_LOG_ERROR("Engine API Catalog: Request error ({}): {}.",
                            errorCode.value(),
                            message.value());
        }
        else
        {
            // TODO: are we sure the field is content and not "messager" or "data"?
            const auto content = data.value().getString("/content");
            if (content)
            {
                const std::string msg {fmt::format("Request \"{} {}\" response: \"{}\"",
                                                   actionStr,
                                                   name.fullName(),
                                                   content.value())};
                WAZUH_LOG_INFO("Engine API Catalog: {}.", msg);
                std::cout << msg << std::endl;
            }
            else
            {
                const std::string msg {fmt::format(
                    "Request \"{} {}\" succeeded", actionStr, name.fullName())};
                WAZUH_LOG_INFO("Engine API Catalog: {}.", msg);
                std::cout << msg << std::endl;
            }
        }
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Engine API Catalog: An error occurred while procesing the "
                        "request response from the API: {}.",
                        e.what());
    }
}

void loadRuleset(const std::string& socketPath,
                 const std::string& collectionNameStr,
                 const std::string& collectionPathStr,
                 const std::string& format,
                 const bool recursive)
{
    // Build and check collection path
    std::error_code ec;
    std::filesystem::path collectionPath;

    try
    {
        collectionPath = std::filesystem::path(collectionPathStr);
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR(
            "Engine API Catalog: An error occurred while loading the ruleset: {}.",
            e.what());
        return;
    }
    if (!std::filesystem::is_directory(collectionPath, ec))
    {
        WAZUH_LOG_ERROR("Engine API Catalog: \"{}\" is not a directory: {}.",
                        collectionPathStr,
                        ec.message());
        ec.clear();
        return;
    }

    // Assert collection name is valid
    if ("decoder" != collectionNameStr && "rule" != collectionNameStr
        && "filter" != collectionNameStr && "output" != collectionNameStr
        && "schema" != collectionNameStr && "environment" != collectionNameStr)
    {
        WAZUH_LOG_ERROR("Engine API Catalog: Invalid collection type \"{}\".",
                        collectionNameStr);
        return;
    }

    auto loadEntry =
        [&](decltype(*std::filesystem::directory_iterator(collectionPath, ec)) dirEntry)
    {
        // If error ignore entry and continue
        if (ec)
        {
            WAZUH_LOG_ERROR(fmt::format("Engine API Catalog: An error ocurred while "
                                        "reading the file \"{}\": {}",
                                        dirEntry.path().c_str(),
                                        ec.message()));
            ec.clear();
            return;
        }

        if (dirEntry.is_regular_file(ec))
        {
            // If error ignore entry and continue
            if (ec)
            {
                WAZUH_LOG_ERROR(fmt::format("Engine API Catalog: An error ocurred "
                                            "while reading the file \"{}\": {}",
                                            dirEntry.path().c_str(),
                                            ec.message()));
                ec.clear();
                return;
            }

            // Read file content
            std::string content;

            try
            {
                std::ifstream file(dirEntry.path());
                content = std::string(std::istreambuf_iterator<char>(file),
                                      std::istreambuf_iterator<char>());
            }
            catch (const std::exception& e)
            {
                WAZUH_LOG_ERROR(fmt::format("Engine API Catalog: An error ocurred "
                                            "while reading the file \"{}\": {}",
                                            dirEntry.path().c_str(),
                                            e.what()));
                return;
            }

            // Send request
            singleRequest(socketPath,
                          actionToString(Action::CREATE),
                          collectionNameStr,
                          format,
                          content);
        }
    };

    if (recursive)
    {
        // Iterate directory recursively and send requests to create items
        for (const auto& dirEntry :
             std::filesystem::recursive_directory_iterator(collectionPath, ec))
        {
            WAZUH_LOG_INFO("Engine API Catalog: Loading {}s from file \"{}\".",
                           collectionNameStr,
                           dirEntry.path().c_str());
            loadEntry(dirEntry);
        }
    }
    else
    {
        // Iterate directory and send requests to create items
        for (const auto& dirEntry :
             std::filesystem::directory_iterator(collectionPath, ec))
        {
            WAZUH_LOG_INFO("Engine API Catalog: Loading {}s from file \"{}\".",
                           collectionNameStr,
                           dirEntry.path().c_str());
            loadEntry(dirEntry);
        }
    }
}

} // namespace catalog_details

void catalog(const std::string& socketPath,
             const std::string& actionStr,
             const std::string& nameStr,
             const std::string& format,
             const std::string& content,
             const std::string& path,
             const bool recursive)
{
    // TODO: logging level should be configured for every command
    logging::LoggingConfig logConfig;
    logConfig.logLevel = logging::LogLevel::Debug;
    logging::loggingInit(logConfig);

    auto action = catalog_details::stringToAction(actionStr.c_str());
    switch (action)
    {
        case catalog_details::Action::CREATE:
        case catalog_details::Action::DELETE:
        case catalog_details::Action::UPDATE:
        case catalog_details::Action::GET:
        case catalog_details::Action::LIST:
        case catalog_details::Action::VALIDATE:
            catalog_details::singleRequest(
                socketPath, actionStr, nameStr, format, content);
            break;
        case catalog_details::Action::LOAD:
            catalog_details::loadRuleset(socketPath, nameStr, path, format, recursive);
            break;
        default:
            WAZUH_LOG_ERROR("Engine API Catalog: Action \"{}\" is not supported.",
                            actionStr);
            break;
    }
}

} // namespace cmd
