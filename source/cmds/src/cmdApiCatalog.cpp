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
    "Engine API Catalog: Invalid name \"{}\" for action \"{}\", the name must be a valid "
    "\"{}\".";
constexpr auto CONTENT_SHOULD_BE_EMPTY =
    "Engine API Catalog: Content should be empty for action \"{}\". Content: \"{}\".";

constexpr auto CONTENT_CANNOT_BE_EMPTY =
    "Engine API XXX Catalog: Content cannot be empty for action \"{}\".";
}

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

    auto action = catalog_details::stringToAction(actionStr.c_str());
    if (action == catalog_details::Action::ERROR_ACTION)
    {
        // TODO: Why do we use std::cerr instead of WAZUH_LOG_ERROR?
        std::cerr << fmt::format("Engine API Catalog: Invalid action \"{}\".", actionStr)
                  << std::endl;
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
        std::cerr << fmt::format(
            "Engine API Catalog: Invalid name \"{}\": {}", nameStr, e.what())
                  << std::endl;
        return;
    }

    switch (action)
    {
        case catalog_details::Action::LIST:
            if (name.parts().size() != 1 && name.parts().size() != 2)
            {
                // TODO: Check this message
                std::cerr << fmt::format(
                    INVALID_NAME_FOR_ACTION, nameStr, actionStr, "<type>[/<item-id>]")
                          << std::endl;
                return;
            }
            if (!content.empty())
            {
                std::cerr << fmt::format(CONTENT_SHOULD_BE_EMPTY, actionStr, content)
                          << std::endl;
                return;
            }
            command = "get";
            break;
        case catalog_details::Action::GET:
            if (name.parts().size() != 3)
            {
                std::cerr << fmt::format(
                    INVALID_NAME_FOR_ACTION, nameStr, actionStr, "<type>/<item-id>/<ver>")
                          << std::endl;
                return;
            }
            if (!content.empty())
            {
                std::cerr << fmt::format(CONTENT_SHOULD_BE_EMPTY, actionStr, content)
                          << std::endl;
                return;
            }
            command = "get";
            break;
        case catalog_details::Action::UPDATE:
            if (name.parts().size() != 3)
            {
                std::cerr << fmt::format(
                    INVALID_NAME_FOR_ACTION, nameStr, actionStr, "<type>/<item-id>/<ver>")
                          << std::endl;
                return;
            }
            if (content.empty())
            {
                std::cerr << fmt::format(CONTENT_CANNOT_BE_EMPTY, actionStr) << std::endl;
                return;
            }
            command = "put";
            break;
        case catalog_details::Action::CREATE:
            if (name.parts().size() != 1)
            {
                std::cerr << fmt::format(
                    INVALID_NAME_FOR_ACTION, nameStr, actionStr, "<type>")
                          << std::endl;
                return;
            }
            if (content.empty())
            {
                std::cerr << fmt::format(CONTENT_CANNOT_BE_EMPTY, actionStr) << std::endl;
                return;
            }
            command = "post";
            break;
        case catalog_details::Action::DELETE:
            if (!content.empty())
            {
                std::cerr << fmt::format(CONTENT_SHOULD_BE_EMPTY, actionStr, content)
                          << std::endl;
                return;
            }
            command = "delete";
            break;
        case catalog_details::Action::VALIDATE:
            if (name.parts().size() != 3)
            {
                std::cerr << fmt::format(
                    INVALID_NAME_FOR_ACTION, nameStr, actionStr, "<type>/<item-id>/<ver>")
                          << std::endl;
                return;
            }
            if (content.empty())
            {
                std::cerr << fmt::format(CONTENT_CANNOT_BE_EMPTY, actionStr) << std::endl;
                return;
            }
            command = "validate";
            break;
        default:
            throw std::runtime_error(
                "Engine API Catalog: Invalid action for a single request.");
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
        std::cerr << "Engine API Catalog: Malformed request: " << request.toStr()
                  << std::endl;
        return;
    }
    auto requestStr = request.toStr();

    try
    {
        auto responseStr = apiclnt::connection(socketPath, requestStr);

        // Assert response is valid
        json::Json responseJson {responseStr.c_str()};
        auto errorCode = responseJson.getInt("/error");
        if (!errorCode)
        {
            std::cerr << fmt::format("Engine API Catalog: Malformed response, no return "
                                     "code (\"error\") field found: \"{}\".",
                                     responseStr)
                      << std::endl;
        }
        auto message = responseJson.getString("/message");
        if (!message)
        {
            std::cerr
                << "Engine API Catalog: Malformed response, no \"message\" field found: "
                << responseStr << std::endl;
        }
        auto data = responseJson.getJson("/data");
        if (!data)
        {
            std::cerr
                << "Engine API Catalog: Malformed response, no \"data\" field found: "
                << responseStr << std::endl;
        }

        // Print friendly response
        if (errorCode.value() != 200)
        {
            std::cout << fmt::format(
                "Communitacion Error ({}): {}.", errorCode.value(), message.value())
                      << std::endl;
        }
        else
        {
            auto content = data.value().getString("/content");
            if (content)
            {
                std::cout << content.value() << std::endl;
            }
            else
            {
                std::cout << "OK" << std::endl;
            }
        }
    }
    catch (const std::exception& e)
    {
        std::cerr
            << "Engine API Catalog: An error occurred while  procesing response from API: "
            << e.what() << std::endl;
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
        std::cerr << "Engine API Catalog: An error occurred while loading the ruleset: "
                  << e.what() << std::endl;
        return;
    }
    if (!std::filesystem::is_directory(collectionPath, ec))
    {
        std::cerr << fmt::format("Engine API Catalog: \"{}\" is not a directory: {}.",
                                 collectionPathStr,
                                 ec.message())
                  << std::endl;
        ec.clear();
        return;
    }

    // Assert collection name is valid
    if ("decoder" != collectionNameStr && "rule" != collectionNameStr
        && "filter" != collectionNameStr && "output" != collectionNameStr
        && "schema" != collectionNameStr && "environment" != collectionNameStr)
    {
        std::cerr << fmt::format("Engine API Catalog: Invalid collection name \"{}\".",
                                 collectionNameStr)
                  << std::endl;
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
            loadEntry(dirEntry);
        }
    }
    else
    {
        // Iterate directory and send requests to create items
        for (const auto& dirEntry :
             std::filesystem::directory_iterator(collectionPath, ec))
        {
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
            WAZUH_LOG_ERROR(fmt::format(
                "Engine API Catalog: Action \"{}\" is not supported.", actionStr));
            break;
    }
}

} // namespace cmd
