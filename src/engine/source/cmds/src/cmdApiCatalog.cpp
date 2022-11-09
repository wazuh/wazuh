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
        std::cerr << "Invalid action " << actionStr << std::endl;
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
        std::cerr << fmt::format("Invalid name [{}]: {}", nameStr, e.what()) << std::endl;
        return;
    }

    switch (action)
    {
        case catalog_details::Action::LIST:
            if (name.parts().size() != 1 && name.parts().size() != 2)
            {
                std::cerr << fmt::format("Invalid name [{}] for action {}, name must be "
                                         "a valid <type>[/<item-id>]",
                                         nameStr,
                                         actionStr)
                          << std::endl;
                return;
            }
            if (!content.empty())
            {
                std::cerr << "Content not allowed for action " << actionStr << std::endl;
                return;
            }
            command = "get";
            break;
        case catalog_details::Action::GET:
            if (name.parts().size() != 3)
            {
                std::cerr << fmt::format("Invalid name [{}] for action {}, name must be "
                                         "a valid <type>/<item-id>/<ver>",
                                         nameStr,
                                         actionStr)
                          << std::endl;
                return;
            }
            if (!content.empty())
            {
                std::cerr << "Content not allowed for action " << actionStr << std::endl;
                return;
            }
            command = "get";
            break;
        case catalog_details::Action::UPDATE:
            if (name.parts().size() != 3)
            {
                std::cerr << fmt::format("Invalid name [{}] for action {}, name must be "
                                         "a valid <type>/<item-id>/<ver>",
                                         nameStr,
                                         actionStr)
                          << std::endl;
                return;
            }
            if (content.empty())
            {
                std::cerr << "Content required for action " << actionStr << std::endl;
                return;
            }
            command = "put";
            break;
        case catalog_details::Action::CREATE:
            if (name.parts().size() != 1)
            {
                std::cerr << fmt::format(
                    "Invalid name [{}] for action {}, name must be a valid <type>",
                    nameStr,
                    actionStr)
                          << std::endl;
                return;
            }
            if (content.empty())
            {
                std::cerr << "Content required for action " << actionStr << std::endl;
                return;
            }
            command = "post";
            break;
        case catalog_details::Action::DELETE:
            if (!content.empty())
            {
                std::cerr << "Content not allowed for action " << actionStr << std::endl;
                return;
            }
            command = "delete";
            break;
        case catalog_details::Action::VALIDATE:
            if (name.parts().size() != 3)
            {
                std::cerr << fmt::format("Invalid name [{}] for action {}, name must be "
                                         "a valid <type>/<item-id>/<ver>",
                                         nameStr,
                                         actionStr)
                          << std::endl;
                return;
            }
            if (content.empty())
            {
                std::cerr << "Content required for action " << actionStr << std::endl;
                return;
            }
            command = "validate";
            break;
        default: throw std::runtime_error("Invalid action for single request");
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
        std::cerr << "Request malformed: " << request.toStr() << std::endl;
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
            std::cerr << "Malformed response, no error code: " << responseStr
                      << std::endl;
        }
        auto message = responseJson.getString("/message");
        if (!message)
        {
            std::cerr << "Malformed response, no message: " << responseStr << std::endl;
        }
        auto data = responseJson.getJson("/data");
        if (!data)
        {
            std::cerr << "Malformed response, no data: " << responseStr << std::endl;
        }

        // Print friendly response
        if (errorCode.value() != 200)
        {
            std::cout << "Error: " << message.value() << std::endl;
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
        std::cerr << "Error procesing response from API: " << e.what() << std::endl;
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
        std::cerr << e.what() << '\n';
        return;
    }
    if (!std::filesystem::is_directory(collectionPath, ec))
    {
        std::cerr << "Error " << collectionPathStr
                  << " is not a directory: " << ec.message() << std::endl;
        ec.clear();
        return;
    }

    // Assert collection name is valid
    if ("decoder" != collectionNameStr && "rule" != collectionNameStr
        && "filter" != collectionNameStr && "output" != collectionNameStr
        && "schema" != collectionNameStr && "environment" != collectionNameStr)
    {
        std::cerr << "Invalid collection name: " << collectionNameStr << std::endl;
        return;
    }

    auto loadEntry =
        [&](decltype(*std::filesystem::directory_iterator(collectionPath, ec)) dirEntry)
        {
            // If error ignore entry and continue
            if (ec)
            {
                std::cerr << "Error reading " << dirEntry.path() << ": " << ec.message()
                        << std::endl;
                ec.clear();
                return;
            }

            if (dirEntry.is_regular_file(ec))
            {
                // If error ignore entry and continue
                if (ec)
                {
                    std::cerr << "Error reading " << dirEntry.path() << ": " << ec.message()
                            << std::endl;
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
                    std::cerr << "Error reading " << dirEntry.path() << ": " << e.what()
                            << std::endl;
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
        default: std::cerr << "Invalid action: " << actionStr << std::endl; break;
    }
}

} // namespace cmd
