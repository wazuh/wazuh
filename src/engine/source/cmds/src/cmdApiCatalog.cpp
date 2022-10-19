#include "cmds/cmdApiCatalog.hpp"
#include "apiclnt/connection.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <string>

#include <api/wazuhRequest.hpp>
#include <api/wazuhResponse.hpp>
#include <json/json.hpp>
#include <name.hpp>

namespace cmd
{
void catalog(const std::string& socketPath,
             const std::string& methodStr,
             const std::string& nameStr,
             const std::string& format,
             const std::string& content)
{
    api::WazuhRequest request;

    auto method = catalog_details::stringToMethod(methodStr.c_str());
    if (method == catalog_details::Method::ERROR_METHOD)
    {
        std::cerr << "Invalid method " << methodStr << std::endl;
        return;
    }

    // Prepare command and assert name is valid for the method
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

    switch (method)
    {
        case catalog_details::Method::LIST:
            if (name.parts().size() != 1 && name.parts().size() != 2)
            {
                std::cerr << fmt::format("Invalid name [{}] for method {}, name must be "
                                         "a valid <type>[/<item-id>]",
                                         nameStr,
                                         methodStr)
                          << std::endl;
                return;
            }
            if (!content.empty())
            {
                std::cerr << "Content not allowed for method " << methodStr << std::endl;
                return;
            }
            command = "get";
            break;
        case catalog_details::Method::GET:
            if (name.parts().size() != 3)
            {
                std::cerr << fmt::format("Invalid name [{}] for method {}, name must be "
                                         "a valid <type>/<item-id>/<ver>",
                                         nameStr,
                                         methodStr)
                          << std::endl;
                return;
            }
            if (!content.empty())
            {
                std::cerr << "Content not allowed for method " << methodStr << std::endl;
                return;
            }
            command = "get";
            break;
        case catalog_details::Method::UPDATE:
            if (name.parts().size() != 3)
            {
                std::cerr << fmt::format("Invalid name [{}] for method {}, name must be "
                                         "a valid <type>/<item-id>/<ver>",
                                         nameStr,
                                         methodStr)
                          << std::endl;
                return;
            }
            if (content.empty())
            {
                std::cerr << "Content required for method " << methodStr << std::endl;
                return;
            }
            command = "put";
            break;
        case catalog_details::Method::CREATE:
            if (name.parts().size() != 1)
            {
                std::cerr << fmt::format(
                    "Invalid name [{}] for method {}, name must be a valid <type>",
                    nameStr,
                    methodStr)
                          << std::endl;
                return;
            }
            if (content.empty())
            {
                std::cerr << "Content required for method " << methodStr << std::endl;
                return;
            }
            command = "post";
            break;
        case catalog_details::Method::DELETE:
            if (name.parts().size() != 3)
            {
                std::cerr << fmt::format("Invalid name [{}] for method {}, name must be "
                                         "a valid <type>/<item-id>/<ver>",
                                         nameStr,
                                         methodStr)
                          << std::endl;
                return;
            }
            if (!content.empty())
            {
                std::cerr << "Content not allowed for method " << methodStr << std::endl;
                return;
            }
            command = "delete";
            break;
        case catalog_details::Method::VALIDATE:
            if (name.parts().size() != 3)
            {
                std::cerr << fmt::format("Invalid name [{}] for method {}, name must be "
                                         "a valid <type>/<item-id>/<ver>",
                                         nameStr,
                                         methodStr)
                          << std::endl;
                return;
            }
            if (content.empty())
            {
                std::cerr << "Content required for method " << methodStr << std::endl;
                return;
            }
            command = "validate";
            break;
        default: break;
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
        responseStr = responseStr.data() + sizeof(int);
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
} // namespace cmd
