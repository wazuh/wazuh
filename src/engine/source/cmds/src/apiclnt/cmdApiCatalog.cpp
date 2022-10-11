#include "cmds/apiclnt/cmdApiCatalog.hpp"
#include "apiclnt/connection.hpp"

#include <algorithm>
#include <cctype>
#include <string>

#include <api/wazuhRequest.hpp>
#include <json/json.hpp>

namespace cmd::apiclnt
{
void catalog(const std::string& socketPath,
             const std::string& methodStr,
             const std::string& uriStr,
             const std::string& format,
             const std::string& content)
{
    api::WazuhRequest request;

    auto method = stringToMethod(methodStr.c_str());
    Uri uri;
    json::Json params;
    params.setObject();
    params.setString(format, "/format");
    switch (method)
    {
        case Method::DELETE:
        case Method::GET:
        {
            uri = Uri(uriStr);
            if (uri.size() < 1 || uri.size() > 2)
            {
                throw std::runtime_error("Invalid URI");
            }
            auto command = methodStr + "_" + uri[0];
            std::transform(command.begin(),
                           command.end(),
                           command.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            if (uri.size() == 2)
            {
                params.setString(uri[1], "/name");
                request = api::WazuhRequest::create(command, params);
            }
            else
            {
                request = api::WazuhRequest::create(command, {});
            }
        }
        break;
        case Method::POST:
        {
            uri = Uri(uriStr);
            if (uri.size() != 1)
            {
                throw std::runtime_error("Invalid URI");
            }
            auto command = methodStr + "_" + uri[0];
            std::transform(command.begin(),
                           command.end(),
                           command.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            params.setString(content, "/content");
            request = api::WazuhRequest::create(command, params);
        }
        break;
        case Method::PUT:
        {
            uri = Uri(uriStr);
            if (uri.size() != 2)
            {
                throw std::runtime_error("Invalid URI");
            }
            auto command = methodStr + "_" + uri[0];
            std::transform(command.begin(),
                           command.end(),
                           command.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            params.setString(uri[1], "/name");
            params.setString(content, "/content");
            request = api::WazuhRequest::create(command, params);
        }
        break;
        default: throw std::runtime_error("Invalid method");
    }
    if (!request.isValid())
    {
        throw std::runtime_error("Invalid request");
    }
    auto requestStr = request.toStr();
    auto response = connection(socketPath, requestStr);
}
} // namespace cmd::apiclnt
