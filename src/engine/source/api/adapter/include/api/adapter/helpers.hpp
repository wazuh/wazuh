#ifndef API_ADAPTER_HELPERS_HPP
#define API_ADAPTER_HELPERS_HPP

#include <functional>
#include <optional>
#include <string_view>

#include <fmt/format.h>

#include <api/adapter/adapter.hpp>
#include <base/json.hpp>
#include <base/name.hpp>

namespace api::adapter::helpers
{
template<typename T>
using PropGetter = std::function<T()>;

template<typename Res, typename T>
ResOrErrorResp<T> tryGetProperty(bool exists, PropGetter<T> propGetter, std::string_view field, std::string_view prop)
{
    if (exists)
    {
        try
        {
            return propGetter();
        }
        catch (const std::exception& e)
        {
            return Error {userErrorResponse<Res>(fmt::format("Invalid {} {}: {}", field, prop, e.what()))};
        }
    }
    return Error {userErrorResponse<Res>(fmt::format("Missing /{}", field))};
}

inline base::RespOrError<json::Json>
getJsonFieldFromBody(const std::string& body, const char* fieldPath, const char* missingMessage)
{
    json::Json reqJson;
    try
    {
        reqJson = json::Json(body.c_str());
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Error parsing request body: {}", e.what())};
    }

    auto field = reqJson.getJson(fieldPath);
    if (!field.has_value())
    {
        return base::Error {missingMessage};
    }

    return field.value();
}

inline httplib::Response buildJsonContentResponse(const json::Json& content)
{
    json::Json responseBody;
    responseBody.setObject();
    responseBody.setString("OK", "/status");
    responseBody.set("/jsonContent", content);

    httplib::Response response;
    response.status = httplib::StatusCode::OK_200;
    response.set_content(responseBody.str(), "plain/text");
    return response;
}

} // namespace api::adapter::helpers

#endif // API_ADAPTER_HELPERS_HPP
