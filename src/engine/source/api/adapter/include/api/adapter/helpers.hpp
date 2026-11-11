// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef API_ADAPTER_HELPERS_HPP
#define API_ADAPTER_HELPERS_HPP

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include <fmt/format.h>

#include <api/adapter/adapter.hpp>
#include <base/json.hpp>
#include <base/name.hpp>
#include <base/utils/stringUtils.hpp>

namespace api::adapter::helpers
{
/// Longest piece of request input an error message repeats back.
inline constexpr std::size_t MAX_ECHOED_INPUT_LENGTH = base::utils::string::MAX_ECHOED_INPUT_LENGTH;

/**
 * @brief Bound a request value before an error message repeats it back.
 *
 * @param value The value taken from the request.
 * @param maxLength Longest text kept (MAX_ECHOED_INPUT_LENGTH by default).
 * @return std::string The value itself when it fits, else its first characters followed by "... (<n> bytes)".
 */
inline std::string truncateForMessage(std::string_view value, std::size_t maxLength = MAX_ECHOED_INPUT_LENGTH)
{
    return base::utils::string::truncateForMessage(value, maxLength);
}

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
            // "Invalid policy name: …", but "Invalid name: …" (not "Invalid name name") when both are the same
            const auto subject = (field == prop) ? std::string(field) : fmt::format("{} {}", field, prop);
            return Error {userErrorResponse<Res>(fmt::format("Invalid {}: {}", subject, e.what()))};
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
    response.set_content(responseBody.str(), "application/json");
    return response;
}

} // namespace api::adapter::helpers

#endif // API_ADAPTER_HELPERS_HPP
