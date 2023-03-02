#ifndef _CMD_SRC_APICLNT_ADAPTER_HPP
#define _CMD_SRC_APICLNT_ADAPTER_HPP

#include <exception>
#include <string>

#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>
#include <eMessages/eMessage.h>
#include <eMessages/engine.pb.h>
#include <json/json.hpp>

#include "apiclnt/client.hpp"

namespace cmd::utils
{

using wpResponse = base::utils::wazuhProtocol::WazuhResponse;
using wpRequest = base::utils::wazuhProtocol::WazuhRequest;

namespace apiAdapter
{

/**
 * @brief Return a WazuhRequest with de eMessage serialized
 * @tparam T
 * @param eMessage eMessage to serialize in the request (parameter)
 * @param command Command to set in the request
 * @param origin Origin to set in the request
 * @return base::utils::wazuhProtocol::WazuhRequest
 */
template<typename T>
wpRequest toWazuhRequest(const std::string& command, const std::string& origin, const T& eMessage)
{
    // Check that T is derived from google::protobuf::Message
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");

    const auto res = eMessage::eMessageToJson<T>(eMessage);

    if (std::holds_alternative<base::Error>(res)) // Should never happen
    {
        const auto& error = std::get<base::Error>(res);
        throw std::runtime_error {error.message};
    }
    auto params = json::Json {std::get<std::string>(res).c_str()};
    return wpRequest::create(command, origin, params);
}

/**
 * @brief Parses the response data from a Wazuh API call into a variant containing either a T object or an error
 * message.
 *
 * If the protobuf  object its returned, it always has the status field set to OK and no error message.
 * @tparam T Type of the expected eMessage response (protobuf message)
 * @param wResponse The response from the Wazuh API call
 * @return std::variant<const T, std::string> A variant containing either a T object or an error message
 */
template<typename T>
std::variant<T, std::string> fromWazuhResponse(const wpResponse& wResponse)
{
    using StatusCode = ::com::wazuh::api::engine::ReturnStatus;

    // Ensure T is derived from google::protobuf::Message
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");

    // Ensure T has the required functions
    static_assert(std::is_invocable_v<decltype(&T::status), T>, "T must have a status function");
    static_assert(std::is_same_v<StatusCode, std::invoke_result_t<decltype(&T::status), T>>,
                  "T::status must return a GenericStatus_Response");
    static_assert(std::is_invocable_v<decltype(&T::has_error), T>, "T must have a has_error function");
    static_assert(std::is_same_v<bool, std::invoke_result_t<decltype(&T::has_error), T>>,
                  "T::has_error must return a bool");
    static_assert(std::is_invocable_v<decltype(&T::error), T>, "T must have an error function");
    static_assert(std::is_same_v<const std::string&, std::invoke_result_t<decltype(&T::error), T>>,
                  "T::error must return a string");

    // Check if the Wazuh API call was successful
    if (wResponse.error())
    {
        // Return an error message containing the response string
        return wResponse.message().value_or(std::string("Unknown error in response:") + wResponse.toString());
    }

    // Parse the response data into a protobuf object
    const auto& data {wResponse.data()};
    const auto res {eMessage::eMessageFromJson<T>(data.str())};

    // Handle parsing errors (should never happen)
    if (std::holds_alternative<base::Error>(res))
    {
        // Return the error message from the parsing result
        return std::get<base::Error>(res).message;
    }

    // Extract the protobuf object
    const auto& eMessage {std::get<T>(res)};

    // Check if the request was successful
    if (eMessage.status() != StatusCode::OK)
    {
        // Return an error message containing the eMessage error, or a generic message if no error message is available
        return eMessage.has_error() ? eMessage.error() : "Unknown error in response (no error message)";
    }

    // Return the protocol buffer object
    return std::move(eMessage);
}
} // namespace apiAdapter

/**
 * @brief Calls the Wazuh API and returns a variant containing either a U response object with the status field set to
 * OK and no error message, or an error message string if the call failed.
 *
 * The call can fail if the Wazuh API is not running, the socket path is wrong, the request is malformed, the response
 * is malformed, or the response contains an error.
 * @param socketPath Path to the Wazuh API socket
 * @tparam T Request eMessage type
 * @tparam U Response eMessage type
 * @param command Command to send to the Wazuh API
 * @param origin Origin to send to the Wazuh API
 * @param eMessage eMessage to send to the Wazuh API
 * @return std::variant<U, std::string> A variant containing either a U response object or an error message string
 */
template<typename T, typename U>
std::variant<U, std::string>
callWAPI(const std::string& socketPath, const std::string& command, const std::string& origin, const T& eMessage)
{

    // The assert is in the subfunction to avoid the compiler warning about unused function parameters
    try
    {
        const auto request {apiAdapter::toWazuhRequest(command, origin, eMessage)};
        apiclnt::Client client {socketPath};
        const auto response {client.send(request)};
        return apiAdapter::fromWazuhResponse<U>(response);
    }
    catch (const std::exception& e)
    {
        return e.what();
    }
}
} // namespace cmd::utils
#endif // _CMD_SRC_APICLNT_ADAPTER_HPP
