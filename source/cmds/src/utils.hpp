#ifndef _CMD_SRC_APICLNT_ADAPTER_HPP
#define _CMD_SRC_APICLNT_ADAPTER_HPP

#include <exception>
#include <string>

#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>
#include <eMessages/eMessage.h>
#include <eMessages/engine.pb.h>
#include <base/json.hpp>

#include <cmds/apiclnt/client.hpp>

namespace cmd::utils
{

using wpResponse = base::utils::wazuhProtocol::WazuhResponse;
using wpRequest = base::utils::wazuhProtocol::WazuhRequest;

namespace apiAdapter
{
/**
 * @brief Converts an eMessage and command into a WazuhRequest.
 *
 * @tparam T Type of the eMessage (protobuf message).
 * @param command Command to set in the request.
 * @param origin Origin to set in the request.
 * @param eMessage eMessage to serialize into the request.
 * @return base::utils::wazuhProtocol::WazuhRequest WazuhRequest containing the serialized eMessage.
 * @throw ClientException if the serialization fails.
 */
template<typename T>
wpRequest toWazuhRequest(const std::string& command, const std::string& origin, const T& eMessage)
{
    // Check that T is derived from google::protobuf::Message
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");

    // Serialize the eMessage object into a JSON string
    const auto res = eMessage::eMessageToJson<T>(eMessage);

    // Check if serialization was successful
    if (std::holds_alternative<base::Error>(res))
    {
        const auto& error = std::string {"Error in serialization (client): "} + std::get<base::Error>(res).message;
        throw ClientException(error, ClientException::Type::PROTOBUFF_SERIALIZE_ERROR);
    }

    // Create a JSON object from the JSON string
    auto params = json::Json {std::get<std::string>(res).c_str()};

    // Create and return the WazuhRequest object
    return wpRequest::create(command, origin, params);
}

/**
 * @brief Parses the response data from a Wazuh API call into a protocol buffer (eMessage of type T).
 *
 * Throws a ClientException if the API call was unsuccessful or if there was an error parsing the response data into
 * the protocol buffer message.
 *
 * @tparam T Type of the expected protocol buffer message
 * @param wResponse The response from the Wazuh API call
 * @return T The protocol buffer message of type T parsed from the response data
 * @throw ClientException if the API call was unsuccessful or if there was an error parsing the response data into
 */
template<typename T>
T fromWazuhResponse(const wpResponse& wResponse)
{
    // The status code used in the protocol buffer message to indicate success
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
        // Throw an exception with the error message from the Wazuh response
        throw ClientException(wResponse.message().value_or("Unknown error in response"),
                              ClientException::Type::WRESPONSE_ERROR);
    }

    // Parse the response data into a protocol buffer message of type T
    const auto& data {wResponse.data()};
    const auto res {eMessage::eMessageFromJson<T>(data.str())};

    // Handle parsing errors (should never happen)
    if (std::holds_alternative<base::Error>(res))
    {
        // Return the error message from the parsing result
        const auto error {std::string {"Deserialization error: "} + std::get<base::Error>(res).message};
        throw ClientException(error, ClientException::Type::PROTOBUFF_DESERIALIZE_ERROR);
    }

    // Check for errors during parsing
    const auto& eMessage {std::get<T>(res)};

    // Check if the request was successful
    if (eMessage.status() != StatusCode::OK)
    {
        // Throw an exception with the error message from the parsing result
        throw ClientException(eMessage.has_error() ? eMessage.error() : "Unknown error in response",
                              ClientException::Type::EMESSAGE_ERROR);
    }

    // Return the parsed protocol buffer message
    return eMessage;
}
} // namespace apiAdapter
} // namespace cmd::utils
#endif // _CMD_SRC_APICLNT_ADAPTER_HPP
