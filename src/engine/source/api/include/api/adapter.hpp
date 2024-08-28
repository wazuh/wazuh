#ifndef _API_ADAPTER_HPP
#define _API_ADAPTER_HPP

#include <type_traits>
#include <variant>

#include <base/utils/wazuhProtocol/wazuhRequest.hpp>
#include <base/utils/wazuhProtocol/wazuhResponse.hpp>
#include <eMessages/eMessage.h>
#include <eMessages/engine.pb.h>

namespace api::adapter
{

/**
 * @brief Return a WazuhResponse with de eMessage serialized or a WazuhResponse with the error if it fails
 * @tparam T
 * @param eMessage
 * @return base::utils::wazuhProtocol::WazuhResponse
 */
template<typename T>
base::utils::wazuhProtocol::WazuhResponse toWazuhResponse(const T& eMessage)
{
    // Check that T is derived from google::protobuf::Message
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");

    const auto res = eMessage::eMessageToJson<T>(eMessage);

    if (std::holds_alternative<base::Error>(res))
    {
        const auto& error = std::get<base::Error>(res);
        return base::utils::wazuhProtocol::WazuhResponse::internalError(error.message);
    }
    return base::utils::wazuhProtocol::WazuhResponse {json::Json {std::get<std::string>(res).c_str()}};
}

/**
 * @brief Return a variant with the parsed eMessage or a WazuhResponse with the error
 *
 * @tparam T Request type
 * @tparam U Response type
 * @param json
 * @return std::variant<base::utils::wazuhProtocol::WazuhResponse, T>
 */
template<typename T, typename U>
std::variant<base::utils::wazuhProtocol::WazuhResponse, T>
fromWazuhRequest(const base::utils::wazuhProtocol::WazuhRequest& wRequest)
{
    // Check that T and U are derived from google::protobuf::Message
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");
    static_assert(std::is_base_of<google::protobuf::Message, U>::value, "U must be a derived class of proto::Message");
    // Check that U has set_status and set_error functions
    static_assert(std::is_invocable_v<decltype(&U::set_status), U, ::com::wazuh::api::engine::ReturnStatus>,
                  "U must have set_status function");
    // static_assert(std::is_invocable_v<decltype(&U::set_error), U, const std::string&>,
    //               "U must have set_error function");

    const auto json = wRequest.getParameters().value_or(json::Json {"{}"}).str();

    auto res = eMessage::eMessageFromJson<T>(json);
    if (std::holds_alternative<base::Error>(res))
    {
        U eResponse;
        eResponse.set_status(::com::wazuh::api::engine::ReturnStatus::ERROR);
        eResponse.set_error(std::get<base::Error>(res).message);
        return toWazuhResponse<U>(eResponse);
    }

    return std::move(std::get<T>(res));
}

/**
 * @brief Return a WazuhResponse with the genericError in WazuhResponse
 *
 * @tparam T Response type
 * @param std::string Error message
 * @return std::variant<base::utils::wazuhProtocol::WazuhResponse, T>
 */
template<typename T>
base::utils::wazuhProtocol::WazuhResponse genericError(const std::string& message)
{
    // Check that T is derived from google::protobuf::Message
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");
    static_assert(std::is_invocable_v<decltype(&T::set_status), T, ::com::wazuh::api::engine::ReturnStatus>,
                  "T must have set_status function");

    T eResponse;
    eResponse.set_status(::com::wazuh::api::engine::ReturnStatus::ERROR);
    eResponse.set_error(message.data());
    return toWazuhResponse<T>(eResponse);
}

/**
 * @brief Return a WazuhResponse with the status OK in WazuhResponse
 *
 * @tparam T Response type
 * @return std::variant<base::utils::wazuhProtocol::WazuhResponse, T>
 */
template<typename T>
base::utils::wazuhProtocol::WazuhResponse genericSuccess()
{
    // Check that T is derived from google::protobuf::Message
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");
    static_assert(std::is_invocable_v<decltype(&T::set_status), T, ::com::wazuh::api::engine::ReturnStatus>,
                  "T must have set_status function");

    T eResponse;
    eResponse.set_status(::com::wazuh::api::engine::ReturnStatus::OK);
    return toWazuhResponse<T>(eResponse);
}

} // namespace api::adapter

#endif // _API_ADAPTER_HPP
