#ifndef _API_ADAPTER_HPP
#define _API_ADAPTER_HPP

#include <variant>

#include <fmt/format.h>
#include <google/protobuf/message.h>
#include <httpsrv/server.hpp>

#include <eMessages/eMessage.h>
#include <eMessages/engine.pb.h>

namespace api::adapter
{
using RouteHandler = std::function<void(const httplib::Request&, httplib::Response&)>;
namespace eEngine = ::com::wazuh::api::engine;

/**
 * @brief Error type containing the response.
 *
 */
struct Error
{
    httplib::Response res;
};

/**
 * @brief Return type for requests or errors.
 *
 * @tparam Req The request type, must be a specialization of protobuf message.
 */
template<typename Req>
using ReqOrError = std::variant<Req, Error>;
template<typename Res>
using ResOrError = ReqOrError<Res>;

/**
 * @brief Get the Error Response object
 *
 * @tparam Res Result type
 * @param res The response
 * @return httplib::Response
 */
template<typename Res>
httplib::Response getError(const ResOrError<Res>& res)
{
    return std::get<Error>(res).res;
}

/**
 * @brief Get the result object
 *
 * @tparam Res Result type
 * @param res The result or error
 * @return Res
 */
template<typename Res>
Res getRes(const ResOrError<Res>& res)
{
    return std::get<Res>(res);
}

/**
 * @brief Check if the response is an error.
 *
 * @tparam Req The request type
 * @param res The response
 * @return true If the response is an error
 * @return false Otherwise
 */
template<typename Req>
inline bool isError(const ReqOrError<Req>& res)
{
    return std::holds_alternative<Error>(res);
}

/**
 * @brief Get the Error Response object
 *
 * @tparam Req Request type
 * @param res The response
 * @return httplib::Response
 */
template<typename Req>
httplib::Response getErrorResp(const ReqOrError<Req>& res)
{
    static_assert(std::is_base_of_v<google::protobuf::Message, Req>, "Request must be a protobuf message");
    return std::get<Error>(res).res;
}

/**
 * @brief Get the request object
 *
 * @tparam Req Request type
 * @param res The response
 * @return Req
 */
template<typename Req>
Req getReq(const ReqOrError<Req>& res)
{
    static_assert(std::is_base_of_v<google::protobuf::Message, Req>, "Request must be a protobuf message");
    return std::get<Req>(res);
}

/**
 * @brief Create an Internal Error Response object
 *
 * @tparam Res The response type
 * @param message The error message
 * @return httplib::Response
 */
template<typename Res>
inline httplib::Response internalErrorResponse(const std::string& message)
{
    Res protoRes;
    protoRes.set_status(eEngine::ReturnStatus::ERROR);
    protoRes.set_error(message);

    const auto result = eMessage::eMessageToJson<Res>(protoRes);
    if (std::holds_alternative<base::Error>(result))
    {
        const auto& error = std::get<base::Error>(result);
        protoRes.set_error(error.message);
    }

    httplib::Response response;
    response.status = httplib::StatusCode::InternalServerError_500;
    response.set_content(std::get<std::string>(result), "plain/text");

    return response;
}

/**
 * @brief Create a response from a protobuf message.
 *
 * @tparam Res The response type
 * @tparam Req The request type
 * @param res The response
 * @return httplib::Response The response object
 */
template<typename Res>
httplib::Response userResponse(const Res& res)
{
    static_assert(std::is_base_of_v<google::protobuf::Message, Res>, "Response must be a protobuf message");
    const auto result = eMessage::eMessageToJson<Res>(res);

    if (std::holds_alternative<base::Error>(result))
    {
        const auto& error = std::get<base::Error>(result);
        return internalErrorResponse<Res>(error.message);
    }

    httplib::Response response;
    response.status = httplib::StatusCode::OK_200;
    response.set_content(std::get<std::string>(result), "plain/text");
    return response;
}

/**
 * @brief Create a User Error Response object
 *
 * @tparam Res The response type
 * @param message The error message
 * @return httplib::Response
 */
template<typename Res>
inline httplib::Response userErrorResponse(const std::string& message)
{
    Res protoRes;
    protoRes.set_status(eEngine::ReturnStatus::ERROR);
    protoRes.set_error(message);

    const auto result = eMessage::eMessageToJson<Res>(protoRes);
    if (std::holds_alternative<base::Error>(result))
    {
        const auto& error = std::get<base::Error>(result);
        return internalErrorResponse<Res>(error.message);
    }

    httplib::Response response;
    response.status = httplib::StatusCode::BadRequest_400;
    response.set_content(std::get<std::string>(result), "plain/text");

    return response;
}

/**
 * @brief Parse a request from a httplib request.
 *
 * @tparam Req The request typeç
 * @tparam Res The response type
 * @param req The httplib request
 * @return ReqOrError<Req> The request or an error with the response
 */
template<typename Req, typename Res>
ReqOrError<Req> parseRequest(const httplib::Request& req)
{
    static_assert(std::is_base_of_v<google::protobuf::Message, Req>, "Request must be a protobuf message");
    if (!req.body.empty())
    {
        auto result = eMessage::eMessageFromJson<Req>(req.body);
        if (std::holds_alternative<base::Error>(result))
        {
            std::string message =
                fmt::format("Failed to parse protobuff json request: {}", std::get<base::Error>(result).message);
            return Error {userErrorResponse<Res>(message)};
        }

        return std::get<Req>(result);
    }

    return Req {};
}

/**
 * @brief Create a request from a protobuf message.
 *
 * @tparam Req The request type
 * @param req The request
 * @return httplib::Request The request object
 */
template<typename Req>
inline httplib::Request createRequest(const Req& req)
{
    static_assert(std::is_base_of_v<google::protobuf::Message, Req>, "Request must be a protobuf message");
    const auto result = eMessage::eMessageToJson<Req>(req);
    if (std::holds_alternative<base::Error>(result))
    {
        throw std::runtime_error {
            fmt::format("Failed to serialize request: {}", std::get<base::Error>(result).message)};
    }

    httplib::Request request;
    request.body = std::get<std::string>(result);
    request.set_header("Content-Type", "plain/text");

    return request;
}

/**
 * @brief Parse a response from a httplib response.
 *
 * @tparam Res The response type
 * @param res The httplib response
 * @return Res The response object
 */
template<typename Res>
inline Res parseResponse(const httplib::Response& res)
{
    static_assert(std::is_base_of_v<google::protobuf::Message, Res>, "Response must be a protobuf message");
    if (!res.body.empty())
    {
        auto result = eMessage::eMessageFromJson<Res>(res.body);
        if (std::holds_alternative<base::Error>(result))
        {
            throw std::runtime_error {std::get<base::Error>(result).message};
        }

        return std::get<Res>(result);
    }

    return Res {};
}

/**
 * @brief Get the Handler object from a weak pointer or return an error response.
 *
 * @tparam Res The response type
 * @tparam IHandler The handler type
 * @param weakHandler The weak handler
 * @return ResOrError<std::shared_ptr<IHandler>>
 */
template<typename Res, typename IHandler>
ResOrError<std::shared_ptr<IHandler>> getHandler(const std::weak_ptr<IHandler>& weakHandler)
{
    if (auto handler = weakHandler.lock())
    {
        return handler;
    }

    return Error {internalErrorResponse<Res>("API endpoint is not available")};
}

} // namespace api::adapter

#endif // _API_ADAPTER_HPP
