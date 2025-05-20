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

struct Error
{
    httplib::Response res;
};

/**
 * @brief Return type for fallible operations with either the result or an error httplib::Response.
 *
 * @tparam Res The result type
 */
template<typename Res>
using ResOrErrorResp = std::variant<Res, Error>;

/**
 * @brief Check if the response is an error.
 *
 * @tparam Res The result type
 * @param res The result
 * @return true If the response is an httplib::Response error (Error)
 * @return false Otherwise
 */
template<typename Res>
inline bool isError(const ResOrErrorResp<Res>& res)
{
    return std::holds_alternative<Error>(res);
}

/**
 * @brief Get the Error object
 *
 * @tparam Res the result type
 * @param res The result
 * @return Error The error object with the httplib::Response
 */
template<typename Res>
Error getError(const ResOrErrorResp<Res>& res)
{
    return std::get<Error>(res);
}

/**
 * @brief Get the httplib::Response error
 *
 * @tparam Res The result type
 * @param res The result
 * @return httplib::Response error response
 */
template<typename Res>
httplib::Response getErrorResp(const ResOrErrorResp<Res>& res)
{
    return getError(res).res;
}

/**
 * @brief Get the result
 *
 * @tparam Res The result type
 * @param res The result
 * @return Res
 */
template<typename Res>
Res getRes(const ResOrErrorResp<Res>& res)
{
    return std::get<Res>(res);
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
 * @return ResOrErrorResp<Req> The request or an error with the response
 */
template<typename Req, typename Res>
ResOrErrorResp<Req> parseRequest(const httplib::Request& req)
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

template<typename Req, typename IHandler>
using ReqAndHandler = std::tuple<std::shared_ptr<IHandler>, Req>;

template<typename Req, typename Res, typename IHandler>
ResOrErrorResp<ReqAndHandler<Req, IHandler>> getReqAndHandler(const httplib::Request& req,
                                                              const std::weak_ptr<IHandler>& weakHandler)
{
    auto handler = weakHandler.lock();
    if (!handler)
    {
        return Error {internalErrorResponse<Res>("Error: Handler is not initialized")};
    }

    auto protoRequest = parseRequest<Req, Res>(req);
    if (isError(protoRequest))
    {
        return getError(protoRequest);
    }

    return ReqAndHandler<Req, IHandler> {handler, getRes(protoRequest)};
}

} // namespace api::adapter

#endif // _API_ADAPTER_HPP
