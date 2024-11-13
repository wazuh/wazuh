#ifndef _HTTPSRV_PROTOHELPERS_HPP
#define _HTTPSRV_PROTOHELPERS_HPP

#include <variant>

#include <google/protobuf/message.h>
#include <httplib.h>

#include <eMessages/engine.pb.h>

namespace httpsrv::proto
{
namespace eEngine
{
using namespace com::wazuh::api::engine;
}

using GenericResT = eEngine::GenericStatus_Response;

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
 * @brief Parse a request from a httplib request.
 *
 * @tparam Req The request type
 * @param req The httplib request
 * @return ReqOrError<Req> The request or an error with the response
 */
template<typename Req>
ReqOrError<Req> parseRequest(const httplib::Request& req)
{
    static_assert(std::is_base_of_v<google::protobuf::Message, Req>, "Request must be a protobuf message");
    Req request;
    if (!request.ParseFromString(req.body))
    {
        GenericResT protoRes;
        protoRes.set_status(eEngine::ReturnStatus::ERROR);
        protoRes.set_error("Failed to parse protobuff request");

        Error errRes;
        errRes.res.status = httplib::StatusCode::BadRequest_400;
        errRes.res.set_content(protoRes.SerializeAsString(), "application/octet-stream");

        return errRes;
    }

    return request;
}

/**
 * @brief Create a response from a protobuf message.
 *
 * @tparam Res The response type
 * @param res The response
 * @return httplib::Response The response object
 */
template<typename Res>
httplib::Response userResponse(const Res& res)
{
    static_assert(std::is_base_of_v<google::protobuf::Message, Res>, "Response must be a protobuf message");
    httplib::Response response;
    response.status = httplib::StatusCode::OK_200;
    response.set_content(res.SerializeAsString(), "application/octet-stream");
    return response;
}

/**
 * @brief Create a User Error Response object
 *
 * @param message The error message
 * @return httplib::Response
 */
inline httplib::Response userErrorResponse(const std::string& message)
{
    GenericResT protoRes;
    protoRes.set_status(eEngine::ReturnStatus::ERROR);
    protoRes.set_error(message);

    httplib::Response response;
    response.status = httplib::StatusCode::BadRequest_400;
    response.set_content(protoRes.SerializeAsString(), "application/octet-stream");

    return response;
}

/**
 * @brief Create an Internal Error Response object
 *
 * @param message The error message
 * @return httplib::Response
 */
inline httplib::Response internalErrorResponse(const std::string& message)
{
    GenericResT protoRes;
    protoRes.set_status(eEngine::ReturnStatus::ERROR);
    protoRes.set_error(message);

    httplib::Response response;
    response.status = httplib::StatusCode::InternalServerError_500;
    response.set_content(protoRes.SerializeAsString(), "application/octet-stream");

    return response;
}

} // namespace httpsrv::proto

#endif // _HTTPSRV_PROTOHELPERS_HPP
