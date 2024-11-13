#include <gtest/gtest.h>

#include <httpsrv/protoHelpers.hpp>

#include "generic_request.pb.h"

using TestReq = com::wazuh::test::generic_request::Generic_Request;

TEST(ProtoHelperTest, Error)
{
    ASSERT_NO_THROW(httpsrv::proto::Error {});
}

TEST(ProtoHelperTest, ReqOrError)
{
    auto fnReq = []()
    {
        httpsrv::proto::ReqOrError<TestReq> {};
    };

    auto fnError = []()
    {
        httpsrv::proto::ReqOrError<httpsrv::proto::Error> {};
    };

    ASSERT_NO_THROW(fnReq());
    ASSERT_NO_THROW(fnError());
}

TEST(ProtoHelperTest, IsError)
{
    auto res = httpsrv::proto::ReqOrError<TestReq> {};
    ASSERT_FALSE(httpsrv::proto::isError(res));

    res = httpsrv::proto::Error {};
    ASSERT_TRUE(httpsrv::proto::isError(res));
}

TEST(ProtoHelperTest, GetErrorResp)
{
    auto res = httpsrv::proto::ReqOrError<TestReq> {};
    ASSERT_THROW(httpsrv::proto::getErrorResp(res), std::bad_variant_access);

    res = httpsrv::proto::Error {};
    ASSERT_NO_THROW(httpsrv::proto::getErrorResp(res));
}

TEST(ProtoHelperTest, GetReq)
{
    TestReq req;
    auto res = httpsrv::proto::ReqOrError<TestReq> {req};
    ASSERT_NO_THROW(httpsrv::proto::getReq(res));

    res = httpsrv::proto::Error {};
    ASSERT_THROW(httpsrv::proto::getReq(res), std::bad_variant_access);
}

TEST(ProtoHelperTest, ParseRequest)
{
    httplib::Request req;
    TestReq protoReq;
    protoReq.set_content("test");
    req.body = protoReq.SerializeAsString();
    httpsrv::proto::ReqOrError<TestReq> res;
    ASSERT_NO_THROW(res = httpsrv::proto::parseRequest<TestReq>(req));
    ASSERT_FALSE(httpsrv::proto::isError(res));
    auto gotReq = httpsrv::proto::getReq(res);
    ASSERT_EQ(gotReq.content(), protoReq.content());

    req.body = "invalid";
    ASSERT_NO_THROW(res = httpsrv::proto::parseRequest<TestReq>(req));
    ASSERT_TRUE(httpsrv::proto::isError(res));
    auto error = httpsrv::proto::getErrorResp(res);
    ASSERT_EQ(error.status, httplib::StatusCode::BadRequest_400);
    auto expectedProtoRes = httpsrv::proto::eEngine::GenericStatus_Response {};
    expectedProtoRes.set_status(httpsrv::proto::eEngine::ReturnStatus::ERROR);
    expectedProtoRes.set_error("Failed to parse protobuff request");
    httpsrv::proto::GenericResT gotProtoRes;
    gotProtoRes.ParseFromString(error.body);
    ASSERT_EQ(gotProtoRes.status(), expectedProtoRes.status());
    ASSERT_EQ(gotProtoRes.error(), expectedProtoRes.error());
}

TEST(ProtoHelperTest, UserResponse)
{
    httplib::Response res;
    httpsrv::proto::GenericResT protoRes;
    protoRes.set_status(httpsrv::proto::eEngine::ReturnStatus::OK);
    ASSERT_NO_THROW(res = httpsrv::proto::userResponse(protoRes));
    ASSERT_EQ(res.status, httplib::StatusCode::OK_200);
    httpsrv::proto::GenericResT gotProtoRes;
    gotProtoRes.ParseFromString(res.body);
    ASSERT_EQ(protoRes.status(), gotProtoRes.status());
}

TEST(ProtoHelperTest, UserErrorResponse)
{
    httplib::Response res;
    httpsrv::proto::GenericResT protoRes;
    protoRes.set_status(httpsrv::proto::eEngine::ReturnStatus::ERROR);
    protoRes.set_error("test");
    ASSERT_NO_THROW(res = httpsrv::proto::userErrorResponse("test"));
    ASSERT_EQ(res.status, httplib::StatusCode::BadRequest_400);
    httpsrv::proto::GenericResT gotProtoRes;
    gotProtoRes.ParseFromString(res.body);
    ASSERT_EQ(protoRes.status(), gotProtoRes.status());
    ASSERT_EQ(protoRes.error(), gotProtoRes.error());
}

TEST(ProtoHelperTest, InternalErrorResponse)
{
    httplib::Response res;
    httpsrv::proto::GenericResT protoRes;
    protoRes.set_status(httpsrv::proto::eEngine::ReturnStatus::ERROR);
    protoRes.set_error("test");
    ASSERT_NO_THROW(res = httpsrv::proto::internalErrorResponse("test"));
    ASSERT_EQ(res.status, httplib::StatusCode::InternalServerError_500);
    httpsrv::proto::GenericResT gotProtoRes;
    gotProtoRes.ParseFromString(res.body);
    ASSERT_EQ(protoRes.status(), gotProtoRes.status());
    ASSERT_EQ(protoRes.error(), gotProtoRes.error());
}
