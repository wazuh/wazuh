#include <gtest/gtest.h>

#include <api/adapter/adapter.hpp>

#include "generic_request.pb.h"

using TestReq = com::wazuh::test::generic_request::Generic_Request;
using TestRes = com::wazuh::api::engine::GenericStatus_Response;

using namespace api::adapter;

TEST(ApiAdapterTest, Error)
{
    ASSERT_NO_THROW(Error {});
}

TEST(ApiAdapterTest, ResOrErrorResp)
{
    auto fnReq = []()
    {
        ResOrErrorResp<TestReq> {};
    };

    auto fnError = []()
    {
        ResOrErrorResp<Error> {};
    };

    ASSERT_NO_THROW(fnReq());
    ASSERT_NO_THROW(fnError());
}

TEST(ApiAdapterTest, IsError)
{
    auto res = ResOrErrorResp<TestReq> {};
    ASSERT_FALSE(isError(res));

    res = Error {};
    ASSERT_TRUE(isError(res));
}

TEST(ApiAdapterTest, GetErrorResp)
{
    auto res = ResOrErrorResp<TestReq> {};
    ASSERT_THROW(getErrorResp(res), std::bad_variant_access);

    res = Error {};
    ASSERT_NO_THROW(getErrorResp(res));
}

TEST(ApiAdapterTest, GetReq)
{
    TestReq req;
    auto res = ResOrErrorResp<TestReq> {req};
    ASSERT_NO_THROW(getRes(res));

    res = Error {};
    ASSERT_THROW(getRes(res), std::bad_variant_access);
}

TEST(ApiAdapterTest, InternalErrorResponse)
{
    httplib::Response res;
    TestRes protoRes;
    protoRes.set_status(eEngine::ReturnStatus::ERROR);
    protoRes.set_error("test");
    ASSERT_NO_THROW(res = internalErrorResponse<TestRes>("test"));
    ASSERT_EQ(res.status, httplib::StatusCode::InternalServerError_500);
    auto gotProtoRes = parseResponse<TestRes>(res);
    ASSERT_EQ(protoRes.status(), gotProtoRes.status());
    ASSERT_EQ(protoRes.error(), gotProtoRes.error());
}

TEST(ApiAdapterTest, UserResponse)
{
    httplib::Response res;
    TestRes protoRes;
    protoRes.set_status(eEngine::ReturnStatus::OK);
    ASSERT_NO_THROW(res = userResponse(protoRes));
    ASSERT_EQ(res.status, httplib::StatusCode::OK_200);
    auto gotProtoRes = parseResponse<TestRes>(res);
    ASSERT_EQ(protoRes.status(), gotProtoRes.status());
}

TEST(ApiAdapterTest, UserErrorResponse)
{
    httplib::Response res;
    TestRes protoRes;
    protoRes.set_status(eEngine::ReturnStatus::ERROR);
    protoRes.set_error("test");
    ASSERT_NO_THROW(res = userErrorResponse<TestRes>("test"));
    ASSERT_EQ(res.status, httplib::StatusCode::BadRequest_400);
    auto gotProtoRes = parseResponse<TestRes>(res);
    ASSERT_EQ(protoRes.status(), gotProtoRes.status());
    ASSERT_EQ(protoRes.error(), gotProtoRes.error());
}

TEST(ApiAdapterTest, ParseRequest)
{
    TestReq protoReq;
    protoReq.set_content("test");
    auto req = createRequest<TestReq>(protoReq);
    ResOrErrorResp<TestReq> res;
    auto fn = [&]()
    {
        res = parseRequest<TestReq, TestRes>(req);
    };
    ASSERT_NO_THROW(fn());
    ASSERT_FALSE(isError(res));
    auto gotReq = getRes(res);
    ASSERT_EQ(gotReq.content(), protoReq.content());

    req.body = "invalid";
    auto fn2 = [&]()
    {
        res = parseRequest<TestReq, TestRes>(req);
    };
    ASSERT_NO_THROW(fn2());
    ASSERT_TRUE(isError(res));
    auto error = getErrorResp(res);
    ASSERT_EQ(error.status, httplib::StatusCode::BadRequest_400);
    auto expectedProtoRes = eEngine::GenericStatus_Response {};
    expectedProtoRes.set_status(eEngine::ReturnStatus::ERROR);
    expectedProtoRes.set_error(
        "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\ninvalid\n^");
    auto gotProtoRes = parseResponse<TestRes>(error);
    ASSERT_EQ(gotProtoRes.status(), expectedProtoRes.status());
    ASSERT_EQ(gotProtoRes.error(), expectedProtoRes.error());
}

TEST(ApiAdapterTest, CreateRequest)
{
    TestReq protoReq;
    protoReq.set_content("test");
    httplib::Request req;
    ASSERT_NO_THROW(req = createRequest<TestReq>(protoReq));
    ASSERT_EQ(req.body, std::get<std::string>(eMessage::eMessageToJson<TestReq>(protoReq)));
    ASSERT_EQ(req.get_header_value("Content-Type"), "plain/text");
}

TEST(ApiAdapterTest, ParseResponse)
{
    httplib::Response res;
    TestRes protoRes;
    protoRes.set_status(eEngine::ReturnStatus::OK);
    ASSERT_NO_THROW(res = userResponse(protoRes));
    ASSERT_EQ(res.status, httplib::StatusCode::OK_200);
    auto gotProtoRes = parseResponse<TestRes>(res);
    ASSERT_EQ(protoRes.status(), gotProtoRes.status());
}
