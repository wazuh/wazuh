// SPDX-License-Identifier: AGPL-3.0-or-later
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
    httpsrv::Response res;
    TestRes protoRes;
    protoRes.set_status(eEngine::ReturnStatus::ERROR);
    protoRes.set_error("test");
    ASSERT_NO_THROW(res = internalErrorResponse<TestRes>("test"));
    ASSERT_EQ(res.status, 500);
    auto gotProtoRes = parseResponse<TestRes>(res);
    ASSERT_EQ(protoRes.status(), gotProtoRes.status());
    ASSERT_EQ(protoRes.error(), gotProtoRes.error());
}

TEST(ApiAdapterTest, UserResponse)
{
    httpsrv::Response res;
    TestRes protoRes;
    protoRes.set_status(eEngine::ReturnStatus::OK);
    ASSERT_NO_THROW(res = userResponse(protoRes));
    ASSERT_EQ(res.status, 200);
    auto gotProtoRes = parseResponse<TestRes>(res);
    ASSERT_EQ(protoRes.status(), gotProtoRes.status());
}

TEST(ApiAdapterTest, UserErrorResponse)
{
    httpsrv::Response res;
    TestRes protoRes;
    protoRes.set_status(eEngine::ReturnStatus::ERROR);
    protoRes.set_error("test");
    ASSERT_NO_THROW(res = userErrorResponse<TestRes>("test"));
    ASSERT_EQ(res.status, 400);
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
    ASSERT_EQ(error.status, 400);
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
    httpsrv::Request req;
    ASSERT_NO_THROW(req = createRequest<TestReq>(protoReq));
    ASSERT_EQ(req.body, std::get<std::string>(eMessage::eMessageToJson<TestReq>(protoReq)));
    ASSERT_EQ(req.header("Content-Type"), "application/json");
}

TEST(ApiAdapterTest, ParseRequestReadsOnlyTheViewedBody)
{
    // The body is a view into the transport's buffer, not a terminated string: whatever follows it must not
    // be parsed.
    const auto json = std::get<std::string>(eMessage::eMessageToJson<TestReq>(
        []
        {
            TestReq protoReq;
            protoReq.set_content("test");
            return protoReq;
        }()));
    const auto buffer = std::make_shared<const std::string>(json + "TRAILING BYTES");
    httpsrv::Request req;
    req.method = httpsrv::Method::POST;
    req.body = std::string_view {*buffer}.substr(0, json.size());
    req.owner = buffer;

    const auto res = parseRequest<TestReq, TestRes>(req);
    ASSERT_FALSE(isError(res));
    EXPECT_EQ(getRes(res).content(), "test");
}

TEST(ApiAdapterTest, ResponsesAreLabelledJson)
{
    TestRes protoRes;
    protoRes.set_status(eEngine::ReturnStatus::OK);

    auto ok = userResponse<TestRes>(protoRes);
    EXPECT_EQ(ok.status, 200);
    EXPECT_EQ(ok.contentType, "application/json");

    auto userError = userErrorResponse<TestRes>("bad request");
    EXPECT_EQ(userError.status, 400);
    EXPECT_EQ(userError.contentType, "application/json");

    auto internalError = internalErrorResponse<TestRes>("internal");
    EXPECT_EQ(internalError.status, 500);
    EXPECT_EQ(internalError.contentType, "application/json");
}

TEST(ApiAdapterTest, ParseResponse)
{
    httpsrv::Response res;
    TestRes protoRes;
    protoRes.set_status(eEngine::ReturnStatus::OK);
    ASSERT_NO_THROW(res = userResponse(protoRes));
    ASSERT_EQ(res.status, 200);
    auto gotProtoRes = parseResponse<TestRes>(res);
    ASSERT_EQ(protoRes.status(), gotProtoRes.status());
}
