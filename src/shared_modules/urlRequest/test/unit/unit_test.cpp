/*
 * Wazuh urlRequest test component
 * Copyright (C) 2015, Wazuh Inc.
 * July 18, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "unit_test.hpp"

using namespace testing;

class RequestWrapper final: public IRequestImplementator
{
    public:
        RequestWrapper() = default;
        virtual ~RequestWrapper() = default;

        MOCK_METHOD(void, setOption, (const OPTION_REQUEST_TYPE optIndex, void *ptr), (override));
        MOCK_METHOD(void, setOption, (const OPTION_REQUEST_TYPE optIndex, const std::string &opt), (override));
        MOCK_METHOD(void, setOption, (const OPTION_REQUEST_TYPE optIndex, const long int opt), (override));
        MOCK_METHOD(void, execute, (), (override));
        MOCK_METHOD(const std::string, response, (), (override));
        MOCK_METHOD(void, appendHeader, (const std::string &header), (override));
};

void UrlRequestUnitTest::SetUp()
{ }

void UrlRequestUnitTest::TearDown()
{ }

constexpr OPTION_REQUEST_TYPE optCustomRequest { OPT_CUSTOMREQUEST };
constexpr OPTION_REQUEST_TYPE optUnixSocketPath { OPT_UNIX_SOCKET_PATH };
constexpr OPTION_REQUEST_TYPE optUrl { OPT_URL };
constexpr OPTION_REQUEST_TYPE optCainfo { OPT_CAINFO };
constexpr OPTION_REQUEST_TYPE optTimeout { OPT_TIMEOUT };
constexpr OPTION_REQUEST_TYPE optWriteData { OPT_WRITEDATA };
constexpr OPTION_REQUEST_TYPE optUserAgent { OPT_USERAGENT };
constexpr OPTION_REQUEST_TYPE optPostFields { OPT_POSTFIELDS };
constexpr OPTION_REQUEST_TYPE optWriteFunction { OPT_WRITEFUNCTION };
constexpr OPTION_REQUEST_TYPE optPostFieldSize { OPT_POSTFIELDSIZE };
constexpr long zero { 0 };

TEST_F(UrlRequestUnitTest, GetFileHttp)
{
    auto request { std::make_shared<RequestWrapper>() };

    EXPECT_CALL(*request, setOption(optUrl, "http://www.wazuh.com/")).Times(1);
    EXPECT_CALL(*request, setOption(optCustomRequest, "GET")).Times(1);
    EXPECT_CALL(*request, setOption(optWriteData, SafeMatcherCast<void*>(_))).Times(1);
    EXPECT_CALL(*request, setOption(optWriteFunction, zero)).Times(1);
    EXPECT_CALL(*request, execute()).Times(1);
    EXPECT_CALL(*request, appendHeader(_)).Times(0);


    GetRequest::builder(request)
    .url("http://www.wazuh.com/")
    .outputFile("/tmp/hello_world.html")
    .execute();
}

TEST_F(UrlRequestUnitTest, GetFileWithUnixSocket)
{
    auto request { std::make_shared<RequestWrapper>() };

    EXPECT_CALL(*request, setOption(optUnixSocketPath, "/tmp/wazuh-agent.sock")).Times(1);
    EXPECT_CALL(*request, setOption(optUrl, "http://www.wazuh.com/")).Times(1);
    EXPECT_CALL(*request, setOption(optCustomRequest, "GET")).Times(1);
    EXPECT_CALL(*request, setOption(optWriteData, SafeMatcherCast<void*>(_))).Times(1);
    EXPECT_CALL(*request, setOption(optWriteFunction, zero)).Times(1);
    EXPECT_CALL(*request, execute()).Times(1);
    EXPECT_CALL(*request, appendHeader(_)).Times(0);

    GetRequest::builder(request)
    .url("http://www.wazuh.com/")
    .unixSocketPath("/tmp/wazuh-agent.sock")
    .outputFile("/tmp/hello_world.html")
    .execute();
}

TEST_F(UrlRequestUnitTest, GetApiRequest)
{
    auto request { std::make_shared<RequestWrapper>() };

    EXPECT_CALL(*request, setOption(optUrl, "http://www.wazuh.com/")).Times(1);
    EXPECT_CALL(*request, setOption(optCustomRequest, "GET")).Times(1);
    EXPECT_CALL(*request, appendHeader("Content-Type: Application/json")).Times(1);
    EXPECT_CALL(*request, setOption(optUserAgent, "Wazuh-Agent/1.0")).Times(1);
    EXPECT_CALL(*request, setOption(optCainfo, "cert.ca")).Times(1);
    EXPECT_CALL(*request, setOption(optTimeout, 10)).Times(1);
    EXPECT_CALL(*request, execute()).Times(1);

    GetRequest::builder(request)
    .url("http://www.wazuh.com/")
    .appendHeader("Content-Type: Application/json")
    .userAgent("Wazuh-Agent/1.0")
    .certificate("cert.ca")
    .timeout(10)
    .execute();
}

TEST_F(UrlRequestUnitTest, PostApiRequest)
{
    auto request { std::make_shared<RequestWrapper>() };

    EXPECT_CALL(*request, setOption(optUrl, "http://www.wazuh.com/")).Times(1);
    EXPECT_CALL(*request, setOption(optCustomRequest, "POST")).Times(1);
    EXPECT_CALL(*request, appendHeader("Content-Type: Application/json")).Times(1);
    EXPECT_CALL(*request, setOption(optUserAgent, "Wazuh-Agent/1.0")).Times(1);
    EXPECT_CALL(*request, setOption(optCainfo, "cert.ca")).Times(1);
    EXPECT_CALL(*request, setOption(optTimeout, 10)).Times(1);
    EXPECT_CALL(*request, execute()).Times(1);

    PostRequest::builder(request)
    .url("http://www.wazuh.com/")
    .appendHeader("Content-Type: Application/json")
    .userAgent("Wazuh-Agent/1.0")
    .certificate("cert.ca")
    .timeout(10)
    .execute();
}

TEST_F(UrlRequestUnitTest, PostApiRequestWithPostFields)
{
    auto request { std::make_shared<RequestWrapper>() };

    EXPECT_CALL(*request, setOption(optUrl, "http://www.wazuh.com/")).Times(1);
    EXPECT_CALL(*request, setOption(optCustomRequest, "POST")).Times(1);
    EXPECT_CALL(*request, appendHeader("Content-Type: Application/json")).Times(1);
    EXPECT_CALL(*request, setOption(optUserAgent, "Wazuh-Agent/1.0")).Times(1);
    EXPECT_CALL(*request, setOption(optCainfo, "cert.ca")).Times(1);
    EXPECT_CALL(*request, setOption(optTimeout, 10)).Times(1);
    EXPECT_CALL(*request, setOption(optPostFields, R"({"name":"wazuh"})")).Times(1);
    EXPECT_CALL(*request, setOption(optPostFieldSize, std::string(R"({"name":"wazuh"})").length())).Times(1);
    EXPECT_CALL(*request, execute()).Times(1);

    PostRequest::builder(request)
    .url("http://www.wazuh.com/")
    .appendHeader("Content-Type: Application/json")
    .userAgent("Wazuh-Agent/1.0")
    .certificate("cert.ca")
    .timeout(10)
    .postData(R"({"name":"wazuh"})"_json)
    .execute();
}

TEST_F(UrlRequestUnitTest, PostApiRequestWithPostFieldsAndUnixSocket)
{
    auto request { std::make_shared<RequestWrapper>() };

    EXPECT_CALL(*request, setOption(optUnixSocketPath, "/tmp/wazuh-agent.sock")).Times(1);
    EXPECT_CALL(*request, setOption(optUrl, "http://www.wazuh.com/")).Times(1);
    EXPECT_CALL(*request, setOption(optCustomRequest, "POST")).Times(1);
    EXPECT_CALL(*request, appendHeader("Content-Type: Application/json")).Times(1);
    EXPECT_CALL(*request, setOption(optUserAgent, "Wazuh-Agent/1.0")).Times(1);
    EXPECT_CALL(*request, setOption(optCainfo, "cert.ca")).Times(1);
    EXPECT_CALL(*request, setOption(optTimeout, 10)).Times(1);
    EXPECT_CALL(*request, setOption(optPostFields, R"({"name":"wazuh"})")).Times(1);
    EXPECT_CALL(*request, setOption(optPostFieldSize, std::string(R"({"name":"wazuh"})").length())).Times(1);
    EXPECT_CALL(*request, execute()).Times(1);

    PostRequest::builder(request)
    .url("http://www.wazuh.com/")
    .appendHeader("Content-Type: Application/json")
    .userAgent("Wazuh-Agent/1.0")
    .certificate("cert.ca")
    .timeout(10)
    .postData(R"({"name":"wazuh"})"_json)
    .unixSocketPath("/tmp/wazuh-agent.sock")
    .execute();
}

TEST_F(UrlRequestUnitTest, PutApiRequest)
{
    auto request { std::make_shared<RequestWrapper>() };

    EXPECT_CALL(*request, setOption(optUrl, "http://www.wazuh.com/")).Times(1);
    EXPECT_CALL(*request, setOption(optCustomRequest, "PUT")).Times(1);
    EXPECT_CALL(*request, appendHeader("Content-Type: Application/json")).Times(1);
    EXPECT_CALL(*request, setOption(optUserAgent, "Wazuh-Agent/1.0")).Times(1);
    EXPECT_CALL(*request, setOption(optCainfo, "cert.ca")).Times(1);
    EXPECT_CALL(*request, setOption(optTimeout, 10)).Times(1);
    EXPECT_CALL(*request, execute()).Times(1);

    PutRequest::builder(request)
    .url("http://www.wazuh.com/")
    .appendHeader("Content-Type: Application/json")
    .userAgent("Wazuh-Agent/1.0")
    .certificate("cert.ca")
    .timeout(10)
    .execute();
}

TEST_F(UrlRequestUnitTest, DeleteApiRequest)
{
    auto request { std::make_shared<RequestWrapper>() };

    EXPECT_CALL(*request, setOption(optUrl, "http://www.wazuh.com/")).Times(1);
    EXPECT_CALL(*request, setOption(optCustomRequest, "DELETE")).Times(1);
    EXPECT_CALL(*request, appendHeader("Content-Type: Application/json")).Times(1);
    EXPECT_CALL(*request, setOption(optUserAgent, "Wazuh-Agent/1.0")).Times(1);
    EXPECT_CALL(*request, setOption(optCainfo, "cert.ca")).Times(1);
    EXPECT_CALL(*request, setOption(optTimeout, 10)).Times(1);
    EXPECT_CALL(*request, execute()).Times(1);

    DeleteRequest::builder(request)
    .url("http://www.wazuh.com/")
    .appendHeader("Content-Type: Application/json")
    .userAgent("Wazuh-Agent/1.0")
    .certificate("cert.ca")
    .timeout(10)
    .execute();
}

TEST_F(UrlRequestUnitTest, BadConstructorDelete)
{
    EXPECT_ANY_THROW(
    {
        DeleteRequest::builder(nullptr)
        .url("http://www.wazuh.com/")
        .appendHeader("Content-Type: Application/json")
        .userAgent("Wazuh-Agent/1.0")
        .certificate("cert.ca")
        .timeout(10)
        .execute();
    });
}

TEST_F(UrlRequestUnitTest, BadConstructorGet)
{
    EXPECT_ANY_THROW(
    {
        GetRequest::builder(nullptr)
        .url("http://www.wazuh.com/")
        .appendHeader("Content-Type: Application/json")
        .userAgent("Wazuh-Agent/1.0")
        .certificate("cert.ca")
        .timeout(10)
        .execute();
    });
}

TEST_F(UrlRequestUnitTest, BadConstructorPost)
{
    EXPECT_ANY_THROW(
    {
        PostRequest::builder(nullptr)
        .url("http://www.wazuh.com/")
        .appendHeader("Content-Type: Application/json")
        .userAgent("Wazuh-Agent/1.0")
        .certificate("cert.ca")
        .timeout(10)
        .execute();
    });
}

TEST_F(UrlRequestUnitTest, BadConstructorPut)
{
    EXPECT_ANY_THROW(
    {
        PutRequest::builder(nullptr)
        .url("http://www.wazuh.com/")
        .appendHeader("Content-Type: Application/json")
        .userAgent("Wazuh-Agent/1.0")
        .certificate("cert.ca")
        .timeout(10)
        .execute();
    });
}
