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

#include "component_test.hpp"
#include "curlWrapper.hpp"
#include "factoryRequestImplemetator.hpp"
#include "urlRequest.hpp"

class EchoServer
{
    public:
        EchoServer()
        {
            std::thread t([&]()
            {
                httplib::Server server;

                server.Get("/", [](const httplib::Request& /*req*/, httplib::Response& res) {
                    res.set_content("Hello World!", "text/json");
                });

                server.Post("/", [](const httplib::Request& req, httplib::Response& res) {
                    res.set_content(req.body, "text/json");
                });

                server.Put("/", [](const httplib::Request& req, httplib::Response& res) {
                    res.set_content(req.body, "text/json");
                });

                server.Delete(R"(/(\d+))", [](const httplib::Request& req, httplib::Response& res) {
                    res.set_content(req.matches[1], "text/json");
                });

                server.listen("localhost", 44441);
            });
            t.detach();
        }
};

EchoServer server;

void ComponentTestInterface::SetUp()
{ }

void ComponentTestInterface::TearDown()
{ }

TEST_F(ComponentTestInterface, GetHelloWorld)
{
    auto callbackComplete = false;
    HTTPRequest::instance().get(HttpURL("http://localhost:44441/"), [&](const std::string &result)
    {
        EXPECT_EQ(result, "Hello World!");
        callbackComplete = true;
    });

    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInterface, PostHelloWorld)
{
    auto callbackComplete = false;
    HTTPRequest::instance().post(HttpURL("http://localhost:44441/"), R"({"hello":"world"})"_json, [&](const std::string &result)
    {
        EXPECT_EQ(result, R"({"hello":"world"})");
        callbackComplete = true;
    });

    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInterface, PutHelloWorld)
{
    auto callbackComplete = false;
    HTTPRequest::instance().update(HttpURL("http://localhost:44441/"), R"({"hello":"world"})"_json, [&](const std::string &result)
    {
        EXPECT_EQ(result, R"({"hello":"world"})");
        callbackComplete = true;
    });

    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInterface, DeleteRandomID)
{
    auto random { std::to_string(std::rand()) };

    auto callbackComplete = false;
    HTTPRequest::instance().delete_(HttpURL("http://localhost:44441/"+random), [&](const std::string &result)
    {
        EXPECT_EQ(result, random);
        callbackComplete = true;
    });

    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInterface, DownloadFile)
{
    HTTPRequest::instance().download(HttpURL("http://localhost:44441/"), "./test.txt", [&](const std::string &result)
    {
        std::cout << result << std::endl;
    });

    std::ifstream file("./test.txt");
    std::string line;
    std::getline(file, line);
    EXPECT_EQ(line, "Hello World!");
}

TEST_F(ComponentTestInterface, DownloadFileError)
{
    auto callbackComplete = false;
    HTTPRequest::instance().download(HttpURL("http://localhost:44441/invalid_file"), "./test.txt", [&](const std::string &result)
    {
        EXPECT_EQ(result, "HTTP response code said error");
        callbackComplete = true;
    });

    EXPECT_TRUE(callbackComplete);
}

using wrapperType = cURLWrapper;
void ComponentTestInternalParameters::SetUp()
{ }

void ComponentTestInternalParameters::TearDown()
{ }

TEST_F(ComponentTestInternalParameters, DownloadFileErrorEmptyOutput)
{
    auto callbackComplete = false;
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("wazuh.com")
            .outputFile("")
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "Failed to open output file");
        callbackComplete = true;
    }
    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInternalParameters, DownloadFileEmptyInvalidUrl)
{
    auto callbackComplete = false;
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("")
            .outputFile("test.txt")
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "URL using bad/illegal format or missing URL");
        callbackComplete = true;
    }
    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInternalParameters, DownloadFileEmptyInvalidUrl2)
{
    auto callbackComplete = false;
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://")
            .outputFile("test.txt")
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "URL using bad/illegal format or missing URL");
        callbackComplete = true;
    }
    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInternalParameters, GetError)
{
    auto callbackComplete = false;
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://localhost:44441/invalid_file")
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        callbackComplete = true;
    }
    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInternalParameters, PostError)
{
    auto callbackComplete = false;
    try
    {
        PostRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://localhost:44441/invalid_file")
            .postData(R"({"hello":"world"})"_json)
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        callbackComplete = true;
    }
    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInternalParameters, PutError)
{
    auto callbackComplete = false;
    try
    {
        PutRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://localhost:44441/invalid_file")
            .postData(R"({"hello":"world"})"_json)
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        callbackComplete = true;
    }
    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInternalParameters, DeleteError)
{
    auto callbackComplete = false;
    try
    {
        DeleteRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .url("http://localhost:44441/invalid_file")
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        callbackComplete = true;
    }
    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInternalParameters, ExecuteGetNoUrl)
{
    auto callbackComplete = false;
    try
    {
        GetRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        callbackComplete = true;
    }
    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInternalParameters, ExecutePostNoUrl)
{
    auto callbackComplete = false;
    try
    {
        PostRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        callbackComplete = true;
    }
    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInternalParameters, ExecutePutNoUrl)
{
    auto callbackComplete = false;
    try
    {
        PutRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        callbackComplete = true;
    }
    EXPECT_TRUE(callbackComplete);
}

TEST_F(ComponentTestInternalParameters, ExecuteDeleteNoUrl)
{
    auto callbackComplete = false;
    try
    {
        DeleteRequest::builder(FactoryRequestWrapper<wrapperType>::create())
            .execute();
    }
    catch (const std::exception &ex)
    {
        EXPECT_EQ(std::string(ex.what()), "HTTP response code said error");
        callbackComplete = true;
    }
    EXPECT_TRUE(callbackComplete);
}

