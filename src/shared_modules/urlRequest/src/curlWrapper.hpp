/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#ifndef _CURLWRAPPER_HPP
#define _CURLWRAPPER_HPP

#include <functional>
#include <map>
#include <memory>
#include <string>
#include "builder.hpp"
#include "curl.h"
#include "customDeleter.hpp"
#include "json.hpp"
#include "singleton.hpp"


enum CURL_RETURN_CONTENT_TYPE
{
    CURL_RETURN_TYPE_NULL,
    CURL_JSON
};

static const std::map<CURL_RETURN_CONTENT_TYPE, std::string> CURL_RETURN_CONTENT_TYPE_MAP =
{
    {CURL_RETURN_TYPE_NULL, ""},
    {CURL_JSON, "application/json"}
};

enum CURL_METHOD_TYPE
{
    CURL_GET,
    CURL_POST,
    CURL_PUT,
    CURL_DELETE
};

static const std::map<CURL_METHOD_TYPE, std::string> CURL_METHOD_TYPE_MAP =
{
    {CURL_GET, "GET"},
    {CURL_POST, "POST"},
    {CURL_PUT, "PUT"},
    {CURL_DELETE, "DELETE"}
};


template <typename T>
class cURLRequest : public Utils::Builder<T>
{
    private:
        static size_t cURLcallback(char* data, size_t size, size_t nmemb, void* userdata)
        {
            const auto str { reinterpret_cast<std::string*>(userdata) };
            str->append(data, size * nmemb);
            return size * nmemb;
        }

        using deleterCurl = CustomDeleter<decltype(&curl_easy_cleanup), curl_easy_cleanup>;
        std::string m_returnValue;
        std::function <void(const std::string&)> m_callback;

    protected:
        const std::unique_ptr<CURL, deleterCurl> m_curlHandle;

    public:
        cURLRequest() : m_curlHandle { curl_easy_init() }
        {
            if (!m_curlHandle)
            {
                throw std::runtime_error("cURL initialization failed");
            }

            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_WRITEFUNCTION,
                             cURLcallback);

            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_WRITEDATA,
                             &m_returnValue);
        }
        // LCOV_EXCL_START
        virtual ~cURLRequest() = default;
        // LCOV_EXCL_STOP
        void execute();
        std::string response() const { return m_returnValue; }
        T & unixSocketPath(const std::string &sock);
        T & url(const std::string &url);
        T & userAgent(const std::string &userAgent);
};

class PostRequest : public cURLRequest<PostRequest>
{
    public:
        PostRequest()
        {
            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_CUSTOMREQUEST,
                             CURL_METHOD_TYPE_MAP.at(CURL_POST).c_str());
        }
        // LCOV_EXCL_START
        virtual ~PostRequest() = default;
        // LCOV_EXCL_STOP
        template <typename T>
        PostRequest & postData(const nlohmann::json &postData);
};

class GetRequest final : public cURLRequest<GetRequest>
{
    using deleterFP = CustomDeleter<decltype(&fclose), fclose>;

    protected:
        std::unique_ptr<FILE, deleterFP> m_fpHandle;

    public:
        GetRequest()
        {
            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_CUSTOMREQUEST,
                             CURL_METHOD_TYPE_MAP.at(CURL_GET).c_str());
        }

        GetRequest & outputFile(const std::string &outputFile);
        // LCOV_EXCL_START
        virtual ~GetRequest() = default;
        // LCOV_EXCL_STOP
};

class DeleteRequest final : public PostRequest
{
    public:
        DeleteRequest()
        {
            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_CUSTOMREQUEST,
                             CURL_METHOD_TYPE_MAP.at(CURL_DELETE).c_str());
        }
        // LCOV_EXCL_START
        virtual ~DeleteRequest() = default;
        // LCOV_EXCL_STOP
};

class PutRequest final : public PostRequest
{
    public:
        PutRequest()
        {
            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_CUSTOMREQUEST,
                             CURL_METHOD_TYPE_MAP.at(CURL_DELETE).c_str());
        }
        // LCOV_EXCL_START
        virtual ~PutRequest() = default;
        // LCOV_EXCL_STOP
};

#endif // _CURLWRAPPER_HPP
