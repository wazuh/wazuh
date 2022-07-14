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

using deleterCurl = CustomDeleter<decltype(&curl_easy_cleanup), curl_easy_cleanup>;

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

        using deleterCurlStringList = CustomDeleter<decltype(&curl_slist_free_all), curl_slist_free_all>;
        std::unique_ptr<curl_slist, deleterCurlStringList> m_curlHeaders;
        std::string m_returnValue;

        std::string m_unixSocketPath;
        std::string m_url;
        std::string m_userAgent;
        std::string m_certificate;

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

        void execute()
        {
            if (m_curlHeaders)
            {
                curl_easy_setopt(m_curlHandle.get(), CURLOPT_HTTPHEADER, m_curlHeaders.get());
            }

            const auto result { curl_easy_perform(m_curlHandle.get()) };
            if (CURLE_OK != result)
            {
                throw std::runtime_error(curl_easy_strerror(result));
            }
        }

        std::string response() const { return m_returnValue; }

        T & unixSocketPath(const std::string &sock)
        {
            m_unixSocketPath = sock;
            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_UNIX_SOCKET_PATH,
                             m_unixSocketPath.empty() ? nullptr : m_unixSocketPath.c_str());

            return static_cast<T&>(*this);
        }

        T & url(const std::string &url)
        {
            m_url = url;
            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_URL,
                             m_url.c_str());

            return static_cast<T&>(*this);
        }

        T & userAgent(const std::string &userAgent)
        {
            m_userAgent = userAgent;
            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_USERAGENT,
                             m_userAgent.c_str());

            return static_cast<T&>(*this);
        }

        T & appendHeader(const std::string &header)
        {
            if (!m_curlHeaders)
            {
                m_curlHeaders.reset(curl_slist_append(m_curlHeaders.get(), header.c_str()));
            }
            else
            {
                curl_slist_append(m_curlHeaders.get(), header.c_str());
            }

            return static_cast<T&>(*this);
        }

        T & timeout(const int timeout)
        {
            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_TIMEOUT,
                             timeout);

            return static_cast<T&>(*this);
        }

        T & certificate(const std::string &cert)
        {
            m_certificate = cert;
            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_CAINFO,
                             m_certificate.c_str());

            return static_cast<T&>(*this);
        }
};

template <typename T>
class PostData
{
    private:
        std::string m_postDataString;
        const std::unique_ptr<CURL, deleterCurl> &m_curlHandleReference;
    public:
        PostData(const std::unique_ptr<CURL, deleterCurl> &curlHandle) : m_curlHandleReference { curlHandle }
        { }
        T & postData(const nlohmann::json &postData)
        {
            m_postDataString = postData.dump();

            curl_easy_setopt(m_curlHandleReference.get(),
                             CURLOPT_POSTFIELDS,
                             m_postDataString.c_str());

            curl_easy_setopt(m_curlHandleReference.get(),
                             CURLOPT_POSTFIELDSIZE,
                             m_postDataString.size());

            return static_cast<T&>(*this);
        }

};

class PostRequest final : public cURLRequest<PostRequest>, public PostData<PostRequest>
{
    public:
        PostRequest() : PostData<PostRequest>(cURLRequest<PostRequest>::m_curlHandle)
        {
            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_CUSTOMREQUEST,
                             CURL_METHOD_TYPE_MAP.at(CURL_POST).c_str());

        }
        // LCOV_EXCL_START
        virtual ~PostRequest() = default;
        // LCOV_EXCL_STOP
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

        GetRequest & outputFile(const std::string &outputFile)
        {
            m_fpHandle.reset(fopen(outputFile.c_str(), "wb"));

            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_WRITEFUNCTION,
                             NULL);

            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_WRITEDATA,
                             m_fpHandle.get());

            return *this;
        }
        // LCOV_EXCL_START
        virtual ~GetRequest() = default;
        // LCOV_EXCL_STOP
};

class PutRequest final : public cURLRequest<PutRequest>, public PostData<PutRequest>
{
    public:
        PutRequest() : PostData<PutRequest>(cURLRequest<PutRequest>::m_curlHandle)
        {
            curl_easy_setopt(m_curlHandle.get(),
                             CURLOPT_CUSTOMREQUEST,
                             CURL_METHOD_TYPE_MAP.at(CURL_PUT).c_str());

        }
        // LCOV_EXCL_START
        virtual ~PutRequest() = default;
        // LCOV_EXCL_STOP
};

class DeleteRequest final : public cURLRequest<DeleteRequest>
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

#endif // _CURLWRAPPER_HPP
