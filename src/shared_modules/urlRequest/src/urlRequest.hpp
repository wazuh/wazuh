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
#include "IRequestImplementator.hpp"
#include "builder.hpp"
#include "customDeleter.hpp"
#include "json.hpp"

enum METHOD_TYPE
{
    METHOD_GET,
    METHOD_POST,
    METHOD_PUT,
    METHOD_DELETE
};

static const std::map<METHOD_TYPE, std::string> METHOD_TYPE_MAP =
{
    {METHOD_GET, "GET"},
    {METHOD_POST, "POST"},
    {METHOD_PUT, "PUT"},
    {METHOD_DELETE, "DELETE"}
};

template <typename T>
class cURLRequest : public Utils::Builder<T, std::shared_ptr<IRequestImplementator>>
{
    private:
        std::string m_unixSocketPath;
        std::string m_url;
        std::string m_userAgent;
        std::string m_certificate;

    protected:
        std::shared_ptr<IRequestImplementator> m_requestImplementator;
        cURLRequest() = default;

        explicit cURLRequest(std::shared_ptr<IRequestImplementator> requestImplementator)
        : m_requestImplementator { requestImplementator }
        {
            if (!m_requestImplementator)
            {
                throw std::runtime_error("Request url initialization failed");
            }
        };

    public:

        // LCOV_EXCL_START
        virtual ~cURLRequest() = default;
        // LCOV_EXCL_STOP

        void execute()
        {
            m_requestImplementator->execute();
        }

        inline const std::string response() const
        {
            return m_requestImplementator->response();
        }

        T & unixSocketPath(const std::string &sock)
        {
            m_unixSocketPath = sock;
            m_requestImplementator->setOption(OPT_UNIX_SOCKET_PATH,
                                              m_unixSocketPath);

            return static_cast<T&>(*this);
        }

        T & url(const std::string &url)
        {
            m_url = url;
            m_requestImplementator->setOption(OPT_URL,
                                              m_url);

            return static_cast<T&>(*this);
        }

        T & userAgent(const std::string &userAgent)
        {
            m_userAgent = userAgent;
            m_requestImplementator->setOption(OPT_USERAGENT,
                                              m_userAgent);

            return static_cast<T&>(*this);
        }

        T & appendHeader(const std::string &header)
        {
            m_requestImplementator->appendHeader(header);
            return static_cast<T&>(*this);
        }

        T & timeout(const int timeout)
        {
            m_requestImplementator->setOption(OPT_TIMEOUT,
                                              timeout);

            return static_cast<T&>(*this);
        }

        T & certificate(const std::string &cert)
        {
            m_certificate = cert;
            m_requestImplementator->setOption(OPT_CAINFO,
                                              m_certificate);

            return static_cast<T&>(*this);
        }
};

template <typename T>
class PostData
{
    private:
        std::string m_postDataString;
        std::shared_ptr<IRequestImplementator> m_handleReference;
    public:
        PostData(std::shared_ptr<IRequestImplementator> handle)
        : m_handleReference { handle }
        { }

        T & postData(const nlohmann::json &postData)
        {
            m_postDataString = postData.dump();

            m_handleReference->setOption(OPT_POSTFIELDS,
                                         m_postDataString);

            m_handleReference->setOption(OPT_POSTFIELDSIZE,
                                         m_postDataString.size());

            return static_cast<T&>(*this);
        }

};

class PostRequest final : public cURLRequest<PostRequest>, public PostData<PostRequest>
{
    public:
        explicit PostRequest(std::shared_ptr<IRequestImplementator> requestImplementator)
        : cURLRequest<PostRequest>(requestImplementator), PostData<PostRequest>(requestImplementator)
        {
            cURLRequest<PostRequest>::m_requestImplementator->setOption(OPT_CUSTOMREQUEST,
                                                                        METHOD_TYPE_MAP.at(METHOD_POST));

        }
        // LCOV_EXCL_START
        virtual ~PostRequest() = default;
        // LCOV_EXCL_STOP
 };

class PutRequest final : public cURLRequest<PutRequest>, public PostData<PutRequest>
{
    public:
        explicit PutRequest(std::shared_ptr<IRequestImplementator> requestImplementator)
        : cURLRequest<PutRequest>(requestImplementator), PostData<PutRequest>(requestImplementator)
        {
            cURLRequest<PutRequest>::m_requestImplementator->setOption(OPT_CUSTOMREQUEST,
                                                                       METHOD_TYPE_MAP.at(METHOD_PUT));

        }

        // LCOV_EXCL_START
        virtual ~PutRequest() = default;
        // LCOV_EXCL_STOP
};

class GetRequest final : public cURLRequest<GetRequest>
{
    using deleterFP = CustomDeleter<decltype(&fclose), fclose>;

    protected:
        std::unique_ptr<FILE, deleterFP> m_fpHandle;

    public:

        explicit GetRequest(std::shared_ptr<IRequestImplementator> requestImplementator)
        : cURLRequest<GetRequest>(requestImplementator)
        {
            m_requestImplementator->setOption(OPT_CUSTOMREQUEST,
                                              METHOD_TYPE_MAP.at(METHOD_GET).c_str());
        }

        GetRequest & outputFile(const std::string &outputFile)
        {
            m_fpHandle.reset(fopen(outputFile.c_str(), "wb"));

            if (!m_fpHandle)
            {
                throw std::runtime_error("Failed to open output file");
            }

            m_requestImplementator->setOption(OPT_WRITEDATA,
                                              m_fpHandle.get());

            m_requestImplementator->setOption(OPT_WRITEFUNCTION,
                                              static_cast<long>(0));

            return *this;
        }
        // LCOV_EXCL_START
        virtual ~GetRequest() = default;
        // LCOV_EXCL_STOP
};

class DeleteRequest final : public cURLRequest<DeleteRequest>
{
    public:
        explicit DeleteRequest(std::shared_ptr<IRequestImplementator> requestImplementator)
        : cURLRequest<DeleteRequest>(requestImplementator)
        {
            m_requestImplementator->setOption(OPT_CUSTOMREQUEST,
                                              METHOD_TYPE_MAP.at(METHOD_DELETE).c_str());

        }

        // LCOV_EXCL_START
        virtual ~DeleteRequest() = default;
        // LCOV_EXCL_STOP
};

#endif // _CURLWRAPPER_HPP

