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

#include "IRequestImplementator.hpp"
#include "builder.hpp"
#include "customDeleter.hpp"
#include "fsWrapper.hpp"
#include "json.hpp"
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#define NOT_USED -1

enum METHOD_TYPE
{
    METHOD_GET,
    METHOD_POST,
    METHOD_PUT,
    METHOD_DELETE
};

static const std::map<METHOD_TYPE, std::string> METHOD_TYPE_MAP = {
    {METHOD_GET, "GET"}, {METHOD_POST, "POST"}, {METHOD_PUT, "PUT"}, {METHOD_DELETE, "DELETE"}};

static const std::vector<std::string> DEFAULT_CAINFO_PATHS = {
    "/etc/ssl/certs/ca-certificates.crt",     // Debian systems
    "/etc/pki/tls/certs/ca-bundle.crt",       // Redhat and Mandriva
    "/usr/share/ssl/certs/ca-bundle.crt",     // RedHat
    "/usr/local/share/certs/ca-root-nss.crt", // FreeBSD
    "/etc/ssl/cert.pem",                      // OpenBSD, FreeBSD, MacOS
};

/**
 * @brief This class is a wrapper for curl library.
 * It provides a simple interface to perform HTTP requests.
 *
 * @tparam T Type of the response body.
 */
template<typename T, typename TFileSystem = FsWrapper>
class cURLRequest
    : public Utils::Builder<T, std::shared_ptr<IRequestImplementator>>
    , public TFileSystem
{
    using deleterFP = CustomDeleter<decltype(&fclose), fclose>;

private:
    std::string m_unixSocketPath;
    std::string m_url;
    std::string m_userAgent;
    std::string m_certificate;
    std::unique_ptr<FILE, deleterFP> m_fpHandle;

protected:
    /**
     * @brief This variable is used to store the request implementator.
     */
    std::shared_ptr<IRequestImplementator> m_requestImplementator;
    cURLRequest() = default;

    /**
     * @brief Create a cURLRequest object.
     *
     * @param requestImplementator Pointer to the request implementator.
     */
    explicit cURLRequest(std::shared_ptr<IRequestImplementator> requestImplementator)
        : m_requestImplementator {requestImplementator}
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

    /**
     * @brief This method executes a request.
     */
    void execute()
    {
        m_requestImplementator->execute();
    }

    /**
     * @brief This method returns the response.
     */
    inline const std::string response() const
    {
        return m_requestImplementator->response();
    }

    /**
     * @brief This method sets the unix socket path and returns a reference to the object.
     * @param sock Unix socket path.
     * @return A reference to the object.
     */
    T& unixSocketPath(const std::string& sock)
    {
        m_unixSocketPath = sock;
        m_requestImplementator->setOption(OPT_UNIX_SOCKET_PATH, m_unixSocketPath);

        return static_cast<T&>(*this);
    }

    /**
     * @brief This method sets the URL and returns a reference to the object.
     * @param url Url to set.
     * @return A reference to the object.
     */
    T& url(const std::string& url)
    {
        m_url = url;
        m_requestImplementator->setOption(OPT_URL, m_url);

        // If the URL starts with "https", we need set CAINFO option.
        // Otherwise, we need to set the SSL_VERIFYPEER option to false.

        if (m_url.find("https") == 0)
        {
            // If the certificate is not set, we try to find it in the default paths.
            if (m_certificate.empty())
            {
                for (const auto& path : DEFAULT_CAINFO_PATHS)
                {
                    if (TFileSystem::exists(path))
                    {
                        certificate(path);
                        break;
                    }
                }
            }

            if (m_certificate.empty())
            {
                m_requestImplementator->setOption(OPT_VERIFYPEER, 0L);
            }
        }

        return static_cast<T&>(*this);
    }

    /**
     * @brief This method sets the user agent and returns a reference to the object.
     * @param userAgent User agent to set.
     * @return A reference to the object.
     */
    T& userAgent(const std::string& userAgent)
    {
        m_userAgent = userAgent;
        m_requestImplementator->setOption(OPT_USERAGENT, m_userAgent);

        return static_cast<T&>(*this);
    }

    /**
     * @brief This method appends a header and returns a reference to the object.
     * @param header Header to append.
     * @return A reference to the object.
     */
    T& appendHeader(const std::string& header)
    {
        m_requestImplementator->appendHeader(header);
        return static_cast<T&>(*this);
    }

    /**
     * @brief This method sets the timeout and returns a reference to the object.
     * @param timeout Timeout to set.
     * @return A reference to the object.
     */
    T& timeout(const int timeout)
    {
        m_requestImplementator->setOption(OPT_TIMEOUT, timeout);

        return static_cast<T&>(*this);
    }

    /**
     * @brief This method sets the certificate and returns a reference to the object.
     * @param cert Certificate to set.
     * @return A reference to the object.
     */
    T& certificate(const std::string& cert)
    {
        m_certificate = cert;
        m_requestImplementator->setOption(OPT_CAINFO, m_certificate);
        m_requestImplementator->setOption(OPT_VERIFYPEER, 1L);

        return static_cast<T&>(*this);
    }

    /**
     * @brief This method create a file with the path given and returns a reference to the object.
     * @param outputFile Output file path.
     * @return A reference to the object.
     */
    T& outputFile(const std::string& outputFile)
    {
        if (!outputFile.empty())
        {
            m_fpHandle.reset(fopen(outputFile.c_str(), "wb"));

            if (!m_fpHandle)
            {
                throw std::runtime_error("Failed to open output file");
            }

            m_requestImplementator->setOption(OPT_WRITEDATA, m_fpHandle.get());

            m_requestImplementator->setOption(OPT_WRITEFUNCTION, static_cast<long>(0));
        }

        return static_cast<T&>(*this);
    }
};

/**
 * @brief This class defines generic methods for HTTP POST requests.
 *
 * @tparam T Type of the response body.
 */
template<typename T>
class PostData
{
private:
    std::string m_postDataString;
    std::shared_ptr<IRequestImplementator> m_handleReference;

public:
    /**
     * @brief This constructor initializes the PostData object.
     * @param handle Shared pointer to the IRequestImplementator.
     */
    explicit PostData(std::shared_ptr<IRequestImplementator> handle)
        : m_handleReference {handle}
    {
    }

    /**
     * @brief This method sets the post data and returns a reference to the object.
     * @param postData Post data to set.
     * @return A reference to the object.
     */
    T& postData(const nlohmann::json& postData)
    {
        m_postDataString = postData.dump();

        m_handleReference->setOption(OPT_POSTFIELDS, m_postDataString);

        m_handleReference->setOption(OPT_POSTFIELDSIZE, m_postDataString.size());

        return static_cast<T&>(*this);
    }
};

/**
 * @brief This class is a wrapper for curl library. It provides a simple interface to perform HTTP POST requests.
 */
class PostRequest final
    : public cURLRequest<PostRequest>
    , public PostData<PostRequest>
{
public:
    /**
     * @brief This constructor initializes the PostRequest object.
     * @param requestImplementator Shared pointer to the request implementator.
     */
    explicit PostRequest(std::shared_ptr<IRequestImplementator> requestImplementator)
        : cURLRequest<PostRequest>(requestImplementator)
        , PostData<PostRequest>(requestImplementator)
    {
        cURLRequest<PostRequest>::m_requestImplementator->setOption(OPT_CUSTOMREQUEST, METHOD_TYPE_MAP.at(METHOD_POST));
    }
    // LCOV_EXCL_START
    virtual ~PostRequest() = default;
    // LCOV_EXCL_STOP
};

/**
 * @brief This class is a wrapper for curl library. It provides a simple interface to perform HTTP PUT requests.
 */
class PutRequest final
    : public cURLRequest<PutRequest>
    , public PostData<PutRequest>
{
public:
    /**
     * @brief This constructor initializes the PutRequest object.
     * @param requestImplementator Shared pointer to the request implementator.
     */
    explicit PutRequest(std::shared_ptr<IRequestImplementator> requestImplementator)
        : cURLRequest<PutRequest>(requestImplementator)
        , PostData<PutRequest>(requestImplementator)
    {
        cURLRequest<PutRequest>::m_requestImplementator->setOption(OPT_CUSTOMREQUEST, METHOD_TYPE_MAP.at(METHOD_PUT));
    }

    // LCOV_EXCL_START
    virtual ~PutRequest() = default;
    // LCOV_EXCL_STOP
};

/**
 * @brief This class is a wrapper for curl library. It provides a simple interface to perform HTTP GET requests.
 */
class GetRequest final : public cURLRequest<GetRequest>
{
public:
    /**
     * @brief This constructor initializes the GetRequest object.
     * @param requestImplementator Shared pointer to the request implementator.
     */
    explicit GetRequest(std::shared_ptr<IRequestImplementator> requestImplementator)
        : cURLRequest<GetRequest>(requestImplementator)
    {
        requestImplementator->setOption(OPT_CUSTOMREQUEST, METHOD_TYPE_MAP.at(METHOD_GET).c_str());
    }

    // LCOV_EXCL_START
    virtual ~GetRequest() = default;
    // LCOV_EXCL_STOP
};

/**
 * @brief This class is a wrapper for curl library. It provides a simple interface to perform HTTP DELETE requests.
 */
class DeleteRequest final : public cURLRequest<DeleteRequest>
{
public:
    /**
     * @brief This constructor initializes the DeleteRequest object.
     * @param requestImplementator Shared pointer to the request implementator.
     */
    explicit DeleteRequest(std::shared_ptr<IRequestImplementator> requestImplementator)
        : cURLRequest<DeleteRequest>(requestImplementator)
    {
        requestImplementator->setOption(OPT_CUSTOMREQUEST, METHOD_TYPE_MAP.at(METHOD_DELETE).c_str());
    }

    // LCOV_EXCL_START
    virtual ~DeleteRequest() = default;
    // LCOV_EXCL_STOP
};

#endif // _CURLWRAPPER_HPP
