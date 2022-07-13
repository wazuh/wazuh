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

#include "curlWrapper.hpp"

template <typename T>
void cURLRequest<T>::execute()
{
    const auto result { curl_easy_perform(m_curlHandle.get()) };
    if (CURLE_OK != result)
    {
        throw std::runtime_error(curl_easy_strerror(result));
    }

    if (m_callback)
    {
        m_callback(m_returnValue);
    }
}

template <typename T>
T & cURLRequest<T>::unixSocketPath(const std::string &sock)
{
    curl_easy_setopt(m_curlHandle.get(),
                     CURLOPT_UNIX_SOCKET_PATH,
                     sock.empty() ? nullptr : sock.c_str());

    return static_cast<T&>(*this);
}

template <typename T>
T & cURLRequest<T>::url(const std::string &url)
{
    curl_easy_setopt(m_curlHandle.get(),
                     CURLOPT_URL,
                     url.c_str());

    return static_cast<T&>(*this);
}

template <typename T>
T & cURLRequest<T>::userAgent(const std::string &userAgent)
{
    curl_easy_setopt(m_curlHandle.get(),
                     CURLOPT_USERAGENT,
                     userAgent.c_str());

    return static_cast<T&>(*this);
}

template <typename T>
PostRequest & PostRequest::postData(const nlohmann::json &postData)
{
    const auto postDataString { postData.dump() };
    curl_easy_setopt(m_curlHandle.get(),
                     CURLOPT_POSTFIELDS,
                     postDataString.c_str());

    curl_easy_setopt(m_curlHandle.get(),
                     CURLOPT_POSTFIELDSIZE,
                     postDataString.size());

    return static_cast<T&>(*this);
}

GetRequest & GetRequest::outputFile(const std::string &outputFile)
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

