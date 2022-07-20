/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 18, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CURL_WRAPPER_HPP
#define _CURL_WRAPPER_HPP

#include "IRequestImplementator.hpp"
#include "curl.h"
#include "customDeleter.hpp"
#include <map>
#include <memory>
#include <ostream>
#include <stdexcept>

using deleterCurl = CustomDeleter<decltype(&curl_easy_cleanup),
                                  curl_easy_cleanup>;
static const std::unique_ptr<CURL, deleterCurl> m_curlHandle { curl_easy_init() };


static const std::map<OPTION_REQUEST_TYPE, CURLoption> OPTION_REQUEST_TYPE_MAP =
{
    {OPT_URL, CURLOPT_URL},
    {OPT_CAINFO, CURLOPT_CAINFO},
    {OPT_TIMEOUT, CURLOPT_TIMEOUT},
    {OPT_WRITEDATA, CURLOPT_WRITEDATA},
    {OPT_USERAGENT, CURLOPT_USERAGENT},
    {OPT_POSTFIELDS, CURLOPT_POSTFIELDS},
    {OPT_WRITEFUNCTION, CURLOPT_WRITEFUNCTION},
    {OPT_POSTFIELDSIZE, CURLOPT_POSTFIELDSIZE},
    {OPT_CUSTOMREQUEST, CURLOPT_CUSTOMREQUEST},
    {OPT_UNIX_SOCKET_PATH, CURLOPT_UNIX_SOCKET_PATH},
    {OPT_FAILONERROR, CURLOPT_FAILONERROR}
};


class cURLWrapper final : public IRequestImplementator
{
    private:
        using deleterCurlStringList = CustomDeleter<decltype(&curl_slist_free_all), curl_slist_free_all>;
        std::unique_ptr<curl_slist, deleterCurlStringList> m_curlHeaders;

        static size_t writeData(char* data, size_t size, size_t nmemb, void* userdata)
        {
            const auto str { reinterpret_cast<std::string*>(userdata) };
            str->append(data, size * nmemb);
            return size * nmemb;
        }
        std::string m_returnValue;

    public:
        cURLWrapper()
        {
            if (!m_curlHandle)
            {
                throw std::runtime_error("cURL initialization failed");
            }

            setOption(OPT_WRITEFUNCTION, reinterpret_cast<void *>(cURLWrapper::writeData));

            setOption(OPT_WRITEDATA, &m_returnValue);

            setOption(OPT_FAILONERROR, 1l);
        }

        virtual ~cURLWrapper() = default;

        inline const std::string response() override
        {
            return m_returnValue;
        }

        void setOption(const OPTION_REQUEST_TYPE optIndex, void *ptr) override
        {
            auto ret = curl_easy_setopt(m_curlHandle.get(),
                             OPTION_REQUEST_TYPE_MAP.at(optIndex),
                             ptr);

            if (ret != CURLE_OK)
            {
                throw std::runtime_error("cURL set option failed");
            }
        }

        void setOption(const OPTION_REQUEST_TYPE optIndex, const std::string &opt) override
        {
            auto ret = curl_easy_setopt(m_curlHandle.get(),
                             OPTION_REQUEST_TYPE_MAP.at(optIndex),
                             opt.c_str());

            if (ret != CURLE_OK)
            {
                throw std::runtime_error("cURLWrapper::setOption() failed");
            }
        }

        void setOption(const OPTION_REQUEST_TYPE optIndex, const long opt) override
        {
            auto ret = curl_easy_setopt(m_curlHandle.get(),
                             OPTION_REQUEST_TYPE_MAP.at(optIndex),
                             opt);

            if (ret != CURLE_OK)
            {
                throw std::runtime_error("cURLWrapper::setOption() failed");
            }

        }

        void appendHeader(const std::string &header) override
        {
            if (!m_curlHeaders)
            {
                m_curlHeaders.reset(curl_slist_append(m_curlHeaders.get(), header.c_str()));
            }
            else
            {
                curl_slist_append(m_curlHeaders.get(), header.c_str());
            }
        }

        void execute() override
        {
            curl_easy_setopt(m_curlHandle.get(), CURLOPT_HTTPHEADER, m_curlHeaders.get());

            const auto result { curl_easy_perform(m_curlHandle.get())};
            if (result != CURLE_OK)
            {
                throw std::runtime_error(curl_easy_strerror(result));
            }
        }
};

#endif // _CURL_WRAPPER_HPP

