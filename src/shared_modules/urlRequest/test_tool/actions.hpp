/*
 * Wazuh urlRequest TestTool
 * Copyright (C) 2015, Wazuh Inc.
 * July 13, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ACTION_HPP
#define _ACTION_HPP
#include <iostream>
#include "HTTPRequest.hpp"

class IAction
{
    public:
        virtual ~IAction() = default;
        virtual void execute() = 0;
};

class DownloadAction final : public IAction
{
    private:
        std::string m_url;
        std::string m_outputFile;

    public:
        DownloadAction(const std::string& url, const std::string& outputFile)
            : m_url(url)
            , m_outputFile(outputFile)
        {}

        void execute() override
        {
            HTTPRequest::instance().download(HttpURL(m_url),
                                             m_outputFile,
            [](const std::string& msg)
            {
                std::cerr << msg << std::endl;
                throw std::runtime_error(msg);
            });
        }
};

class GetAction final : public IAction
{
    private:
        std::string m_url;

    public:
        GetAction(const std::string& url)
            : m_url(url)
        {}

        void execute() override
        {
            HTTPRequest::instance().get(HttpURL(m_url),
            [](const std::string& msg)
            {
                std::cout << msg << std::endl;
            },
            [](const std::string& msg)
            {
                std::cerr << msg << std::endl;
                throw std::runtime_error(msg);
            });
        }
};

class PostAction final : public IAction
{
    private:
        std::string m_url;
        nlohmann::json m_data;

    public:
        PostAction(const std::string& url, const nlohmann::json& data)
            : m_url(url)
            , m_data(data)
        {}

        void execute() override
        {
            HTTPRequest::instance().post(HttpURL(m_url),
                                         m_data,
            [](const std::string& msg)
            {
                std::cout << msg << std::endl;
            },
            [](const std::string& msg)
            {
                std::cerr << msg << std::endl;
                throw std::runtime_error(msg);
            });
        }
};

class PutAction final : public IAction
{
    private:
        std::string m_url;
        nlohmann::json m_data;

    public:
        PutAction(const std::string& url, const nlohmann::json& data)
            : m_url(url)
            , m_data(data)
        {}

        void execute() override
        {
            HTTPRequest::instance().update(HttpURL(m_url),
                                           m_data,
            [](const std::string& msg)
            {
                std::cout << msg << std::endl;
            },
            [](const std::string& msg)
            {
                std::cerr << msg << std::endl;
                throw std::runtime_error(msg);
            });
        }
};

class DeleteAction final : public IAction
{
    private:
        std::string m_url;
    public:
        DeleteAction(const std::string& url)
            : m_url(url)
        {}

        void execute() override
        {
            HTTPRequest::instance().delete_(HttpURL(m_url),
            [](const std::string& msg)
            {
                std::cout << msg << std::endl;
            },
            [](const std::string& msg)
            {
                std::cerr << msg << std::endl;
                throw std::runtime_error(msg);
            });
        }
};

#endif // _ACTION_HPP
