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
#include "HTTPRequest.hpp"
#include "curlException.hpp"
#include <iostream>

/**
 * @brief Action interface.
 */
class IAction
{
public:
    virtual ~IAction() = default;

    /**
     * @brief Virtual method to execute the action.
     */
    virtual void execute() = 0;
};

/**
 * @brief This class is used to perform a DOWNLOAD action.
 */
class DownloadAction final : public IAction
{
private:
    std::string m_url;
    std::string m_outputFile;

public:
    /**
     * @brief Constructor for DownloadAction class.
     * @param url URL to download.
     * @param outputFile Output file.
     */
    explicit DownloadAction(const std::string& url, const std::string& outputFile)
        : m_url(url)
        , m_outputFile(outputFile)
    {
    }

    /**
     * @brief Executes the action.
     */
    void execute() override
    {
        HTTPRequest::instance().download(HttpURL(m_url),
                                         m_outputFile,
                                         [](const std::string& msg, const long responseCode)
                                         {
                                             std::cerr << msg << ": " << responseCode << std::endl;
                                             throw std::runtime_error(msg);
                                         });
    }
};

/**
 * @brief This class is used to perform a GET action.
 */
class GetAction final : public IAction
{
private:
    std::string m_url;

public:
    /**
     * @brief Constructor of GetAction class.
     * @param url URL to perform the GET request.
     */
    explicit GetAction(const std::string& url)
        : m_url(url)
    {
    }

    /**
     * @brief This method is used to perform the GET request.
     */
    void execute() override
    {
        HTTPRequest::instance().get(
            HttpURL(m_url),
            [](const std::string& msg) { std::cout << msg << std::endl; },
            [](const std::string& msg, const long responseCode)
            {
                std::cerr << msg << ": " << responseCode << std::endl;
                throw std::runtime_error(msg);
            });
    }
};

/**
 * @brief This class is used to perform a POST action.
 */
class PostAction final : public IAction
{
private:
    std::string m_url;
    nlohmann::json m_data;

public:
    /**
     * @brief Constructor of PostAction class.
     * @param url URL to perform the POST request.
     * @param data Data to send in the POST request.
     */
    explicit PostAction(const std::string& url, const nlohmann::json& data)
        : m_url(url)
        , m_data(data)
    {
    }

    /**
     * @brief This method is used to perform the POST request.
     */
    void execute() override
    {
        HTTPRequest::instance().post(
            HttpURL(m_url),
            m_data,
            [](const std::string& msg) { std::cout << msg << std::endl; },
            [](const std::string& msg, const long responseCode)
            {
                std::cerr << msg << ": " << responseCode << std::endl;
                throw std::runtime_error(msg);
            });
    }
};

/**
 * @brief This class is used to perform a PUT action.
 */
class PutAction final : public IAction
{
private:
    std::string m_url;
    nlohmann::json m_data;

public:
    /**
     * @brief Constructor of PutAction class.
     * @param url URL to perform the PUT request.
     * @param data Data to send in the PUT request.
     */
    explicit PutAction(const std::string& url, const nlohmann::json& data)
        : m_url(url)
        , m_data(data)
    {
    }

    /**
     * @brief This method is used to perform the PUT request.
     */
    void execute() override
    {
        HTTPRequest::instance().update(
            HttpURL(m_url),
            m_data,
            [](const std::string& msg) { std::cout << msg << std::endl; },
            [](const std::string& msg, const long responseCode)
            {
                std::cerr << msg << ": " << responseCode << std::endl;
                throw std::runtime_error(msg);
            });
    }
};

/**
 * @brief This class is used to perform a DELETE action.
 */
class DeleteAction final : public IAction
{
private:
    std::string m_url;

public:
    /**
     * @brief Constructor of DeleteAction class.
     * @param url URL to perform the DELETE request.
     */
    explicit DeleteAction(const std::string& url)
        : m_url(url)
    {
    }

    /**
     * @brief This method is used to perform the DELETE request.
     */
    void execute() override
    {
        HTTPRequest::instance().delete_(
            HttpURL(m_url),
            [](const std::string& msg) { std::cout << msg << std::endl; },
            [](const std::string& msg, const long responseCode)
            {
                std::cerr << msg << ": " << responseCode << std::endl;
                throw std::runtime_error(msg);
            });
    }
};

#endif // _ACTION_HPP
