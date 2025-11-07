/*
 * Wazuh - Quickwit connector.
 * Copyright (C) 2015, Wazuh Inc.
 * November 7, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _QUICKWIT_CONNECTOR_HPP
#define _QUICKWIT_CONNECTOR_HPP

#include <functional>
#include <json.hpp>
#include <memory>
#include <mutex>
#include <string_view>

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

/**
 * @brief QuickwitConnectorAsync class - Quickwit async connector.
 *
 * This class provides async indexing capabilities for Quickwit,
 * a cloud-native search engine optimized for logs and traces.
 */

constexpr auto QW_NAME {"QuickwitConnector"};

class EXPORTED QuickwitConnectorAsync final
{
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;

public:
    /**
     * @brief Class constructor that initializes the Quickwit connector.
     *
     * @param config Quickwit configuration, including hosts and SSL settings.
     * @param logFunction Callback function to be called when trying to log a message.
     */
    explicit QuickwitConnectorAsync(
        const nlohmann::json& config,
        const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
            logFunction = {});

    ~QuickwitConnectorAsync();

    /**
     * @brief Index a document.
     *
     * @param id ID of the document (ignored for Quickwit, as it doesn't require explicit IDs).
     * @param index Index name.
     * @param data Data in JSON format.
     */
    void index(std::string_view id, std::string_view index, std::string_view data);

    /**
     * @brief Index a document with version (version is ignored for Quickwit).
     *
     * @param id ID of the document.
     * @param index Index name.
     * @param data Data in JSON format.
     * @param version Document version (ignored).
     */
    void index(std::string_view id, std::string_view index, std::string_view data, std::string_view version);

    /**
     * @brief Index a document without explicit ID.
     *
     * @param index Index name.
     * @param data Data in JSON format.
     */
    void index(std::string_view index, std::string_view data);

    /**
     * @brief Check if a server is available.
     *
     * @return true if a server is available, false otherwise.
     */
    bool isAvailable() const;

    /**
     * @brief Create an index in Quickwit.
     *
     * @param index Index name.
     * @param config Index configuration in JSON format.
     */
    void createIndex(std::string_view index, const nlohmann::json& config);
};

class QuickwitConnectorException : public std::exception
{
private:
    std::string m_message;

public:
    explicit QuickwitConnectorException(std::string message)
        : m_message(std::move(message))
    {
    }

    const char* what() const noexcept override
    {
        return m_message.c_str();
    }
};

#endif // _QUICKWIT_CONNECTOR_HPP
