/*
 * Wazuh - Indexer connector.
 * Copyright (C) 2015, Wazuh Inc.
 * June 2, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_CONNECTOR_HPP
#define _INDEXER_CONNECTOR_HPP

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "threadEventDispatcher.hpp"
#include <json.hpp>
#include <string>

using ThreadDispatchQueue = ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>>;

/**
 * @brief IndexerConnector
 *
 */
class EXPORTED IndexerConnector final
{
public:
    /**
     * @brief Construct a new Indexer Connector object
     *
     * @param config
     */
    explicit IndexerConnector(const nlohmann::json& config);
    ~IndexerConnector();

    /**
     * @brief
     *
     * @param message
     */
    void publish(const std::string& message);
};

#endif // _INDEXER_CONNECTOR_HPP
