/*
 * Wazuh Inventory sync
 * Copyright (C) 2015, Wazuh Inc.
 * May 14, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_SYNC_HPP
#define _INVENTORY_SYNC_HPP

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "json.hpp"
#include "singleton.hpp"
#include <functional>
#include <string>

/**
 * @brief InventorySync class.
 *
 */
class EXPORTED InventorySync final : public Singleton<InventorySync>
{
public:
    /**
     * @brief Starts Inventory Sync.
     *
     * @param logFunction Log function to be used.
     * @param configuration Sync configuration.
     */
    void start(const std::function<void(const int,
                                        const std::string&,
                                        const std::string&,
                                        const int,
                                        const std::string&,
                                        const std::string&,
                                        va_list)>& logFunction,
               const nlohmann::json& configuration) const;
    /**
     * @brief Stops Inventory sync.
     *
     */
    void stop() const;
};

#endif // _INVENTORY_SYNC_HPP
