/*
 * Wazuh Inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * January 13, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_HARVESTER_HPP
#define _INVENTORY_HARVESTER_HPP

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
 * @brief InventoryHarvester class.
 *
 */
class EXPORTED InventoryHarvester final : public Singleton<InventoryHarvester>
{
public:
    /**
     * @brief Starts Inventory harvester.
     *
     * @param logFunction Log function to be used.
     * @param configuration Harvester configuration.
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
     * @brief Stops Inventory scanner.
     *
     */
    void stop() const;
};

#endif // _INVENTORY_HARVESTER_HPP
