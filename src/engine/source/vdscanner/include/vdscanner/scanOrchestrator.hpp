/*
 * Wazuh Vulnerability scanner - Scan Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SCAN_ORCHESTRATOR_HPP
#define _SCAN_ORCHESTRATOR_HPP

#include "databaseFeedManager.hpp"
#include <memory>
#include <nlohmann/json_fwd.hpp>
#include <string>

namespace vdscanner
{
enum class PayloadType
{
    PackageList = 0,
    FullScan = 1
};

/**
 * @brief ScanOrchestrator class.
 *
 */
class ScanOrchestrator final
{
public:
    /**
     * @brief Class constructor.
     *
     */
    // LCOV_EXCL_START
    ScanOrchestrator();

    ~ScanOrchestrator() = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Process an event.
     *
     * @param input Event to process.
     */
    void processEvent(const std::string& request, std::string& response) const;

private:
    /**
     * @brief Runs orchestrator, decoding and building context.
     *
     * @param data Data to process.
     * @param response Raw data to process.
     */
    void run(PayloadType type, const nlohmann::json& request, std::string& response) const;

    std::shared_ptr<DatabaseFeedManager> m_databaseFeedManager;
    mutable std::shared_mutex m_mutex;
};
} // namespace vdscanner
#endif // _SCAN_ORCHESTRATOR_HPP
