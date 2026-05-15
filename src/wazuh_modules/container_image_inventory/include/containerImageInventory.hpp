/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_IMAGE_INVENTORY_HPP
#define _CONTAINER_IMAGE_INVENTORY_HPP

#include "containerImageInventoryTypes.hpp"
#include "json.hpp"

namespace container_image_inventory
{
    struct ScanOptions
    {
        std::string archive_path;
        std::string configured_ref;
    };

    class Scanner
    {
    public:
        explicit Scanner(TraceFn trace = nullptr);
        ScanResult scan_archive(const ScanOptions& opts);

    private:
        TraceFn m_trace;
        void trace(const std::string& msg) const;
    };

    nlohmann::json result_to_json(const ScanResult& r);
    std::string result_to_summary(const ScanResult& r);
} // namespace container_image_inventory

#endif
