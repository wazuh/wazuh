/*
 * Copyright (C) 2015, Wazuh Inc.
 * November 5, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fs/xzHelper.hpp"

namespace fs
{
XzHelper::XzHelper(const std::filesystem::path& source, const std::filesystem::path& dest, uint32_t threadCount)
    : m_spDataProvider(std::make_unique<fs::xz::FileDataProvider>(source))
    , m_spDataCollector(std::make_unique<fs::xz::FileDataCollector>(dest))
    , m_threadCount(threadCount)
{
}

XzHelper::XzHelper(const std::filesystem::path& source, std::vector<uint8_t>& dest, uint32_t threadCount)
    : m_spDataProvider(std::make_unique<fs::xz::FileDataProvider>(source))
    , m_spDataCollector(std::make_unique<fs::xz::VectorDataCollector>(dest))
    , m_threadCount(threadCount)
{
}

XzHelper::XzHelper(const std::vector<uint8_t>& source, const std::filesystem::path& dest, uint32_t threadCount)
    : m_spDataProvider(std::make_unique<fs::xz::VectorDataProvider>(source))
    , m_spDataCollector(std::make_unique<fs::xz::FileDataCollector>(dest))
    , m_threadCount(threadCount)
{
}

XzHelper::XzHelper(const std::vector<uint8_t>& source, std::vector<uint8_t>& dest, uint32_t threadCount)
    : m_spDataProvider(std::make_unique<fs::xz::VectorDataProvider>(source))
    , m_spDataCollector(std::make_unique<fs::xz::VectorDataCollector>(dest))
    , m_threadCount(threadCount)
{
}

XzHelper::XzHelper(const std::string& source, const std::filesystem::path& dest, uint32_t threadCount)
    : m_spDataProvider(std::make_unique<fs::xz::StringDataProvider>(source))
    , m_spDataCollector(std::make_unique<fs::xz::FileDataCollector>(dest))
    , m_threadCount(threadCount)
{
}

XzHelper::XzHelper(const std::string& source, std::vector<uint8_t>& dest, uint32_t threadCount)
    : m_spDataProvider(std::make_unique<fs::xz::StringDataProvider>(source))
    , m_spDataCollector(std::make_unique<fs::xz::VectorDataCollector>(dest))
    , m_threadCount(threadCount)
{
}

void XzHelper::compress(uint32_t compressionPreset)
{
    fs::xz::Wrapper xz(m_threadCount);
    xz.compress(*m_spDataProvider, *m_spDataCollector, compressionPreset);
}

void XzHelper::decompress()
{
    fs::xz::Wrapper xz(m_threadCount);
    xz.decompress(*m_spDataProvider, *m_spDataCollector);
}
} // namespace fs
