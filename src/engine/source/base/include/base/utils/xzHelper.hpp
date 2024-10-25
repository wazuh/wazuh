/*
 * Wazuh - Shared Modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * April 19, 2023.
 *
 */

#ifndef _XZ_HELPER_HPP
#define _XZ_HELPER_HPP

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "xz/fileDataCollector.hpp"
#include "xz/fileDataProvider.hpp"
#include "xz/iDataCollector.hpp"
#include "xz/iDataProvider.hpp"
#include "xz/stringDataProvider.hpp"
#include "xz/vectorDataCollector.hpp"
#include "xz/vectorDataProvider.hpp"
#include "xz/wrapper.hpp"

namespace base::utils
{
/**
 * @brief Helper class for compressing/decompressing data in xz format
 *
 */
class XzHelper
{
    std::unique_ptr<base::utils::xz::IDataProvider> m_spDataProvider;   ///< Data provider
    std::unique_ptr<base::utils::xz::IDataCollector> m_spDataCollector; ///< Data collector
    uint32_t m_threadCount;

public:
    /**
     * @brief Construct XZ helper with file input and file output
     *
     * @param source Path to input file
     * @param dest Path to destination file
     * @param threadCount  Number of worker threads. 0 uses all the available threads.
     */
    XzHelper(const std::filesystem::path& source,
             const std::filesystem::path& dest,
             uint32_t threadCount = base::utils::xz::DEFAULT_THREAD_COUNT)
        : m_spDataProvider(std::make_unique<base::utils::xz::FileDataProvider>(source))
        , m_spDataCollector(std::make_unique<base::utils::xz::FileDataCollector>(dest))
        , m_threadCount(threadCount)
    {
    }

    /**
     * @brief Construct XZ helper with file input and vector output
     *
     * @param source Path to input file
     * @param dest Vector for the output data
     * @param threadCount  Number of worker threads. 0 uses all the available threads.
     */
    XzHelper(const std::filesystem::path& source,
             std::vector<uint8_t>& dest,
             uint32_t threadCount = base::utils::xz::DEFAULT_THREAD_COUNT)
        : m_spDataProvider(std::make_unique<base::utils::xz::FileDataProvider>(source))
        , m_spDataCollector(std::make_unique<base::utils::xz::VectorDataCollector>(dest))
        , m_threadCount(threadCount)
    {
    }

    /**
     * @brief Construct XZ helper with vector input and file output
     *
     * @param source Vector with the input data
     * @param dest Path to destination file
     * @param threadCount  Number of worker threads. 0 uses all the available threads.
     */
    XzHelper(const std::vector<uint8_t>& source,
             const std::filesystem::path& dest,
             uint32_t threadCount = base::utils::xz::DEFAULT_THREAD_COUNT)
        : m_spDataProvider(std::make_unique<base::utils::xz::VectorDataProvider>(source))
        , m_spDataCollector(std::make_unique<base::utils::xz::FileDataCollector>(dest))
        , m_threadCount(threadCount)
    {
    }

    /**
     * @brief Construct XZ helper with vector input and vector output
     *
     * @param source Vector with the input data
     * @param dest Vector for the output data
     * @param threadCount  Number of worker threads. 0 uses all the available threads.
     */
    XzHelper(const std::vector<uint8_t>& source,
             std::vector<uint8_t>& dest,
             uint32_t threadCount = base::utils::xz::DEFAULT_THREAD_COUNT)
        : m_spDataProvider(std::make_unique<base::utils::xz::VectorDataProvider>(source))
        , m_spDataCollector(std::make_unique<base::utils::xz::VectorDataCollector>(dest))
        , m_threadCount(threadCount)
    {
    }

    /**
     * @brief Construct XZ helper with string input and file output
     *
     * @param source String with the input data
     * @param dest Path to destination file
     * @param threadCount  Number of worker threads. 0 uses all the available threads.
     */
    XzHelper(const std::string& source,
             const std::filesystem::path& dest,
             uint32_t threadCount = base::utils::xz::DEFAULT_THREAD_COUNT)
        : m_spDataProvider(std::make_unique<base::utils::xz::StringDataProvider>(source))
        , m_spDataCollector(std::make_unique<base::utils::xz::FileDataCollector>(dest))
        , m_threadCount(threadCount)
    {
    }

    /**
     * @brief Construct XZ helper with string input and vector output
     *
     * @param source String with the input data
     * @param dest Vector for the output data
     * @param threadCount  Number of worker threads. 0 uses all the available threads.
     */
    XzHelper(const std::string& source,
             std::vector<uint8_t>& dest,
             uint32_t threadCount = base::utils::xz::DEFAULT_THREAD_COUNT)
        : m_spDataProvider(std::make_unique<base::utils::xz::StringDataProvider>(source))
        , m_spDataCollector(std::make_unique<base::utils::xz::VectorDataCollector>(dest))
        , m_threadCount(threadCount)
    {
    }

    /**
     * @brief Compress the input data
     *
     * @param compressionPreset Compression level. A value from 0 to 9. Roughly, the higher the value the higher the
     * compression ratio, at the expense of slower times and more memory usage. Default preset is 9.
     */
    void compress(uint32_t compressionPreset = base::utils::xz::DEFAULT_COMPRESSION_PRESET)
    {
        base::utils::xz::Wrapper xz(m_threadCount);
        xz.compress(*m_spDataProvider, *m_spDataCollector, compressionPreset);
    }

    /**
     * @brief Decompress the input data
     *
     */
    void decompress()
    {
        base::utils::xz::Wrapper xz(m_threadCount);
        xz.decompress(*m_spDataProvider, *m_spDataCollector);
    }
};

} // namespace base::utils

#endif // _XZ_HELPER_HPP
