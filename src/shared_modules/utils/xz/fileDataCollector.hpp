/*
 * Wazuh - Shared Modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * April 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FILE_DATA_COLLECTOR_HPP
#define _FILE_DATA_COLLECTOR_HPP

#include "iDataCollector.hpp"
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

namespace Xz
{
    /**
     * @brief Collects the output data and saves it to a file
     *
     */
    class FileDataCollector : public IDataCollector
    {
        static constexpr size_t DEFAULT_BUFFER_SIZE {8192}; ///< Default buffer size
        std::filesystem::path m_filePath;                   ///< Output file path
        std::ofstream m_file;                               ///< Output file stream
        std::vector<uint8_t> m_buffer; ///< Buffer used to receive data that will be saved to the file

    public:
        /**
         * @brief Construct a new File Data Collector object
         *
         * @param outputFilePath Path to the input file
         * @param bufferSize Size to give to the receiving buffer
         */
        explicit FileDataCollector(const std::filesystem::path& outputFilePath, size_t bufferSize = DEFAULT_BUFFER_SIZE)
            : m_filePath(outputFilePath)
        {
            m_buffer.resize(bufferSize);
        }

        /*! @copydoc IDataCollector::begin() */
        void begin() override
        {
            m_file = std::ofstream(m_filePath);
            if (!m_file.is_open())
            {
                // LCOV_EXCL_START
                throw std::runtime_error("Could not open destination file '" + m_filePath.string() + "'");
                // LCOV_EXCL_STOP
            }
        }

        /*! @copydoc IDataCollector::finish() */
        void finish() override
        {
            m_file.close();
        }

        /*! @copydoc IDataCollector::setBuffer() */
        void setBuffer(uint8_t** buffer, size_t& buffSize) override
        {
            *buffer = m_buffer.data();
            buffSize = m_buffer.size();
        }

        /*! @copydoc IDataCollector::dataReady() */
        void dataReady(size_t unusedBufferLen) override
        {
            m_file.write(reinterpret_cast<char*>(m_buffer.data()), m_buffer.size() - unusedBufferLen);
            if (!m_file.good())
            {
                throw std::runtime_error("Error saving data: " + std::string(std::strerror(errno))); // LCOV_EXCL_LINE
            }
        }
    };
} // namespace Xz
#endif // _FILE_DATA_COLLECTOR_HPP
