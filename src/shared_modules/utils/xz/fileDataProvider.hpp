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

#ifndef _FILE_DATA_PROVIDER_HPP
#define _FILE_DATA_PROVIDER_HPP

#include "iDataProvider.hpp"
#include <filesystem>
#include <fstream>
#include <vector>

namespace Xz
{
    /**
     * @brief Provides data from an input file
     *
     */
    class FileDataProvider : public IDataProvider
    {
        static constexpr size_t DEFAULT_BUFFER_SIZE {8192}; ///< Default buffer size
        std::filesystem::path m_filePath;                   ///< Input file path
        std::ifstream m_file;                               ///< Input file stream
        std::vector<uint8_t> m_buffer;                      ///< Buffer used to read data from the file

    public:
        /**
         * @brief Construct a new File Data Provider object
         *
         * @param inputFilePath Path to the input file
         * @param bufferSize Size to give to the reading buffer
         */
        explicit FileDataProvider(const std::filesystem::path& inputFilePath, size_t bufferSize = DEFAULT_BUFFER_SIZE)
            : m_filePath(inputFilePath)
        {
            m_buffer.resize(bufferSize);
        }

        /*! @copydoc IDataProvider::begin() */
        void begin() override
        {
            m_file = std::ifstream(m_filePath);
            if (!m_file.is_open())
            {
                throw std::runtime_error("Could not open input file '" + m_filePath.string() + "'");
            }
        }

        /**
         * @copydoc IDataProvider::getNextBlock()
         * @details Read a block of data from the file into m_buffer. If the end of the file was reached returns dataLen
         * = 0
         * @return DataBlock
         */
        DataBlock getNextBlock() override
        {
            DataBlock dataBlock;
            if (!m_file.eof())
            {
                m_file.read(reinterpret_cast<char*>(m_buffer.data()), m_buffer.size());
                dataBlock.data = m_buffer.data();
                dataBlock.dataLen = m_file.gcount();
            }
            return dataBlock;
        }
    };
} // namespace Xz
#endif // _FILE_DATA_PROVIDER_HPP
