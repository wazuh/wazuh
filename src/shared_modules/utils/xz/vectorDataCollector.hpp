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

#ifndef _VECTOR_DATA_COLLECTOR_HPP
#define _VECTOR_DATA_COLLECTOR_HPP

#include "iDataCollector.hpp"
#include <cstddef>
#include <cstdint>
#include <vector>

namespace Xz
{
    /**
     * @brief Collects the output data in a vector
     *
     */
    class VectorDataCollector : public IDataCollector
    {
        static constexpr size_t DEFAULT_BUFFER_SIZE {8192}; ///< Default buffer size
        std::vector<uint8_t>& m_output;                     ///< Output data
        size_t m_outDataIdx {0};                            ///< Index to the last received byte of the output data
        size_t m_bufferSize;                                ///< Buffer size to use in each data block

    public:
        /**
         * @brief Construct a new Vector Data Collector object
         *
         * @param output Reference to vector to collect the output data
         * @param bufferSize Buffer size to use for the receiving buffer
         */
        explicit VectorDataCollector(std::vector<uint8_t>& output, size_t bufferSize = DEFAULT_BUFFER_SIZE)
            : m_output(output)
            , m_bufferSize(bufferSize)
        {
        }

        /*! @copydoc IDataCollector::begin() */
        void begin() override
        {
            m_outDataIdx = 0;
        }

        /*! @copydoc IDataCollector::setBuffer() */
        void setBuffer(uint8_t** buffer, size_t& buffSize) override
        {
            // Allocate more space on the vector
            m_output.resize(m_output.size() + m_bufferSize);

            // Set the output buffer and its available space
            *buffer = &m_output[m_outDataIdx];
            buffSize = m_bufferSize;
        }

        /*! @copydoc IDataCollector::dataReady() */
        void dataReady(size_t unusedBufferLen) override
        {
            // Calculate the amount of new data
            auto const newDataQty {m_bufferSize - unusedBufferLen};
            // Move the output data index accordingly
            m_outDataIdx += newDataQty;
            // Reset the size of the output data
            m_output.resize(m_outDataIdx);
        }
    };
} // namespace Xz
#endif // _VECTOR_DATA_COLLECTOR_HPP
