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

#ifndef _I_DATA_COLLECTOR_HPP
#define _I_DATA_COLLECTOR_HPP
#include <cstddef>
#include <cstdint>

namespace Xz
{
    /**
     * @brief Data collector interface for the XZ Wrapper
     *
     */
    class IDataCollector
    {
    public:
        // LCOV_EXCL_START
        virtual ~IDataCollector() = default;
        // LCOV_EXCL_STOP

        /**
         * @brief Called at the start of the process so that the collector can initialize its internal state
         *
         */
        virtual void begin() = 0;

        /**
         * @brief Called at the end of the process so that the collector can close its state properly
         *
         */
        virtual void finish() {};

        /**
         * @brief Set the output buffer
         *
         * @param[out] buffer Buffer to hold the partial output data
         * @param[out] buffSize Size of the buffer
         */
        virtual void setBuffer(uint8_t** buffer, size_t& buffSize) = 0;

        /**
         * @brief Called when there is data ready to be saved in the output buffer
         *
         * @param unusedBufferLen Amount of unused space in the output buffer.
         */
        virtual void dataReady(size_t unusedBufferLen) = 0;
    };
} // namespace Xz
#endif // _I_DATA_COLLECTOR_HPP
