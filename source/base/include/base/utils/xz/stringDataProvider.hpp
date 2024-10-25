/*
 * Wazuh - Shared Modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * June 23, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BASE_UTILS_STRING_DATA_PROVIDER_HPP
#define _BASE_UTILS_STRING_DATA_PROVIDER_HPP

#include <string>

#include "iDataProvider.hpp"

namespace base::utils::xz
{
/**
 * @brief Provides data from a string
 *
 */
class StringDataProvider : public IDataProvider
{
    const std::string& m_inputData; ///< Reference to the input string
    bool hasPendingData {true};     ///< Indicates whether there is unprocessed data.

public:
    /**
     * @brief Construct a new String Data Provider object
     *
     * @param inputData String with the input data
     */
    explicit StringDataProvider(const std::string& inputData)
        : m_inputData(inputData)
    {
    }

    /*! @copydoc IDataProvider::begin() */
    void begin() override { hasPendingData = true; }

    /*! @copydoc IDataProvider::getNextBlock() */
    DataBlock getNextBlock() override
    {
        DataBlock dataBlock;
        if (hasPendingData)
        {
            // Since all the input data is already available in the input string just provide all the data in one
            // block.
            dataBlock.data = reinterpret_cast<const uint8_t*>(m_inputData.data());
            dataBlock.dataLen = m_inputData.size();
            hasPendingData = false;
        }
        return dataBlock;
    }
};
} // namespace base::utils::xz
#endif // _BASE_UTILS_STRING_DATA_PROVIDER_HPP
