/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FACTORY_DECODER_HPP
#define _FACTORY_DECODER_HPP

#include "dataDecoder.hpp"
#include "registryProviderDecoder.hpp"
#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <vector>

enum MessageType
{
    RegisterProvider = 0x00000001,
};

/**
 * @brief FactoryDecoder class.
 *
 */
class FactoryDecoder final
{
public:
    /**
     * @brief Creates and return a decoder.
     *
     * @param data Data to be decoded.
     * @return std::shared_ptr<DataDecoder> Decoder.
     */
    static std::shared_ptr<DataDecoder> create(const std::shared_ptr<std::vector<char>>& data)
    {
        // Decode data
        if (data->size() < sizeof(uint32_t))
        {
            throw std::runtime_error("Invalid data");
        }

        auto* ip = reinterpret_cast<const uint32_t*>(data->data());

        if (*ip == MessageType::RegisterProvider)
        {
            return std::make_shared<RegisterProviderDecoder>(data);
        }
        else
        {
            throw std::runtime_error("Invalid data, message type not found");
        }
    }
};
#endif // _FACTORY_DECODER_HPP
