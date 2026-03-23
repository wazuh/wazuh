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

#ifndef _REGISTER_PROVIDER_DECODER_HPP
#define _REGISTER_PROVIDER_DECODER_HPP

#include "contentModuleFacade.hpp"
#include "dataDecoder.hpp"

/**
 * @brief RegisterProviderDecoder class.
 *
 */
class RegisterProviderDecoder final : public DataDecoder
{
private:
    const std::shared_ptr<std::vector<char>>& m_data;

public:
    /**
     * @brief Class constructor.
     *
     * @param data
     */
    explicit RegisterProviderDecoder(const std::shared_ptr<std::vector<char>>& data)
        : m_data {data}
    {
    }

    /**
     * @brief Decode data.
     *
     */
    void decode() override
    {
        auto decodedData = nlohmann::json::parse(m_data->begin() + sizeof(uint32_t), m_data->end());
        ContentModuleFacade::instance().addProvider(decodedData.at("name").get_ref<const std::string&>(),
                                                    decodedData.at("url").get_ref<const std::string&>(),
                                                    decodedData.at("path").get_ref<const std::string&>());
    }
};

#endif // _REGISTER_PROVIDER_DECODER_HPP
