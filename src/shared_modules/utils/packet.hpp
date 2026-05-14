/*
 * Wazuh utils
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKET_HPP
#define _PACKET_HPP

#include <memory>

class Packet final
{
public:
    Packet(char* data, uint32_t size)
        : m_data {std::make_unique<char[]>(size + 1)}
        , m_size(size)
        , m_offset(0)
    {
        std::copy(data, data + size, this->m_data.get());
    }
    virtual ~Packet() = default;
    std::unique_ptr<char[]> m_data;
    uint32_t m_size;
    uint32_t m_offset;
};

#endif // _PACKET_HPP
