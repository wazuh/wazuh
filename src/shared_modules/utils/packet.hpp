/*
 * Wazuh utils
 * Copyright (C) Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
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
