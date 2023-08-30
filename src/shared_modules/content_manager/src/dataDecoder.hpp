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

#ifndef _DATA_DECODER_HPP
#define _DATA_DECODER_HPP

/**
 * @brief DataDecoder class.
 *
 */
class DataDecoder
{
public:
    virtual ~DataDecoder() = default;

    /**
     * @brief Decodes data.
     *
     */
    virtual void decode() = 0;
};

#endif // _DATA_DECODER_HPP
