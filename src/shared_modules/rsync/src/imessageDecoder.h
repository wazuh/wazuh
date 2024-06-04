/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _IMESSAGE_DECODER_H
#define _IMESSAGE_DECODER_H
#include <string>
#include <vector>

namespace RSync
{
    struct SyncInputData final
    {
        std::string command;
        std::string begin;
        std::string end;
        int32_t id;
    };

    class IMessageDecoder
    {
        public:
            // LCOV_EXCL_START
            virtual ~IMessageDecoder() = default;
            // LCOV_EXCL_STOP
            virtual SyncInputData decode(const std::vector<unsigned char>& rawData) = 0;
    };
};// namespace RSync

#endif //_IMESSAGE_DECODER_H
