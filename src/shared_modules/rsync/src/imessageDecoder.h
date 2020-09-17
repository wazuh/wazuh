/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * September 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _IMESSAGEDECODER_H
#define _IMESSAGEDECODER_H
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
        virtual SyncInputData decode(const std::vector<unsigned char>& rawData) = 0;
    };
};// namespace RSync

#endif //_IMESSAGEDECODER_H