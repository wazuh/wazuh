/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * September 10, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _IMESSAGE_CREATOR_H
#define _IMESSAGE_CREATOR_H

#include "json.hpp"
#include "rsyncImplementation.h"

namespace RSync
{
    template <typename Type>
    class IMessageCreator
    {
        public:
            // LCOV_EXCL_START
            virtual ~IMessageCreator() = default;
            // LCOV_EXCL_STOP
            virtual void send(const ResultCallback callback, const nlohmann::json& config, const Type& data) = 0;
    };
};// namespace RSync

#endif //_IMESSAGE_CREATOR_H
