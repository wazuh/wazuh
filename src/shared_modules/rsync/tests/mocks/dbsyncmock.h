/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * September 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MOCKDBSYNC_TEST_H
#define _MOCKDBSYNC_TEST_H

#include <gmock/gmock.h>
#include <string>
#include "dbsyncWrapper.h"

class MockDBSync : public RSync::DBSyncWrapper
{
    public:
        MockDBSync() : RSync::DBSyncWrapper(nullptr) {};
        virtual ~MockDBSync() = default;

        MOCK_METHOD(void,
                    select,
                    (nlohmann::json&, ResultCallbackData),
                    (override));

};

#endif //_MOCKDBSYNC_TEST_H
