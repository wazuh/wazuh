/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * March 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "RpmPackageManager_test.h"
#include "packages/rpmlibWrapper.h"
#include "packages/rpmPackageManager.h"

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgReferee;

void RpmLibTest::SetUp() {};
void RpmLibTest::TearDown() {};

class RpmLibMock final : public IRpmLibWrapper
{
    public:
        RpmLibMock() = default;
        virtual ~RpmLibMock() override {};
        MOCK_METHOD(int, rpmReadConfigFiles, (const char * file, const char * target));
        MOCK_METHOD(void, rpmFreeRpmrc, ());
        MOCK_METHOD(rpmtd, rpmtdNew, ());
        MOCK_METHOD(void, rpmtdFree, (rpmtd td));
        MOCK_METHOD(rpmts, rpmtsCreate, ());
        MOCK_METHOD(int, rpmtsOpenDB, (rpmts ts, int dbmode));
        MOCK_METHOD(int, rpmtsCloseDB, (rpmts ts));
        MOCK_METHOD(rpmts, rpmtsFree, (rpmts ts));
        MOCK_METHOD(int, headerGet, (Header h, rpmTagVal tag, rpmtd td, headerGetFlags flags));
        MOCK_METHOD(const char *, rpmtdGetString, (rpmtd td));
        MOCK_METHOD(uint64_t, rpmtdGetNumber, (rpmtd td));
        MOCK_METHOD(int, rpmtsRun, (rpmts ts, rpmps okProbs, rpmprobFilterFlags ignoreSet));
        MOCK_METHOD(rpmdbMatchIterator, rpmtsInitIterator, (const rpmts ts, rpmDbiTagVal rpmtag, const void *keypointer, size_t keylen));
        MOCK_METHOD(Header, rpmdbNextIterator, (rpmdbMatchIterator mi));
        MOCK_METHOD(rpmdbMatchIterator, rpmdbFreeIterator, (rpmdbMatchIterator mi));
};


TEST_F(RpmLibTest, MissingConfFiles)
{
    auto mock {std::make_shared<RpmLibMock>()};
    EXPECT_CALL(*mock, rpmReadConfigFiles(_, _)).WillOnce(Return(-1));
    EXPECT_THROW({
        try {
            RpmPackageManager rpm{mock};
        }
        catch(const std::runtime_error &e)
        {
            EXPECT_STREQ(e.what(), "rpmReadConfigFiles failed");
            throw;
        }
    }, std::runtime_error);
}

TEST_F(RpmLibTest, MultipleInstances)
{
    auto mock {std::make_shared<RpmLibMock>()};
    RpmPackageManager otherRpm{mock};
    EXPECT_THROW({
        try {
            RpmPackageManager rpm{mock};
        }
        catch(const std::runtime_error &e)
        {
            EXPECT_STREQ(e.what(), "there is another RPM instance already created");
            throw;
        }
    }, std::runtime_error);
}