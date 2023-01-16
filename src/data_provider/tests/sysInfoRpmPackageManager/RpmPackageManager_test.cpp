/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "RpmPackageManager_test.h"
#include "packages/rpmlibWrapper.h"
#include "packages/rpmPackageManager.h"
#include <rpm/rpmtag.h>

#include <fcntl.h>

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgReferee;

// We are using NiceMock to avoid having to use ON_CALL excessively.
using ::testing::NiceMock;

void RpmLibTest::SetUp() {};
void RpmLibTest::TearDown() {};

class RpmLibMock : public IRpmLibWrapper
{
    public:
        RpmLibMock() = default;
        virtual ~RpmLibMock() override {};
        MOCK_METHOD(int, rpmReadConfigFiles, (const char* file, const char* target), (override));
        MOCK_METHOD(void, rpmFreeRpmrc, (), (override));
        MOCK_METHOD(rpmtd, rpmtdNew, (), (override));
        MOCK_METHOD(void, rpmtdFree, (rpmtd td), (override));
        MOCK_METHOD(rpmts, rpmtsCreate, (), (override));
        MOCK_METHOD(int, rpmtsOpenDB, (rpmts ts, int dbmode), (override));
        MOCK_METHOD(int, rpmtsCloseDB, (rpmts ts), (override));
        MOCK_METHOD(rpmts, rpmtsFree, (rpmts ts), (override));
        MOCK_METHOD(int, headerGet, (Header h, rpmTagVal tag, rpmtd td, headerGetFlags flags), (override));
        MOCK_METHOD(const char*, rpmtdGetString, (rpmtd td), (override));
        MOCK_METHOD(uint64_t, rpmtdGetNumber, (rpmtd td), (override));
        MOCK_METHOD(int, rpmtsRun, (rpmts ts, rpmps okProbs, rpmprobFilterFlags ignoreSet), (override));
        MOCK_METHOD(rpmdbMatchIterator, rpmtsInitIterator, (const rpmts ts, rpmDbiTagVal rpmtag, const void* keypointer, size_t keylen), (override));
        MOCK_METHOD(Header, rpmdbNextIterator, (rpmdbMatchIterator mi), (override));
        MOCK_METHOD(rpmdbMatchIterator, rpmdbFreeIterator, (rpmdbMatchIterator mi), (override));
};


TEST(RpmLibTest, MissingConfFiles)
{
    auto mock {std::make_shared<RpmLibMock>()};
    EXPECT_CALL(*mock, rpmReadConfigFiles(_, _)).WillOnce(Return(-1));
    EXPECT_THROW(
    {
        try
        {
            RpmPackageManager rpm{mock};
        }
        catch (const std::runtime_error& e)
        {
            EXPECT_STREQ(e.what(), "rpmReadConfigFiles failed");
            throw;
        }
    }, std::runtime_error);
}

TEST(RpmLibTest, MultipleInstances)
{
    auto mock {std::make_shared<NiceMock<RpmLibMock>>()};
    RpmPackageManager otherRpm{mock};
    EXPECT_THROW(
    {
        try
        {
            RpmPackageManager rpm{mock};
        }
        catch (const std::runtime_error& e)
        {
            EXPECT_STREQ(e.what(), "there is another RPM instance already created");
            throw;
        }
    }, std::runtime_error);
}

TEST(RpmLibTest, RAII)
{
    auto mock {std::make_shared<NiceMock<RpmLibMock>>()};
    EXPECT_CALL(*mock, rpmReadConfigFiles(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*mock, rpmFreeRpmrc());
    {
        RpmPackageManager rpm{mock};
    }
}

TEST(RpmLibTest, TransactionSetCreateFailure)
{
    auto mock {std::make_shared<NiceMock<RpmLibMock>>()};
    std::vector<RpmPackageManager::Package> packages;
    EXPECT_CALL(*mock, rpmtsCreate()).WillOnce(Return(nullptr));

    EXPECT_THROW(
    {
        try
        {
            RpmPackageManager rpm{mock};

            for (const auto& p : rpm)
            {
            }
        }
        catch (const std::runtime_error& e)
        {
            EXPECT_STREQ(e.what(), "rpmtsCreate failed");
            throw;
        }
    }, std::runtime_error);
}

TEST(RpmLibTest, OpenDatabaseFailure)
{
    const auto tsMock = reinterpret_cast<rpmts>(0x45);
    auto mock {std::make_shared<NiceMock<RpmLibMock>>()};
    std::vector<RpmPackageManager::Package> packages;
    EXPECT_CALL(*mock, rpmtsCreate()).WillOnce(Return(tsMock));
    EXPECT_CALL(*mock, rpmtsOpenDB(tsMock, _)).WillOnce(Return(-1));

    EXPECT_THROW(
    {
        try
        {
            RpmPackageManager rpm{mock};

            for (const auto& p : rpm)
            {
            }
        }
        catch (const std::runtime_error& e)
        {
            EXPECT_STREQ(e.what(), "rpmtsOpenDB failed");
            throw;
        }
    }, std::runtime_error);
}

// Tests mostly the construction and destruction of RpmPackageManager::Iterator
TEST(RpmLibTest, TransactionSetRunFailure)
{
    const auto tsMock = reinterpret_cast<rpmts>(0x45);
    auto mock {std::make_shared<NiceMock<RpmLibMock>>()};
    std::vector<RpmPackageManager::Package> packages;
    EXPECT_CALL(*mock, rpmtsCreate()).WillOnce(Return(tsMock));
    EXPECT_CALL(*mock, rpmtsOpenDB(tsMock, _)).WillOnce(Return(0));
    EXPECT_CALL(*mock, rpmtsRun(tsMock, nullptr, _)).WillOnce(Return(-1));

    EXPECT_THROW(
    {
        try
        {
            RpmPackageManager rpm{mock};

            for (const auto& p : rpm)
            {
            }
        }
        catch (const std::runtime_error& e)
        {
            EXPECT_STREQ(e.what(), "rpmtsRun failed");
            throw;
        }
    }, std::runtime_error);
}

TEST(RpmLibTest, TagDataContainerCreateFailure)
{
    const auto tsMock = reinterpret_cast<rpmts>(0x45);
    auto mock {std::make_shared<NiceMock<RpmLibMock>>()};
    std::vector<RpmPackageManager::Package> packages;
    EXPECT_CALL(*mock, rpmtsCreate()).WillOnce(Return(tsMock));
    EXPECT_CALL(*mock, rpmtsOpenDB(tsMock, _)).WillOnce(Return(0));
    EXPECT_CALL(*mock, rpmtsRun(tsMock, nullptr, _)).WillOnce(Return(0));
    EXPECT_CALL(*mock, rpmtdNew()).WillOnce(nullptr);

    EXPECT_THROW(
    {
        try
        {
            RpmPackageManager rpm{mock};

            for (const auto& p : rpm)
            {
            }
        }
        catch (const std::runtime_error& e)
        {
            EXPECT_STREQ(e.what(), "rpmtdNew failed");
            throw;
        }
    }, std::runtime_error);
}

TEST(RpmLibTest, IteratorInitFailure)
{
    const auto tsMock = reinterpret_cast<rpmts>(0x45);
    const auto tdMock = reinterpret_cast<rpmtd>(0x4D);
    auto mock {std::make_shared<NiceMock<RpmLibMock>>()};
    std::vector<RpmPackageManager::Package> packages;
    EXPECT_CALL(*mock, rpmtsCreate()).WillOnce(Return(tsMock));
    EXPECT_CALL(*mock, rpmtsOpenDB(tsMock, _)).WillOnce(Return(0));
    EXPECT_CALL(*mock, rpmtsRun(tsMock, nullptr, _)).WillOnce(Return(0));
    EXPECT_CALL(*mock, rpmtdNew()).WillOnce(Return(tdMock));
    EXPECT_CALL(*mock, rpmtsInitIterator(tsMock, 1000, _, _)).WillOnce(Return(nullptr));

    EXPECT_THROW(
    {
        try
        {
            RpmPackageManager rpm{mock};

            for (const auto& p : rpm)
            {
            }
        }
        catch (const std::runtime_error& e)
        {
            EXPECT_STREQ(e.what(), "rpmtsInitIterator failed");
            throw;
        }
    }, std::runtime_error);
}

TEST(RpmLibTest, NoPackages)
{
    const auto tsMock = reinterpret_cast<rpmts>(0x45);
    const auto tdMock = reinterpret_cast<rpmtd>(0x4D);
    const auto tsIteratorMock = reinterpret_cast<rpmdbMatchIterator>(0x41);
    auto mock {std::make_shared<NiceMock<RpmLibMock>>()};
    std::vector<RpmPackageManager::Package> packages;
    EXPECT_CALL(*mock, rpmtsCreate()).WillOnce(Return(tsMock));
    EXPECT_CALL(*mock, rpmtsOpenDB(tsMock, O_RDONLY)).WillOnce(Return(0));
    EXPECT_CALL(*mock, rpmtsRun(tsMock, nullptr, _)).WillOnce(Return(0));
    EXPECT_CALL(*mock, rpmtdNew()).WillOnce(Return(tdMock));
    EXPECT_CALL(*mock, rpmtsInitIterator(tsMock, 1000, _, _)).WillOnce(Return(tsIteratorMock));
    EXPECT_CALL(*mock, rpmdbNextIterator(tsIteratorMock)).WillOnce(Return(nullptr));

    EXPECT_CALL(*mock, rpmtsCloseDB(tsMock));
    EXPECT_CALL(*mock, rpmtsFree(tsMock));
    EXPECT_CALL(*mock, rpmtdFree(tdMock));
    EXPECT_CALL(*mock, rpmdbFreeIterator(tsIteratorMock));

    {
        RpmPackageManager rpm{mock};

        for (const auto& p : rpm)
        {
        }
    }
}

TEST(RpmLibTest, SinglePackage)
{
    auto tsMock = reinterpret_cast<rpmts>(0x45);
    auto tdMock = reinterpret_cast<rpmtd>(0x4D);
    auto headerMock = reinterpret_cast<Header>(0xFE);
    auto tsIteratorMock = reinterpret_cast<rpmdbMatchIterator>(0x41);
    auto mock {std::make_shared<NiceMock<RpmLibMock>>()};
    EXPECT_CALL(*mock, rpmtsCreate()).WillOnce(Return(tsMock));
    EXPECT_CALL(*mock, rpmtdNew()).WillOnce(Return(tdMock));
    EXPECT_CALL(*mock, rpmtsRun(tsMock, nullptr, _)).WillOnce(Return(0));
    EXPECT_CALL(*mock, rpmtsInitIterator(tsMock, 1000, _, _)).WillOnce(Return(tsIteratorMock));

    EXPECT_CALL(*mock, rpmdbNextIterator(_)).WillOnce(Return(headerMock)).WillOnce(nullptr);

    EXPECT_CALL(*mock, headerGet(headerMock, _, tdMock, HEADERGET_DEFAULT)).WillRepeatedly(Return(1));
    EXPECT_CALL(*mock, rpmtdGetString(_)).Times(9).WillOnce(Return("name"))
    .WillOnce(Return("version"))
    .WillOnce(Return("release"))
    .WillOnce(Return("summary"))
    .WillOnce(Return("vendor"))
    .WillOnce(Return("group"))
    .WillOnce(Return("source"))
    .WillOnce(Return("arch"))
    .WillOnce(Return("description"));
    EXPECT_CALL(*mock, rpmtdGetNumber(_)).Times(3)
    .WillOnce(Return(1)) // epoch
    .WillOnce(Return(20)) // installtime
    .WillOnce(Return(20)); // size

    std::vector<RpmPackageManager::Package> packages;
    {
        RpmPackageManager rpm{mock};

        for (const auto& p : rpm)
        {
            EXPECT_EQ(p.name, "name");
            EXPECT_EQ(p.release, "release");
            EXPECT_EQ(p.epoch, uint64_t{1});
            EXPECT_EQ(p.summary, "summary");
            EXPECT_EQ(p.installTime, "20");
            EXPECT_EQ(p.size, uint64_t{20});
            EXPECT_EQ(p.vendor, "vendor");
            EXPECT_EQ(p.group, "group");
            EXPECT_EQ(p.source, "source");
            EXPECT_EQ(p.architecture, "arch");
            EXPECT_EQ(p.description, "description");
        }
    }
}

TEST(RpmLibTest, TwoPackages)
{
    auto tsMock = reinterpret_cast<rpmts>(0x45);
    auto tdMock = reinterpret_cast<rpmtd>(0x4D);
    auto headerMock = reinterpret_cast<Header>(0xFE);
    auto tsIteratorMock = reinterpret_cast<rpmdbMatchIterator>(0x41);
    auto mock {std::make_shared<NiceMock<RpmLibMock>>()};
    EXPECT_CALL(*mock, rpmtsCreate()).WillOnce(Return(tsMock));
    EXPECT_CALL(*mock, rpmtdNew()).WillOnce(Return(tdMock));
    EXPECT_CALL(*mock, rpmtsRun(tsMock, nullptr, _)).WillOnce(Return(0));
    EXPECT_CALL(*mock, rpmtsInitIterator(tsMock, 1000, _, _)).WillOnce(Return(tsIteratorMock));

    EXPECT_CALL(*mock, rpmdbNextIterator(_)).WillOnce(Return(headerMock))
    .WillOnce(Return(headerMock))
    .WillOnce(nullptr);

    EXPECT_CALL(*mock, headerGet(headerMock, _, tdMock, HEADERGET_DEFAULT)).WillRepeatedly(Return(1));
    EXPECT_CALL(*mock, rpmtdGetString(_)).Times(18).WillOnce(Return("name"))
    .WillOnce(Return("version"))
    .WillOnce(Return("release"))
    .WillOnce(Return("summary"))
    .WillOnce(Return("vendor"))
    .WillOnce(Return("group"))
    .WillOnce(Return("source"))
    .WillOnce(Return("arch"))
    .WillOnce(Return("description"))
    .WillOnce(Return("name"))
    .WillOnce(Return("version"))
    .WillOnce(Return("release"))
    .WillOnce(Return("summary"))
    .WillOnce(Return("vendor"))
    .WillOnce(Return("group"))
    .WillOnce(Return("source"))
    .WillOnce(Return("arch"))
    .WillOnce(Return("description"));
    EXPECT_CALL(*mock, rpmtdGetNumber(_)).Times(6).WillOnce(Return(1)) // epoch
    .WillOnce(Return(20)) // installtime
    .WillOnce(Return(20)) // size
    .WillOnce(Return(1)) // epoch
    .WillOnce(Return(20)) // installtime
    .WillOnce(Return(20)); // size


    std::vector<RpmPackageManager::Package> packages;
    RpmPackageManager rpm{mock};
    auto count {0};

    for (const auto& p : rpm)
    {
        EXPECT_EQ(p.name, "name");
        EXPECT_EQ(p.release, "release");
        EXPECT_EQ(p.epoch, uint64_t{1});
        EXPECT_EQ(p.summary, "summary");
        EXPECT_EQ(p.installTime, "20");
        EXPECT_EQ(p.size, uint64_t{20});
        EXPECT_EQ(p.vendor, "vendor");
        EXPECT_EQ(p.group, "group");
        EXPECT_EQ(p.source, "source");
        EXPECT_EQ(p.architecture, "arch");
        EXPECT_EQ(p.description, "description");
        count++;
    }

    EXPECT_EQ(count, 2);
}
