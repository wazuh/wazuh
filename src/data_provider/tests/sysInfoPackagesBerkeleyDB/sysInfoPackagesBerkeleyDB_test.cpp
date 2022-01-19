/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * March 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysInfoPackagesBerkeleyDB_test.h"
#include "packages/berkeleyRpmDbHelper.h"

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgReferee;

void SysInfoPackagesBerkeleyDBTest::SetUp() {};
void SysInfoPackagesBerkeleyDBTest::TearDown() {};

class BerkeleyDbWrapperMock final : public IBerkeleyDbWrapper
{
    public:
        BerkeleyDbWrapperMock() = default;
        virtual ~BerkeleyDbWrapperMock() = default;
        MOCK_METHOD(int32_t, getRow, (DBT& key, DBT& data), (override));
};

TEST_F(SysInfoPackagesBerkeleyDBTest, EmptyTable)
{
    DBT data, key;
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    const auto& dbWrapper { std::make_shared<BerkeleyDbWrapperMock>() };
    EXPECT_CALL(*dbWrapper, getRow(_, _))
    .Times(2)
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(1)));
    BerkeleyRpmDBReader reader(dbWrapper);
    reader.getNext();
}

TEST_F(SysInfoPackagesBerkeleyDBTest, EmptyTableTwoCallsCheckHeaderOmit)
{
    DBT data, key;
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    const auto& dbWrapper { std::make_shared<BerkeleyDbWrapperMock>() };
    EXPECT_CALL(*dbWrapper, getRow(_, _))
    .Times(3)
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(1)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(1)));
    BerkeleyRpmDBReader reader(dbWrapper);
    reader.getNext();
    reader.getNext();
}

TEST_F(SysInfoPackagesBerkeleyDBTest, TableTwoCallsCheckOutput)
{
    DBT data, key;
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    char bytes[FIRST_ENTRY_OFFSET + ENTRY_SIZE * 3 + 6 + 13 + 4 + 1];
    memset(bytes, 0, sizeof(bytes));
    char* cp;
    int* ip;

    data.data = bytes;
    data.size = FIRST_ENTRY_OFFSET + ENTRY_SIZE * 3 + 6 + 13 + 4;

    cp = (char*) bytes;

    // index lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(3);
    cp += 4;

    // Data lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(23);
    cp += 4;

    // Name
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(TAG_NAME);
    cp += 4;

    // type
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(STRING_TYPE);
    cp += 4;

    //offset
    ip = (int32_t*)cp;
    *ip = 0;
    cp += 4;

    // unused data
    cp += 4;

    // Description
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(TAG_SUMMARY);
    cp += 4;

    // type
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(STRING_VECTOR_TYPE);
    cp += 4;

    //offset
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(6);
    cp += 4;

    cp += 4;

    // size
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(TAG_SIZE);
    cp += 4;

    // type
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(INT32_TYPE);
    cp += 4;

    //offset
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(19);
    cp += 4;

    cp += 4;

    strcpy(cp, "Wazuh");
    cp += 6;

    strcpy(cp, "The Best EDR");
    cp += 13;

    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(1);
    cp += 4;

    const auto& dbWrapper { std::make_shared<BerkeleyDbWrapperMock>() };
    EXPECT_CALL(*dbWrapper, getRow(_, _))
    .Times(2)
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)));
    BerkeleyRpmDBReader reader(dbWrapper);
    EXPECT_EQ("Wazuh\t\tThe Best EDR\t1\t\t\t\t\t\t\t\n", reader.getNext());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, TableTwoCallsCheckOutputWithMissingTag)
{
    DBT data, key;
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    char bytes[FIRST_ENTRY_OFFSET + ENTRY_SIZE * 3 + 6 + 13 + 4 + 1];
    memset(bytes, 0, sizeof(bytes));
    char* cp;
    int* ip;

    data.data = bytes;
    data.size = FIRST_ENTRY_OFFSET + ENTRY_SIZE * 3 + 6 + 13 + 4;

    cp = (char*) bytes;

    // index lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(3);
    cp += 4;

    // Data lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(23);
    cp += 4;

    // Name
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(TAG_NAME);
    cp += 4;

    // type
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(STRING_TYPE);
    cp += 4;

    //offset
    ip = (int32_t*)cp;
    *ip = 0;
    cp += 4;

    // unused data
    cp += 4;

    // Description
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(0);
    cp += 4;

    // type
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(STRING_TYPE);
    cp += 4;

    //offset
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(6);
    cp += 4;

    cp += 4;

    // size
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(TAG_SIZE);
    cp += 4;

    // type
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(INT32_TYPE);
    cp += 4;

    //offset
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(19);
    cp += 4;

    cp += 4;

    strcpy(cp, "Wazuh");
    cp += 6;

    strcpy(cp, "The Best EDR");
    cp += 13;

    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(1);
    cp += 4;

    const auto& dbWrapper { std::make_shared<BerkeleyDbWrapperMock>() };
    EXPECT_CALL(*dbWrapper, getRow(_, _))
    .Times(2)
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)));
    BerkeleyRpmDBReader reader(dbWrapper);
    EXPECT_EQ("Wazuh\t\t\t1\t\t\t\t\t\t\t\n", reader.getNext());
}


TEST_F(SysInfoPackagesBerkeleyDBTest, TableTwoCallsCheckOutputNoHeader)
{
    DBT data, key;
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    data.data = nullptr;
    data.size = 4;

    const auto& dbWrapper { std::make_shared<BerkeleyDbWrapperMock>() };
    EXPECT_CALL(*dbWrapper, getRow(_, _))
    .Times(2)
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)));
    BerkeleyRpmDBReader reader(dbWrapper);
    EXPECT_TRUE(reader.getNext().empty());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, TableTwoCallsCheckOutputHeaderWithNoData)
{
    DBT data, key;
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    char bytes[FIRST_ENTRY_OFFSET + 1];
    memset(bytes, 0, sizeof(bytes));
    char* cp;
    int* ip;

    data.data = bytes;
    data.size = 8;

    cp = (char*) bytes;

    // index lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(3);
    cp += 4;

    // Data lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(23);
    cp += 4;

    const auto& dbWrapper { std::make_shared<BerkeleyDbWrapperMock>() };
    EXPECT_CALL(*dbWrapper, getRow(_, _))
    .Times(2)
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)));
    BerkeleyRpmDBReader reader(dbWrapper);
    EXPECT_TRUE(reader.getNext().empty());
}
