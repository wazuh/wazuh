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
    .Times(3)
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(Return(1));
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
    .Times(3)
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(Return(1));
    BerkeleyRpmDBReader reader(dbWrapper);
    EXPECT_TRUE(reader.getNext().empty());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, EmptyTableGetNextPythonFiles)
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
    std::vector<std::string> pythonFiles;
    ASSERT_FALSE(reader.getNextPythonFiles(pythonFiles));
    ASSERT_TRUE(pythonFiles.empty());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, EmptyTableTwoCallsCheckHeaderOmitGetNextPythonFiles)
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
    std::vector<std::string> pythonFiles;
    ASSERT_FALSE(reader.getNextPythonFiles(pythonFiles));
    ASSERT_TRUE(pythonFiles.empty());
    ASSERT_FALSE(reader.getNextPythonFiles(pythonFiles));
    ASSERT_TRUE(pythonFiles.empty());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, NonPythonPackageGetNextPythonFiles)
{
    DBT data, key;
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    char bytes[FIRST_ENTRY_OFFSET + ENTRY_SIZE + 6];
    memset(bytes, 0, sizeof(bytes));
    char* cp;
    int* ip;

    data.data = bytes;
    data.size = sizeof(bytes);

    cp = (char*) bytes;

    // index lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(1);
    cp += 4;

    // Data lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(6);
    cp += 4;

    // Name tag
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

    strcpy(cp, "Wazuh");

    const auto& dbWrapper { std::make_shared<BerkeleyDbWrapperMock>() };
    EXPECT_CALL(*dbWrapper, getRow(_, _))
    .Times(2)
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(1)));

    BerkeleyRpmDBReader reader(dbWrapper);
    std::vector<std::string> pythonFiles;
    ASSERT_FALSE(reader.getNextPythonFiles(pythonFiles));
    ASSERT_TRUE(pythonFiles.empty());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, PythonPackageWithFilesGetNextPythonFiles)
{
    DBT data, key;
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    char bytes[FIRST_ENTRY_OFFSET + ENTRY_SIZE * 4 + 11 + 4 + 4 + 9 + 9 + 10 + 1];
    memset(bytes, 0, sizeof(bytes));
    char* cp;
    int* ip;

    data.data = bytes;
    data.size = sizeof(bytes);

    cp = (char*) bytes;

    // index lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(4);
    cp += 4;

    // Data lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(47);
    cp += 4;

    // Name tag
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

    // dir indexes tag
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(TAG_DIRINDEXES);
    cp += 4;

    // type
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(INT32_TYPE);
    cp += 4;

    //offset
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(11);
    cp += 4;

    // count
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(2);
    cp += 4;

    // basenames tag
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(TAG_BASENAMES);
    cp += 4;

    // type
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(STRING_VECTOR_TYPE);
    cp += 4;

    // offset
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(19);
    cp += 4;

    // count
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(2);
    cp += 4;

    // dirnames tag
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(TAG_DIRNAMES);
    cp += 4;

    // type
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(STRING_VECTOR_TYPE);
    cp += 4;

    // offset
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(37);
    cp += 4;

    // count
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(1);
    cp += 4;

    strcpy(cp, "python-pkg");
    cp += 11;

    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(0);
    cp += 4;

    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(0);
    cp += 4;

    strcpy(cp, "file1.py");
    cp += 9;

    strcpy(cp, "file2.py");
    cp += 9;

    strcpy(cp, "/usr/lib/");
    cp += 10;

    const auto& dbWrapper { std::make_shared<BerkeleyDbWrapperMock>() };
    EXPECT_CALL(*dbWrapper, getRow(_, _))
    .Times(2)
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)));

    BerkeleyRpmDBReader reader(dbWrapper);
    std::vector<std::string> pythonFiles;
    ASSERT_TRUE(reader.getNextPythonFiles(pythonFiles));
    ASSERT_EQ(2u, pythonFiles.size());
    ASSERT_EQ("/usr/lib/file1.py", pythonFiles[0]);
    ASSERT_EQ("/usr/lib/file2.py", pythonFiles[1]);
}

TEST_F(SysInfoPackagesBerkeleyDBTest, PythonPackageNoFilesGetNextPythonFiles)
{
    DBT data, key;
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    char bytes[FIRST_ENTRY_OFFSET + ENTRY_SIZE + 11 + 1];
    memset(bytes, 0, sizeof(bytes));
    char* cp;
    int* ip;

    data.data = bytes;
    data.size = sizeof(bytes);

    cp = (char*) bytes;

    // index lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(1);
    cp += 4;

    // Data lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(11);
    cp += 4;

    // Name tag
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

    strcpy(cp, "python-pkg");

    const auto& dbWrapper { std::make_shared<BerkeleyDbWrapperMock>() };
    EXPECT_CALL(*dbWrapper, getRow(_, _))
    .Times(2)
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)));

    BerkeleyRpmDBReader reader(dbWrapper);
    std::vector<std::string> pythonFiles;
    ASSERT_TRUE(reader.getNextPythonFiles(pythonFiles));
    ASSERT_TRUE(pythonFiles.empty());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, PlatformPythonPackageWithFilesGetNextPythonFiles)
{
    DBT data, key;
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    char bytes[FIRST_ENTRY_OFFSET + ENTRY_SIZE * 4 + 27 + 4 + 4 + 9 + 9 + 10 + 1];
    memset(bytes, 0, sizeof(bytes));
    char* cp;
    int* ip;

    data.data = bytes;
    data.size = sizeof(bytes);

    cp = (char*) bytes;

    // index lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(4);
    cp += 4;

    // Data lenght
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(63);
    cp += 4;

    // Name tag
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

    // dir indexes tag
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(TAG_DIRINDEXES);
    cp += 4;

    // type
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(INT32_TYPE);
    cp += 4;

    //offset
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(27);
    cp += 4;

    // count
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(2);
    cp += 4;

    // basenames tag
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(TAG_BASENAMES);
    cp += 4;

    // type
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(STRING_VECTOR_TYPE);
    cp += 4;

    // offset
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(35);
    cp += 4;

    // count
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(2);
    cp += 4;

    // dirnames tag
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(TAG_DIRNAMES);
    cp += 4;

    // type
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(STRING_VECTOR_TYPE);
    cp += 4;

    // offset
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(53);
    cp += 4;

    // count
    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(1);
    cp += 4;

    strcpy(cp, "platform-python-sample-pkg");
    cp += 27;

    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(0);
    cp += 4;

    ip = (int32_t*)cp;
    *ip = __builtin_bswap32(0);
    cp += 4;

    strcpy(cp, "file1.py");
    cp += 9;

    strcpy(cp, "file2.py");
    cp += 9;

    strcpy(cp, "/usr/lib/");
    cp += 10;

    const auto& dbWrapper { std::make_shared<BerkeleyDbWrapperMock>() };
    EXPECT_CALL(*dbWrapper, getRow(_, _))
    .Times(2)
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)));

    BerkeleyRpmDBReader reader(dbWrapper);
    std::vector<std::string> pythonFiles;
    ASSERT_TRUE(reader.getNextPythonFiles(pythonFiles));
    ASSERT_EQ(2u, pythonFiles.size());
    ASSERT_EQ("/usr/lib/file1.py", pythonFiles[0]);
    ASSERT_EQ("/usr/lib/file2.py", pythonFiles[1]);
}

namespace
{
    struct TestEntry
    {
        int32_t tag;
        int32_t type;
        int32_t offset;
        int32_t count;
    };

    // Zeroed padding follows the record so a read that ignores the data region would still find a NUL.
    std::vector<char> buildRecord(const std::vector<TestEntry>& entries, const std::string& dataRegion)
    {
        std::vector<char> record(FIRST_ENTRY_OFFSET + ENTRY_SIZE * entries.size() + dataRegion.size() + 64, 0);
        auto put = [&record](size_t pos, int32_t value)
        {
            const auto be { __builtin_bswap32(static_cast<uint32_t>(value)) };
            memcpy(record.data() + pos, &be, sizeof(be));
        };

        put(0, static_cast<int32_t>(entries.size()));
        put(4, static_cast<int32_t>(dataRegion.size()));

        size_t pos { FIRST_ENTRY_OFFSET };

        for (const auto& entry : entries)
        {
            put(pos, entry.tag);
            put(pos + 4, entry.type);
            put(pos + 8, entry.offset);
            put(pos + 12, entry.count);
            pos += ENTRY_SIZE;
        }

        memcpy(record.data() + pos, dataRegion.data(), dataRegion.size());
        return record;
    }

    std::shared_ptr<BerkeleyDbWrapperMock> mockRow(std::vector<char>& record, size_t recordSize)
    {
        DBT data, key;
        memset(&key, 0, sizeof(key));
        memset(&data, 0, sizeof(data));
        data.data = record.data();
        data.size = static_cast<u_int32_t>(recordSize);
        const auto dbWrapper { std::make_shared<BerkeleyDbWrapperMock>() };
        EXPECT_CALL(*dbWrapper, getRow(_, _))
        .Times(2)
        .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)))
        .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(data), Return(0)));
        return dbWrapper;
    }

    size_t recordSize(size_t entries, const std::string& dataRegion)
    {
        return FIRST_ENTRY_OFFSET + ENTRY_SIZE * entries + dataRegion.size();
    }
}

TEST_F(SysInfoPackagesBerkeleyDBTest, ValidRecordRegression)
{
    const std::string region { std::string("Wazuh\0", 6) };
    auto record { buildRecord({{TAG_NAME, STRING_TYPE, 0, 1}}, region) };
    BerkeleyRpmDBReader reader(mockRow(record, recordSize(1, region)));
    EXPECT_EQ("Wazuh\t\t\t\t\t\t\t\t\t\t\n", reader.getNext());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, OffsetOutOfRangeIsIgnored)
{
    const std::string region { std::string("Wazuh\0", 6) };
    auto record { buildRecord({{TAG_NAME, STRING_TYPE, 0, 1}, {TAG_ARCH, STRING_TYPE, 1000, 1}}, region) };
    BerkeleyRpmDBReader reader(mockRow(record, recordSize(2, region)));
    EXPECT_EQ("Wazuh\t\t\t\t\t\t\t\t\t\t\n", reader.getNext());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, OffsetEqualToDataSizeIsIgnored)
{
    const std::string region { std::string("Wazuh\0", 6) };
    auto record { buildRecord({{TAG_NAME, STRING_TYPE, 6, 1}}, region) };
    BerkeleyRpmDBReader reader(mockRow(record, recordSize(1, region)));
    EXPECT_EQ("\t\t\t\t\t\t\t\t\t\t\n", reader.getNext());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, NegativeOffsetIsIgnored)
{
    const std::string region { std::string("Wazuh\0", 6) };
    auto record { buildRecord({{TAG_NAME, STRING_TYPE, -4, 1}}, region) };
    BerkeleyRpmDBReader reader(mockRow(record, recordSize(1, region)));
    EXPECT_EQ("\t\t\t\t\t\t\t\t\t\t\n", reader.getNext());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, NegativeDataSizeRecordIsSkippedAndScanContinues)
{
    const std::string region { std::string("Wazuh\0", 6) };
    auto bad { buildRecord({{TAG_NAME, STRING_TYPE, 0, 1}}, region) };
    const auto be { __builtin_bswap32(static_cast<uint32_t>(-1)) };
    memcpy(bad.data() + 4, &be, sizeof(be));
    auto good { buildRecord({{TAG_NAME, STRING_TYPE, 0, 1}}, region) };

    DBT key, badData, goodData;
    memset(&key, 0, sizeof(key));
    memset(&badData, 0, sizeof(badData));
    memset(&goodData, 0, sizeof(goodData));
    badData.data = bad.data();
    badData.size = static_cast<u_int32_t>(recordSize(1, region));
    goodData.data = good.data();
    goodData.size = static_cast<u_int32_t>(recordSize(1, region));

    const auto dbWrapper { std::make_shared<BerkeleyDbWrapperMock>() };
    EXPECT_CALL(*dbWrapper, getRow(_, _))
    .Times(4)
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(badData), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(badData), Return(0)))
    .WillOnce(DoAll(SetArgReferee<0>(key), SetArgReferee<1>(goodData), Return(0)))
    .WillOnce(Return(1));

    BerkeleyRpmDBReader reader(dbWrapper);
    EXPECT_EQ("Wazuh\t\t\t\t\t\t\t\t\t\t\n", reader.getNext());
    EXPECT_TRUE(reader.getNext().empty());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, MissingNulTerminatorIsIgnored)
{
    const std::string region { "Wazuh" };
    auto record { buildRecord({{TAG_NAME, STRING_TYPE, 0, 1}}, region) };
    BerkeleyRpmDBReader reader(mockRow(record, recordSize(1, region)));
    EXPECT_EQ("\t\t\t\t\t\t\t\t\t\t\n", reader.getNext());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, Int32TruncatedByDataRegionIsIgnored)
{
    const std::string region { std::string("Wazuh\0\0\0", 8) };
    auto record { buildRecord({{TAG_SIZE, INT32_TYPE, 6, 1}}, region) };
    BerkeleyRpmDBReader reader(mockRow(record, recordSize(1, region)));
    EXPECT_EQ("\t\t\t\t\t\t\t\t\t\t\n", reader.getNext());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, PythonFilesOffsetOutOfRangeYieldsNoFiles)
{
    const std::string region { std::string("python-pkg\0", 11) };
    auto record { buildRecord({{TAG_NAME, STRING_TYPE, 0, 1}, {TAG_BASENAMES, STRING_VECTOR_TYPE, 5000, 1}}, region) };
    BerkeleyRpmDBReader reader(mockRow(record, recordSize(2, region)));
    std::vector<std::string> pythonFiles;
    ASSERT_TRUE(reader.getNextPythonFiles(pythonFiles));
    ASSERT_TRUE(pythonFiles.empty());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, PythonFilesNegativeOffsetYieldsNoFiles)
{
    const std::string region { std::string("python-pkg\0", 11) };
    auto record { buildRecord({{TAG_NAME, STRING_TYPE, -1, 1}}, region) };
    BerkeleyRpmDBReader reader(mockRow(record, recordSize(1, region)));
    std::vector<std::string> pythonFiles;
    ASSERT_TRUE(reader.getNextPythonFiles(pythonFiles));
    ASSERT_TRUE(pythonFiles.empty());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, PythonFilesOversizedCountYieldsNoFiles)
{
    const std::string region { std::string("python-pkg\0file1.py\0/usr/lib/\0", 30) };
    auto record { buildRecord({{TAG_NAME, STRING_TYPE, 0, 1},
            {TAG_DIRINDEXES, INT32_TYPE, 0, 0x7fffffff},
            {TAG_BASENAMES, STRING_VECTOR_TYPE, 11, 1000},
            {TAG_DIRNAMES, STRING_VECTOR_TYPE, 20, 1}}, region) };
    BerkeleyRpmDBReader reader(mockRow(record, recordSize(4, region)));
    std::vector<std::string> pythonFiles;
    ASSERT_TRUE(reader.getNextPythonFiles(pythonFiles));
    ASSERT_TRUE(pythonFiles.empty());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, PythonFilesNegativeCountYieldsNoFiles)
{
    const std::string region { std::string("python-pkg\0file1.py\0/usr/lib/\0", 30) };
    auto record { buildRecord({{TAG_NAME, STRING_TYPE, 0, 1},
            {TAG_BASENAMES, STRING_VECTOR_TYPE, 11, -1}}, region) };
    BerkeleyRpmDBReader reader(mockRow(record, recordSize(2, region)));
    std::vector<std::string> pythonFiles;
    ASSERT_TRUE(reader.getNextPythonFiles(pythonFiles));
    ASSERT_TRUE(pythonFiles.empty());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, PythonFilesMissingNulYieldsNoFiles)
{
    const std::string region { std::string("python-pkg\0", 11) + "file1.py" };
    auto record { buildRecord({{TAG_NAME, STRING_TYPE, 0, 1},
            {TAG_DIRINDEXES, INT32_TYPE, 0, 0},
            {TAG_BASENAMES, STRING_VECTOR_TYPE, 11, 1}}, region) };
    BerkeleyRpmDBReader reader(mockRow(record, recordSize(3, region)));
    std::vector<std::string> pythonFiles;
    ASSERT_TRUE(reader.getNextPythonFiles(pythonFiles));
    ASSERT_TRUE(pythonFiles.empty());
}

TEST_F(SysInfoPackagesBerkeleyDBTest, PythonFilesMoreDirIndexesThanBasenamesDoesNotOverread)
{
    const std::string region { std::string("python-pkg\0", 11) + std::string("\0\0\0\0\0\0\0\0", 8) + std::string("file1.py\0/usr/lib/\0", 19) };
    auto record { buildRecord({{TAG_NAME, STRING_TYPE, 0, 1},
            {TAG_DIRINDEXES, INT32_TYPE, 11, 2},
            {TAG_BASENAMES, STRING_VECTOR_TYPE, 19, 1},
            {TAG_DIRNAMES, STRING_VECTOR_TYPE, 28, 1}}, region) };
    BerkeleyRpmDBReader reader(mockRow(record, recordSize(4, region)));
    std::vector<std::string> pythonFiles;
    ASSERT_TRUE(reader.getNextPythonFiles(pythonFiles));
    ASSERT_EQ(1u, pythonFiles.size());
    ASSERT_EQ("/usr/lib/file1.py", pythonFiles[0]);
}
