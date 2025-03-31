/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "sysInfoPackageLinuxParserRPM_test.hpp"
#include "packages/packageLinuxDataRetriever.h"
#include "packages/berkeleyRpmDbHelper.h"
#include <rpm/header.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#include <db.h>


using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgPointee;
using ::testing::AnyNumber;

class UtilsMock
{
    public:
        MOCK_METHOD(std::string, exec, (const std::string&, const size_t));
        MOCK_METHOD(bool, existsRegular, (const std::string& path));
};

static UtilsMock* gs_utils_mock = NULL;

std::string UtilsWrapperLinux::exec(const std::string& cmd, const size_t bufferSize)
{
    return gs_utils_mock->exec(cmd, bufferSize);
}
bool UtilsWrapperLinux::existsRegular(const std::string& path)
{
    return gs_utils_mock->existsRegular(path);
}

class RpmLibMock
{
    public:
        MOCK_METHOD(int, rpmReadConfigFiles, (const char* file, const char* target));
        MOCK_METHOD(void, rpmFreeRpmrc, ());
        MOCK_METHOD(rpmtd, rpmtdNew, ());
        MOCK_METHOD(rpmtd, rpmtdFree, (rpmtd td));
        MOCK_METHOD(rpmts, rpmtsCreate, ());
        MOCK_METHOD(int, rpmtsOpenDB, (rpmts ts, int dbmode));
        MOCK_METHOD(int, rpmtsCloseDB, (rpmts ts));
        MOCK_METHOD(rpmts, rpmtsFree, (rpmts ts));
        MOCK_METHOD(int, headerGet, (Header h, rpmTagVal tag, rpmtd td, headerGetFlags flags));
        MOCK_METHOD(const char*, rpmtdGetString, (rpmtd td));
        MOCK_METHOD(uint64_t, rpmtdGetNumber, (rpmtd td));
        MOCK_METHOD(int, rpmtsRun, (rpmts ts, rpmps okProbs, rpmprobFilterFlags ignoreSet));
        MOCK_METHOD(rpmdbMatchIterator, rpmtsInitIterator, (const rpmts ts, rpmDbiTagVal rpmtag, const void* keypointer, size_t keylen));
        MOCK_METHOD(Header, rpmdbNextIterator, (rpmdbMatchIterator mi));
        MOCK_METHOD(rpmdbMatchIterator, rpmdbFreeIterator, (rpmdbMatchIterator mi));
        MOCK_METHOD(rpmfi, rpmfiNew, (rpmts ts, Header h, rpmTagVal tag, rpmfiFlags flags));
        MOCK_METHOD(rpm_count_t, rpmfiFC, (rpmfi fi));
        MOCK_METHOD(int, rpmfiNext, (rpmfi fi));
        MOCK_METHOD(const char*, rpmfiFN, (rpmfi fi));
        MOCK_METHOD(rpmfi, rpmfiFree, (rpmfi fi));
};

static RpmLibMock* gs_rpm_mock = NULL;

int rpmReadConfigFiles(const char* file, const char* target)
{
    return gs_rpm_mock->rpmReadConfigFiles(file, target);
}
void rpmFreeRpmrc()
{
    gs_rpm_mock->rpmFreeRpmrc();
}
rpmtd rpmtdNew()
{
    return gs_rpm_mock->rpmtdNew();
}
rpmtd rpmtdFree(rpmtd td)
{
    return gs_rpm_mock->rpmtdFree(td);
}
rpmts rpmtsCreate()
{
    return gs_rpm_mock->rpmtsCreate();
}
int rpmtsOpenDB(rpmts ts, int dbmode)
{
    return gs_rpm_mock->rpmtsOpenDB(ts, dbmode);
}
int rpmtsCloseDB(rpmts ts)
{
    return gs_rpm_mock->rpmtsCloseDB(ts);
}
rpmts rpmtsFree(rpmts ts)
{
    return gs_rpm_mock->rpmtsFree(ts);
}
int headerGet(Header h, rpmTagVal tag, rpmtd td, headerGetFlags flags)
{
    return gs_rpm_mock->headerGet(h, tag, td, flags);
}
const char* rpmtdGetString(rpmtd td)
{
    return gs_rpm_mock->rpmtdGetString(td);
}
uint64_t rpmtdGetNumber(rpmtd td)
{
    return gs_rpm_mock->rpmtdGetNumber(td);
}
int rpmtsRun(rpmts ts, rpmps okProbs, rpmprobFilterFlags ignoreSet)
{
    return gs_rpm_mock->rpmtsRun(ts, okProbs, ignoreSet);
}
rpmdbMatchIterator rpmtsInitIterator(const rpmts ts, rpmDbiTagVal rpmtag, const void* keypointer, size_t keylen)
{
    return gs_rpm_mock->rpmtsInitIterator(ts, rpmtag, keypointer, keylen);
}
Header rpmdbNextIterator(rpmdbMatchIterator mi)
{
    return gs_rpm_mock->rpmdbNextIterator(mi);
}
rpmdbMatchIterator rpmdbFreeIterator(rpmdbMatchIterator mi)
{
    return gs_rpm_mock->rpmdbFreeIterator(mi);
}
rpmfi rpmfiNew(rpmts ts, Header h, rpmTagVal tag, rpmfiFlags flags)
{
    return gs_rpm_mock->rpmfiNew(ts, h, tag, flags);
}
rpm_count_t rpmfiFC(rpmfi fi)
{
    return gs_rpm_mock->rpmfiFC(fi);
}
int rpmfiNext(rpmfi fi)
{
    return gs_rpm_mock->rpmfiNext(fi);
}
const char* rpmfiFN(rpmfi fi)
{
    return gs_rpm_mock->rpmfiFN(fi);
}
rpmfi rpmfiFree(rpmfi fi)
{
    return gs_rpm_mock->rpmfiFree(fi);
}

class LibDBMock
{
    public:
        MOCK_METHOD(int, db_create, (DB**, DB_ENV*, u_int32_t));
        MOCK_METHOD(char*, db_strerror, (int));
        MOCK_METHOD(int, set_lorder, (DB*, int));
        MOCK_METHOD(int, open, (DB*, DB_TXN*, const char*, const char*, DBTYPE, u_int32_t, int));
        MOCK_METHOD(int, cursor, (DB*, DB_TXN*, DBC**, u_int32_t));
        MOCK_METHOD(int, c_get, (DBC*, DBT*, DBT*, u_int32_t));
        MOCK_METHOD(int, c_close, (DBC* cursor));
        MOCK_METHOD(int, close, (DB*, u_int32_t));
};

static LibDBMock* gs_libdb_mock = NULL;

int db_create(DB** dbp, DB_ENV* dbenv, u_int32_t flags)
{
    return gs_libdb_mock->db_create(dbp, dbenv, flags);
}
char* db_strerror(int error)
{
    return gs_libdb_mock->db_strerror(error);
}
int db_set_lorder(DB* dbp, int lorder)
{
    return gs_libdb_mock->set_lorder(dbp, lorder);
}
int db_open(DB* db, DB_TXN* txnid, const char* file, const char* database, DBTYPE type, u_int32_t flags, int mode)
{
    return gs_libdb_mock->open(db, txnid, file, database, type, flags, mode);
}
int db_cursor(DB* db, DB_TXN* txnid, DBC** cursorp, u_int32_t flags)
{
    return gs_libdb_mock->cursor(db, txnid, cursorp, flags);
}
int db_c_get(DBC* cursor, DBT* key, DBT* data, u_int32_t flags)
{
    return gs_libdb_mock->c_get(cursor, key, data, flags);
}
int db_c_close(DBC* cursor)
{
    return gs_libdb_mock->c_close(cursor);
}
int db_close(DB* db, u_int32_t flags)
{
    return gs_libdb_mock->close(db, flags);
}

class CallbackMock
{
    public:
        CallbackMock() = default;
        ~CallbackMock() = default;
        MOCK_METHOD(void, callbackMock, (nlohmann::json&), ());
};

TEST(SysInfoPackageLinuxParserRPM_test, rpmFromBerkleyDB)
{
    CallbackMock wrapper;

    auto expectedPackage1 =
        R"({"architecture":"amd64","description":"The Open Source Security Platform","format":"rpm","groups":"test","install_time":"5","name":"Wazuh","size":321,"vendor":"The Wazuh Team","version":"123:4.4-1","location":" ","priority":" ","source":" "})"_json;

    auto utils_mock { std::make_unique<UtilsMock>() };
    auto libdb_mock { std::make_unique<LibDBMock>() };

    gs_utils_mock = utils_mock.get();
    gs_libdb_mock = libdb_mock.get();

    DB db {};
    DBC cursor {};

    db.set_lorder = db_set_lorder;
    db.open = db_open;
    db.cursor = db_cursor;
    db.close = db_close;
    cursor.c_get = db_c_get;
    cursor.c_close = db_c_close;

    EXPECT_CALL(*utils_mock, existsRegular(_)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*libdb_mock, db_create(_, _, _)).Times(1).WillOnce(DoAll(SetArgPointee<0>(&db), Return(0)));
    EXPECT_CALL(*libdb_mock, set_lorder(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*libdb_mock, open(_, _, _, _, _, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*libdb_mock, cursor(_, _, _, _)).Times(1).WillOnce(DoAll(SetArgPointee<2>(&cursor), Return(0)));

    // Emulate data stored in database

    std::string name { "Wazuh" };
    std::string version { "4.4" };
    std::string release { "1" };
    int epoch { 123 };
    std::string summary { "The Open Source Security Platform" };
    int itime { 5 };
    int size { 321 };
    std::string vendor { "The Wazuh Team" };
    std::string group { "test" };
    std::string source { "github" };
    std::string arch { "amd64" };

    const auto total_fields {11};
    const auto total_fields_len
    {
        (name.length() + version.length() + release.length() + summary.length() + vendor.length() + group.length() + source.length() + arch.length() + 9) +
        (sizeof(epoch) + sizeof(itime) + sizeof(size))
    };

    const auto total_len {FIRST_ENTRY_OFFSET + ENTRY_SIZE* total_fields + total_fields_len + 1};

    DBT data {}, key {};
    char bytes[total_len] {};
    int bytes_count {};

    char* cp;
    int* ip;

    data.data = bytes;
    data.size = total_len;

    cp = bytes;

    auto entry
    {
        [&cp, &bytes_count](int tag, int type, unsigned int len)
        {
            // Name
            int32_t* tmp = reinterpret_cast<int32_t*>(cp);
            *tmp = __builtin_bswap32(tag);
            cp += sizeof(int32_t);
            // type
            tmp = reinterpret_cast<int32_t*>(cp);
            *tmp = __builtin_bswap32(type);
            cp += sizeof(int32_t);
            //offset
            tmp = reinterpret_cast<int32_t*>(cp);
            *tmp = __builtin_bswap32(bytes_count);
            bytes_count += len;
            cp += sizeof(int32_t);
            // unused data
            cp += sizeof(int32_t);
        }
    };


    auto content_string
    {
        [&cp](std::string value)
        {
            strcpy(cp, value.c_str());
            cp += value.length() + 1;
        }
    };
    auto content_int
    {
        [&cp](int value)
        {
            int32_t* tmp = reinterpret_cast<int32_t*>(cp);
            *tmp = __builtin_bswap32(value);
            cp += sizeof(int);
        }
    };


    {
        // Header
        ip = reinterpret_cast<int32_t*>(cp);
        *ip = __builtin_bswap32(total_fields);
        cp += sizeof(int);
        ip = reinterpret_cast<int32_t*>(cp);
        *ip = __builtin_bswap32(total_fields_len);
        cp += sizeof(int);
    }

    entry(TAG_NAME, STRING_TYPE, name.length() + 1);
    entry(TAG_VERSION, STRING_TYPE, version.length() + 1);
    entry(TAG_RELEASE, STRING_TYPE, release.length() + 1);
    entry(TAG_EPOCH, INT32_TYPE, sizeof(epoch));
    entry(TAG_SUMMARY, STRING_TYPE, summary.length() + 1);
    entry(TAG_ITIME, INT32_TYPE, sizeof(itime));
    entry(TAG_SIZE, INT32_TYPE, sizeof(size));
    entry(TAG_VENDOR, STRING_TYPE, vendor.length() + 1);
    entry(TAG_GROUP, STRING_TYPE, group.length() + 1);
    entry(TAG_SOURCE, STRING_TYPE, source.length() + 1);
    entry(TAG_ARCH, STRING_TYPE, arch.length() + 1);

    content_string(name);
    content_string(version);
    content_string(release);
    content_int(epoch);
    content_string(summary);
    content_int(itime);
    content_int(size);
    content_string(vendor);
    content_string(group);
    content_string(source);
    content_string(arch);


    EXPECT_CALL(*libdb_mock, c_get(_, _, _, _)).Times(3)
    .WillOnce(DoAll(SetArgPointee<1>(key), SetArgPointee<2>(data), Return(0)))
    .WillOnce(DoAll(SetArgPointee<1>(key), SetArgPointee<2>(data), Return(0)))
    .WillOnce(Return(1));
    EXPECT_CALL(*libdb_mock, c_close(_)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*libdb_mock, close(_, _)).Times(1).WillOnce(Return(0));


    EXPECT_CALL(wrapper, callbackMock(expectedPackage1)).Times(1);

    getRpmInfo([&wrapper](nlohmann::json & packageInfo)
    {
        wrapper.callbackMock(packageInfo);
    });

}

TEST(SysInfoPackageLinuxParserRPM_test, rpmFromLibRPM)
{
    CallbackMock wrapper;

    auto expectedPackage1 =
        R"({"name":"1","architecture":"2","description":"3","size":4,"version":"5:7-6","vendor":"8","install_time":"9","groups":"10","format":"rpm","location":" ","priority":" ","source":" "})"_json;

    auto utils_mock { std::make_unique<UtilsMock>() };
    auto rpm_mock { std::make_unique<RpmLibMock>() };

    gs_utils_mock = utils_mock.get();
    gs_rpm_mock = rpm_mock.get();
    rpmts ts = (rpmts) 0x123;
    rpmtd td = (rpmtd) 0x123;
    rpmdbMatchIterator mi = (rpmdbMatchIterator) 0x123;
    Header header = (Header) 0x123;

    EXPECT_CALL(*utils_mock, existsRegular(_)).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*rpm_mock, rpmReadConfigFiles(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*rpm_mock, rpmtsCreate()).Times(1).WillOnce(Return(ts));


    EXPECT_CALL(*rpm_mock, rpmtsOpenDB(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*rpm_mock, rpmtsRun(_, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*rpm_mock, rpmtdNew()).Times(1).WillOnce(Return(td));
    EXPECT_CALL(*rpm_mock, rpmtsInitIterator(_, _, _, _)).Times(1).WillOnce(Return(mi));
    EXPECT_CALL(*rpm_mock, rpmdbNextIterator(_)).WillOnce(Return(header)).WillOnce(Return(nullptr));
    EXPECT_CALL(*rpm_mock, rpmtsCloseDB(_)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*rpm_mock, rpmtsFree(_)).Times(1).WillOnce(Return(nullptr));
    EXPECT_CALL(*rpm_mock, rpmtdFree(_)).Times(1).WillOnce(Return(nullptr));
    EXPECT_CALL(*rpm_mock, rpmdbFreeIterator(_)).Times(1).WillOnce(Return(nullptr));
    EXPECT_CALL(*rpm_mock, rpmFreeRpmrc());

    EXPECT_CALL(*rpm_mock, headerGet(_, _, _, _)).Times(AnyNumber()).WillRepeatedly(Return(1));

    EXPECT_CALL(*rpm_mock, rpmtdGetString(_)) \
    .WillOnce(Return("1")) \
    .WillOnce(Return("7")) \
    .WillOnce(Return("6")) \
    .WillOnce(Return("summary")) \
    .WillOnce(Return("8")) \
    .WillOnce(Return("10")) \
    .WillOnce(Return("source")) \
    .WillOnce(Return("2")) \
    .WillOnce(Return("3"));
    EXPECT_CALL(*rpm_mock, rpmtdGetNumber(_)).WillOnce(Return(5)).WillOnce(Return(9)).WillOnce(Return(4));


    EXPECT_CALL(wrapper, callbackMock(expectedPackage1)).Times(1);

    getRpmInfo([&wrapper](nlohmann::json & data)
    {
        wrapper.callbackMock(data);
    });

}

TEST(SysInfoPackageLinuxParserRPM_test, rpmFallbackFromLibRPM)
{
    CallbackMock wrapper;

    auto expectedPackage1 =
        R"({"name":"1","architecture":"2","description":"3","size":4,"version":"5:7-6","vendor":"8","install_time":"9","groups":"10","format":"rpm","location":" ","priority":" ","source":" "})"_json;
    auto expectedPackage2 =
        R"({"name":"11","architecture":"12","description":"13","size":14,"version":"15:17-16","vendor":"18","install_time":"19","groups":"20","format":"rpm","location":" ","priority":" ","source":" "})"_json;

    auto utils_mock { std::make_unique<UtilsMock>() };
    auto rpm_mock { std::make_unique<RpmLibMock>() };

    gs_utils_mock = utils_mock.get();
    gs_rpm_mock = rpm_mock.get();

    EXPECT_CALL(*utils_mock, existsRegular(_)).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*rpm_mock, rpmReadConfigFiles(_, _)).Times(1).WillOnce(Return(1));
    EXPECT_CALL(*utils_mock, exec(_, _)).Times(1).WillOnce(Return("1\t2\t3\t4\t5\t6\t7\t8\t9\t10\t\n11\t12\t13\t14\t15\t16\t17\t18\t19\t20\t\n"));
    EXPECT_CALL(wrapper, callbackMock(expectedPackage1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedPackage2)).Times(1);

    getRpmInfo([&wrapper](nlohmann::json & data)
    {
        wrapper.callbackMock(data);
    });

}

TEST(SysInfoPackageLinuxParserRPM_test, rpmFallbackFromBerkleyDBConfigError)
{
    CallbackMock wrapper;

    auto expectedPackage1 =
        R"({"name":"1","architecture":"2","description":"3","size":4,"version":"5:7-6","vendor":"8","install_time":"9","groups":"10","format":"rpm","location":" ","priority":" ","source":" "})"_json;
    auto expectedPackage2 =
        R"({"name":"11","architecture":"12","description":"13","size":14,"version":"15:17-16","vendor":"18","install_time":"19","groups":"20","format":"rpm","location":" ","priority":" ","source":" "})"_json;

    auto utils_mock { std::make_unique<UtilsMock>() };
    auto libdb_mock { std::make_unique<LibDBMock>() };

    gs_utils_mock = utils_mock.get();
    gs_libdb_mock = libdb_mock.get();

    EXPECT_CALL(*utils_mock, existsRegular(_)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*libdb_mock, db_create(_, _, _)).Times(1).WillOnce(Return(1));
    EXPECT_CALL(*libdb_mock, db_strerror(_)).Times(1).WillOnce(Return(const_cast<char*>("test")));
    EXPECT_CALL(*utils_mock, exec(_, _)).Times(1).WillOnce(Return("1\t2\t3\t4\t5\t6\t7\t8\t9\t10\t\n11\t12\t13\t14\t15\t16\t17\t18\t19\t20\t\n"));
    EXPECT_CALL(wrapper, callbackMock(expectedPackage1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedPackage2)).Times(1);

    getRpmInfo([&wrapper](nlohmann::json & data)
    {
        wrapper.callbackMock(data);
    });

}

TEST(SysInfoPackageLinuxParserRPM_test, rpmFallbackFromBerkleyDBOpenError)
{
    CallbackMock wrapper;

    auto expectedPackage1 =
        R"({"name":"1","architecture":"2","description":"3","size":4,"version":"5:7-6","vendor":"8","install_time":"9","groups":"10","format":"rpm","location":" ","priority":" ","source":" "})"_json;
    auto expectedPackage2 =
        R"({"name":"11","architecture":"12","description":"13","size":14,"version":"15:17-16","vendor":"18","install_time":"19","groups":"20","format":"rpm","location":" ","priority":" ","source":" "})"_json;

    auto utils_mock { std::make_unique<UtilsMock>() };
    auto libdb_mock { std::make_unique<LibDBMock>() };

    gs_utils_mock = utils_mock.get();
    gs_libdb_mock = libdb_mock.get();

    DB db {};

    db.set_lorder = db_set_lorder;
    db.open = db_open;
    db.close = db_close;

    EXPECT_CALL(*utils_mock, existsRegular(_)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*libdb_mock, db_create(_, _, _)).Times(1).WillOnce(DoAll(SetArgPointee<0>(&db), Return(0)));
    EXPECT_CALL(*libdb_mock, set_lorder(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*libdb_mock, open(_, _, _, _, _, _, _)).Times(1).WillOnce(Return(1));
    EXPECT_CALL(*libdb_mock, db_strerror(_)).Times(1).WillOnce(Return(const_cast<char*>("test")));
    EXPECT_CALL(*libdb_mock, close(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*utils_mock, exec(_, _)).Times(1).WillOnce(Return("1\t2\t3\t4\t5\t6\t7\t8\t9\t10\t\n11\t12\t13\t14\t15\t16\t17\t18\t19\t20\t\n"));
    EXPECT_CALL(wrapper, callbackMock(expectedPackage1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedPackage2)).Times(1);

    getRpmInfo([&wrapper](nlohmann::json & data)
    {
        wrapper.callbackMock(data);
    });

}

TEST(SysInfoPackageLinuxParserRPM_test, rpmFallbackFromBerkleyDBCursorError)
{
    CallbackMock wrapper;

    auto expectedPackage1 =
        R"({"name":"1","architecture":"2","description":"3","size":4,"version":"5:7-6","vendor":"8","install_time":"9","groups":"10","format":"rpm","location":" ","priority":" ","source":" "})"_json;
    auto expectedPackage2 =
        R"({"name":"11","architecture":"12","description":"13","size":14,"version":"15:17-16","vendor":"18","install_time":"19","groups":"20","format":"rpm","location":" ","priority":" ","source":" "})"_json;

    auto utils_mock { std::make_unique<UtilsMock>() };
    auto libdb_mock { std::make_unique<LibDBMock>() };

    gs_utils_mock = utils_mock.get();
    gs_libdb_mock = libdb_mock.get();

    DB db {};

    db.set_lorder = db_set_lorder;
    db.open = db_open;
    db.close = db_close;
    db.cursor = db_cursor;

    EXPECT_CALL(*utils_mock, existsRegular(_)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*libdb_mock, db_create(_, _, _)).Times(1).WillOnce(DoAll(SetArgPointee<0>(&db), Return(0)));
    EXPECT_CALL(*libdb_mock, set_lorder(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*libdb_mock, open(_, _, _, _, _, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*libdb_mock, cursor(_, _, _, _)).Times(1).WillOnce(Return(1));
    EXPECT_CALL(*libdb_mock, db_strerror(_)).Times(1).WillOnce(Return(const_cast<char*>("test")));
    EXPECT_CALL(*libdb_mock, close(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*utils_mock, exec(_, _)).Times(1).WillOnce(Return("1\t2\t3\t4\t5\t6\t7\t8\t9\t10\t\n11\t12\t13\t14\t15\t16\t17\t18\t19\t20\t\n"));
    EXPECT_CALL(wrapper, callbackMock(expectedPackage1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedPackage2)).Times(1);

    getRpmInfo([&wrapper](nlohmann::json & data)
    {
        wrapper.callbackMock(data);
    });

}

TEST(SysInfoPackageLinuxParserRPM_test, emptyRpmFallback)
{
    CallbackMock wrapper;

    auto utils_mock { std::make_unique<UtilsMock>() };
    auto rpm_mock { std::make_unique<RpmLibMock>() };

    gs_utils_mock = utils_mock.get();
    gs_rpm_mock = rpm_mock.get();

    EXPECT_CALL(*utils_mock, existsRegular(_)).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*rpm_mock, rpmReadConfigFiles(_, _)).Times(1).WillOnce(Return(1));
    EXPECT_CALL(*utils_mock, exec(_, _)).Times(1).WillOnce(Return(""));
    EXPECT_CALL(wrapper, callbackMock(_)).Times(0);

    getRpmInfo([&wrapper](nlohmann::json & data)
    {
        wrapper.callbackMock(data);
    });
}

TEST(SysInfoPackageLinuxParserRPM_test, invalidPackageParsingRpmFallback)
{
    CallbackMock wrapper;

    auto utils_mock { std::make_unique<UtilsMock>() };
    auto rpm_mock { std::make_unique<RpmLibMock>() };
    auto libdb_mock { std::make_unique<LibDBMock>() };

    gs_utils_mock = utils_mock.get();
    gs_rpm_mock = rpm_mock.get();

    EXPECT_CALL(*utils_mock, existsRegular(_)).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*rpm_mock, rpmReadConfigFiles(_, _)).Times(1).WillOnce(Return(1));
    EXPECT_CALL(*utils_mock, exec(_, _)).Times(1).WillOnce(Return("this is not a valid rpm -qa output"));
    EXPECT_CALL(wrapper, callbackMock(_)).Times(0);

    getRpmInfo([&wrapper](nlohmann::json & data)
    {
        wrapper.callbackMock(data);
    });
}
