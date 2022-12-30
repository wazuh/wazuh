#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <random>
#include <thread>

#include <gtest/gtest.h>
#include <pthread.h> //For barrier, not strictly necessary

#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>

// TODO: can we move this utility functions to headers accessible to tests and
// benchmark?
static std::string getRandomString(int len, bool includeSymbols = false)
{
    static const char alphanum[] = "0123456789"
                                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz";

    static const char symbols[] = "-_'\\/. *!\"#$%&()+[]{},;";

    std::string tmp_s;
    tmp_s.reserve(len);

    std::string dict = alphanum;
    if (includeSymbols)
    {
        dict += symbols;
    }

    for (int i = 0; i < len; ++i)
    {
        tmp_s += dict[rand() % dict.size()];
    }
    return tmp_s;
}
namespace
{

const std::string KEY {"dummy_key"};
const std::string VALUE {"dummy_value"};
const std::string FILE_PATH {"/tmp/input_file"};
const std::string KVDB_PATH {"/tmp/kvdbTestSuitePath/"};
const std::string kTestDBName {"TEST_DB"};
const std::string kTestDB1Name {"TEST_DB_1"};
const std::string kTestAlternativeDBName {"ALTERNATIVE_TEST_DB"};
const std::string rawValueKeyA {"valueA"};
const std::string valueKeyA {fmt::format("\"{}\"", rawValueKeyA)};
const int rawValueKeyB {69};
const std::string valueKeyB {fmt::format("{}", rawValueKeyB)};
const std::string rawValueKeyCA {"valueCA"};
const std::string rawValueKeyCB {"valueCB"};
const std::string rawValueKeyCC {"valueCC"};
const std::string valueKeyC {
    fmt::format("[\"{}\",\"{}\",\"{}\"]", rawValueKeyCA, rawValueKeyCB, rawValueKeyCC)};
const std::string rawValueKeyDA {"valueDA"};
const int rawValueKeyDB {666};
const int rawValueKeyDC0 {10};
const int rawValueKeyDC1 {7};
const int rawValueKeyDC2 {1992};
const std::string valueKeyD {
    fmt::format("{{\"keyDA\":\"{}\",\"keyDB\":{},\"keyDC\":[{},{},{}]}}",
                rawValueKeyDA,
                rawValueKeyDB,
                rawValueKeyDC0,
                rawValueKeyDC1,
                rawValueKeyDC2)};

inline void createJsonTestFile(const std::string filePath = FILE_PATH)
{
    // File creation
    if (!std::filesystem::exists(FILE_PATH))
    {
        std::ofstream exampleFile(FILE_PATH);
        if (exampleFile.is_open())
        {
            exampleFile << fmt::format("{{\n\t\"keyA\": {},\n\t\"keyB\": {},\n"
                                       "\t\"keyC\": {},\n\t\"keyD\": {}\n}}",
                                       valueKeyA,
                                       valueKeyB,
                                       valueKeyC,
                                       valueKeyD);
            exampleFile.close();
        }
    }
}

class KVDBTest : public ::testing::Test
{

protected:
    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        // cleaning directory in order to start without garbage.
        if (std::filesystem::exists(KVDB_PATH))
        {
            std::filesystem::remove_all(KVDB_PATH);
        }
        kvdbManager = {std::make_shared<kvdb_manager::KVDBManager>(KVDB_PATH)};
        kvdbManager->getHandler(kTestDBName, true);
    };

    virtual void TearDown()
    {
        kvdbManager->unloadDB(kTestDBName);
        kvdbManager->deleteDB(kTestAlternativeDBName);

        if (std::filesystem::exists(FILE_PATH))
        {
            std::filesystem::remove(FILE_PATH);
        }
    };
};

TEST_F(KVDBTest, CreateGetKvdbFile)
{
    auto kvdbAddHandle = kvdbManager->getHandler(kTestDB1Name, true);
    ASSERT_FALSE(std::holds_alternative<base::Error>(kvdbAddHandle));

    kvdb_manager::KVDBHandle kvdbGetHandle;
    ASSERT_NO_THROW(kvdbGetHandle = std::get<kvdb_manager::KVDBHandle>(kvdbAddHandle));
    ASSERT_TRUE(kvdbGetHandle);
    ASSERT_STREQ(kvdbGetHandle->getName().data(), kTestDB1Name.c_str());
    ASSERT_TRUE(kvdbGetHandle->isReady());

    kvdbManager->unloadDB(kTestDB1Name);
}

TEST_F(KVDBTest, DeleteLoadedKvdbFile)
{
    // load the DB a seccond time (emulating function helper)
    auto handler = kvdbManager->getHandler(kTestDBName);
    auto opError = kvdbManager->deleteDB(kTestDBName);
    ASSERT_TRUE(opError.has_value());
    ASSERT_STREQ(
        opError.value().message.c_str(),
        fmt::format("Database '{}' is already in use '1' times", kTestDBName).c_str());
}

TEST_F(KVDBTest, DeleteUnexistentKvdbFile)
{
    auto opError = kvdbManager->deleteDB("UnexistenKVDB");
    ASSERT_TRUE(opError.has_value());
}

TEST_F(KVDBTest, OkDeleteSimple)
{
    auto opError = kvdbManager->deleteDB(kTestDBName);
    ASSERT_FALSE(opError.has_value());
}

TEST_F(KVDBTest, CreateColumn)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    auto res = kvdbManager->getHandler(kTestDBName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdb = std::get<kvdb_manager::KVDBHandle>(res);
    bool retval = kvdb->createColumn(COLUMN_NAME);
    ASSERT_TRUE(retval);
}

TEST_F(KVDBTest, CreateDeleteColumns)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    auto res = kvdbManager->getHandler(kTestDBName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdb = std::get<kvdb_manager::KVDBHandle>(res);
    bool retval = kvdb->createColumn(COLUMN_NAME);
    ASSERT_TRUE(retval);
    retval = kvdb->deleteColumn(COLUMN_NAME);
    ASSERT_TRUE(retval);
    retval = kvdb->deleteColumn(COLUMN_NAME);
    ASSERT_FALSE(retval);
}

TEST_F(KVDBTest, WriteSimple)
{
    auto res = kvdbManager->getHandler(kTestDBName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdbHandle = std::get<kvdb_manager::KVDBHandle>(res);
    ASSERT_TRUE(kvdbHandle);

    bool retval;
    ASSERT_NO_THROW(retval = kvdbHandle->write(KEY, VALUE));
    ASSERT_TRUE(retval);
}

TEST_F(KVDBTest, WriteKeySeveralValueCases)
{
    std::optional<base::Error> writeResult;
    // integer
    json::Json jsonKeyValue {valueKeyB.c_str()};
    ASSERT_NO_THROW(writeResult = kvdbManager->writeKey(kTestDBName, KEY, jsonKeyValue));
    ASSERT_FALSE(writeResult.has_value());

    // array
    json::Json jsonArrayValue {valueKeyC.c_str()};
    ASSERT_NO_THROW(writeResult =
                        kvdbManager->writeKey(kTestDBName, KEY, jsonArrayValue));
    ASSERT_FALSE(writeResult.has_value());

    // object
    json::Json jsonObjectValue {valueKeyD.c_str()};
    ASSERT_NO_THROW(writeResult =
                        kvdbManager->writeKey(kTestDBName, KEY, jsonObjectValue));
    ASSERT_FALSE(writeResult.has_value());
}

TEST_F(KVDBTest, GetJValueSeveralCases)
{
    createJsonTestFile();

    auto resultString = kvdbManager->createFromJFile(kTestDB1Name, FILE_PATH);
    ASSERT_FALSE(resultString.has_value());

    auto val = kvdbManager->getRawValue(kTestDB1Name, "keyA");
    ASSERT_FALSE(std::holds_alternative<base::Error>(val));
    ASSERT_EQ(std::get<std::string>(val), valueKeyA);

    val = kvdbManager->getRawValue(kTestDB1Name, "keyB");
    ASSERT_FALSE(std::holds_alternative<base::Error>(val));
    ASSERT_EQ(std::get<std::string>(val), valueKeyB);

    val = kvdbManager->getRawValue(kTestDB1Name, "keyC");
    ASSERT_FALSE(std::holds_alternative<base::Error>(val));
    ASSERT_EQ(std::get<std::string>(val), valueKeyC);

    val = kvdbManager->getRawValue(kTestDB1Name, "keyD");
    ASSERT_FALSE(std::holds_alternative<base::Error>(val));
    ASSERT_EQ(std::get<std::string>(val), valueKeyD);
}

TEST_F(KVDBTest, ReadWrite)
{
    std::string valueRead;
    bool retval;

    auto res = kvdbManager->getHandler(kTestDBName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdb = std::get<kvdb_manager::KVDBHandle>(res);

    retval = kvdb->write(KEY, VALUE);
    ASSERT_TRUE(retval);

    retval = kvdb->hasKey(KEY);
    ASSERT_TRUE(retval);

    valueRead = std::get<std::string>(kvdb->read(KEY));
    ASSERT_EQ(valueRead, VALUE);

    retval = kvdb->readPinned(KEY, valueRead); // Check this...
    ASSERT_TRUE(retval);
    ASSERT_EQ(valueRead, VALUE);

    auto deleteResult = kvdb->deleteKey(KEY);
    ASSERT_FALSE(deleteResult.has_value());

    retval = kvdb->hasKey(KEY);
    ASSERT_FALSE(retval);

    ASSERT_FALSE(std::holds_alternative<std::string>(kvdb->read(KEY)));

    // it results ok even if the key doesn't exist
    deleteResult = kvdb->deleteKey(KEY);
    ASSERT_FALSE(deleteResult.has_value());

    ASSERT_FALSE(std::holds_alternative<std::string>(kvdb->read(KEY)));

    retval = kvdb->readPinned(KEY, valueRead);
    ASSERT_FALSE(retval);
    ASSERT_FALSE(std::holds_alternative<std::string>(kvdb->read(KEY)));
}

// Key-only write
TEST_F(KVDBTest, KeyOnlyWrite)
{
    bool retval;
    auto res = kvdbManager->getHandler(kTestDBName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdb = std::get<kvdb_manager::KVDBHandle>(res);

    retval = kvdb->hasKey(KEY);
    ASSERT_FALSE(retval);

    retval = kvdb->writeKeyOnly(KEY);
    ASSERT_TRUE(retval);

    retval = kvdb->hasKey(KEY);
    ASSERT_TRUE(retval);

    auto valueRead = kvdb->read(KEY);
    ASSERT_STREQ(std::get<std::string>(kvdb->read(KEY)).c_str(), "");

    auto deleteResult = kvdb->deleteKey(KEY);
    ASSERT_FALSE(deleteResult.has_value());

    retval = kvdb->hasKey(KEY);
    ASSERT_FALSE(retval);
}

TEST_F(KVDBTest, ReadWriteColumn)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    bool retval;

    auto res = kvdbManager->getHandler(kTestDBName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdb = std::get<kvdb_manager::KVDBHandle>(res);

    retval = kvdb->createColumn(COLUMN_NAME);
    ASSERT_TRUE(retval);

    retval = kvdb->write(KEY, VALUE, COLUMN_NAME);
    ASSERT_TRUE(retval);

    auto valueRead = kvdb->read(KEY, COLUMN_NAME);
    ASSERT_EQ(std::get<std::string>(valueRead), VALUE);
}

TEST_F(KVDBTest, Transaction_ok)
{
    std::vector<std::pair<std::string, std::string>> vInput = {{"key1", "value1"},
                                                               {"key2", "value2"},
                                                               {"key3", "value3"},
                                                               {"key4", "value4"},
                                                               {"key5", "value5"}};
    bool retval;

    auto res = kvdbManager->getHandler(kTestDBName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdb = std::get<kvdb_manager::KVDBHandle>(res);
    retval = kvdb->writeToTransaction(vInput);
    ASSERT_TRUE(retval);
    for (auto pair : vInput)
    {
        auto valueRead = kvdb->read(pair.first);
        ASSERT_EQ(std::get<std::string>(valueRead), pair.second);
    }
}

TEST_F(KVDBTest, Transaction_invalid_input)
{
    bool retval;
    auto res = kvdbManager->getHandler(kTestDBName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdb = std::get<kvdb_manager::KVDBHandle>(res);

    // Empty input
    std::vector<std::pair<std::string, std::string>> vEmptyInput = {};
    retval = kvdb->writeToTransaction(vEmptyInput);
    ASSERT_FALSE(retval);

    // Invalid Column name
    std::vector<std::pair<std::string, std::string>> vInput = {{"key1", "value1"}};
    retval = kvdb->writeToTransaction(vInput, "InexistentColumn");
    ASSERT_FALSE(retval);

    // Partial input
    std::vector<std::pair<std::string, std::string>> vPartialInput = {{"", "value1"},
                                                                      {"key2", "value2"}};
    retval = kvdb->writeToTransaction(vPartialInput);
    ASSERT_TRUE(retval);
    auto valueRead = kvdb->read(vPartialInput[1].first);
    ASSERT_EQ(std::get<std::string>(valueRead), vPartialInput[1].second);
}

// TODO Mock DB and create tests for:
//  Txn start error
//  Put error
//  Commit error

TEST_F(KVDBTest, CleanColumn)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    std::string valueRead;
    bool retval;

    auto res = kvdbManager->getHandler(kTestDBName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdb = std::get<kvdb_manager::KVDBHandle>(res);

    // default column
    retval = kvdb->write(KEY, VALUE);
    ASSERT_TRUE(retval);
    valueRead = std::get<std::string>(kvdb->read(KEY));
    ASSERT_EQ(valueRead, VALUE);
    retval = kvdb->cleanColumn();
    ASSERT_TRUE(retval);
    ASSERT_TRUE(std::holds_alternative<base::Error>(kvdb->read(KEY)));

    // custom column
    retval = kvdb->createColumn(COLUMN_NAME);
    ASSERT_TRUE(retval);
    retval = kvdb->write(KEY, VALUE, COLUMN_NAME);
    ASSERT_TRUE(retval);
    valueRead = std::get<std::string>(kvdb->read(KEY, COLUMN_NAME));
    ASSERT_EQ(valueRead, VALUE);
    retval = kvdb->cleanColumn(COLUMN_NAME);
    ASSERT_TRUE(retval);
    ASSERT_TRUE(std::holds_alternative<base::Error>(kvdb->read(KEY, COLUMN_NAME)));
}

TEST_F(KVDBTest, ValueKeyLength)
{
    auto res = kvdbManager->getHandler(kTestDBName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdb = std::get<kvdb_manager::KVDBHandle>(res);
    std::string valueRead;
    std::string valueWrite;
    bool retval;

    valueWrite = getRandomString(128, true);
    retval = kvdb->write(KEY, valueWrite);
    ASSERT_TRUE(retval);
    valueRead = std::get<std::string>(kvdb->read(KEY));
    ASSERT_EQ(valueWrite, valueRead);

    valueWrite = getRandomString(512, true);
    retval = kvdb->write(KEY, valueWrite);
    ASSERT_TRUE(retval);
    valueRead = std::get<std::string>(kvdb->read(KEY));
    ASSERT_EQ(valueWrite, valueRead);

    valueWrite = getRandomString(1024, true);
    retval = kvdb->write(KEY, valueWrite);
    ASSERT_TRUE(retval);
    valueRead = std::get<std::string>(kvdb->read(KEY));
    ASSERT_EQ(valueWrite, valueRead);
}

TEST_F(KVDBTest, ManagerConcurrency)
{
    constexpr static const char* dbName = "test_db";
    constexpr int kMaxTestIterations = 100;

    pthread_barrier_t barrier;
    ASSERT_EQ(0, pthread_barrier_init(&barrier, NULL, 3));

    std::thread create {[&]
                        {
                            auto retval = pthread_barrier_wait(&barrier);
                            EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == retval
                                        || 0 == retval);
                            auto m = kvdbManager;
                            for (int i = 0; i < kMaxTestIterations; ++i)
                            {
                                auto res = m->getHandler(dbName, true);
                            }
                        }};

    std::thread read {[&]
                      {
                          auto retval = pthread_barrier_wait(&barrier);
                          EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == retval
                                      || 0 == retval);
                          auto m = kvdbManager;
                          for (int i = 0; i < kMaxTestIterations; ++i)
                          {
                              auto res = m->getHandler(dbName, false);
                          }
                      }};

    std::thread del {[&]
                     {
                         auto retval = pthread_barrier_wait(&barrier);
                         EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == retval
                                     || 0 == retval);
                         auto m = kvdbManager;
                         for (int i = 0; i < kMaxTestIterations; ++i)
                         {
                             auto res = m->getHandler(dbName);
                             if (std::holds_alternative<kvdb_manager::KVDBHandle>(res))
                             {
                                m->deleteDB(dbName);
                             }
                         }
                     }};

    create.join();
    read.join();
    del.join();
}

TEST_F(KVDBTest, KVDBConcurrency)
{
    constexpr static const char* dbName = "test_db";
    constexpr int kMaxTestIterations = 100;

    pthread_barrier_t barrier;
    ASSERT_EQ(0, pthread_barrier_init(&barrier, NULL, 4));

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution distrib(0, 100);

    kvdbManager->getHandler(dbName, true);

    std::thread create {[&]
                        {
                            auto retval = pthread_barrier_wait(&barrier);
                            EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == retval
                                        || 0 == retval);
                            auto res = kvdbManager->getHandler(dbName);
                            auto& db = std::get<kvdb_manager::KVDBHandle>(res);
                            for (int i = 0; i < kMaxTestIterations; ++i)
                            {
                                db->createColumn(fmt::format("colname.{}", distrib(gen)));
                            }
                        }};

    std::thread write {[&]
                       {
                           auto retval = pthread_barrier_wait(&barrier);
                           EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == retval
                                       || 0 == retval);
                           auto res = kvdbManager->getHandler(dbName);
                           auto& db = std::get<kvdb_manager::KVDBHandle>(res);
                           for (int i = 0; i < kMaxTestIterations; ++i)
                           {
                               db->write(fmt::format("key{}", distrib(gen)),
                                         "value",
                                         fmt::format("colname.{}", distrib(gen)));
                           }
                       }};

    std::thread read {[&]
                      {
                          auto retval = pthread_barrier_wait(&barrier);
                          EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == retval
                                      || 0 == retval);
                          auto res = kvdbManager->getHandler(dbName);
                          auto& db = std::get<kvdb_manager::KVDBHandle>(res);
                          for (int i = 0; i < kMaxTestIterations; ++i)
                          {
                              db->read(fmt::format("key{}", distrib(gen)),
                                       fmt::format("colname.{}", distrib(gen)));
                          }
                      }};

    std::thread del {[&]
                     {
                         auto retval = pthread_barrier_wait(&barrier);
                         EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == retval
                                     || 0 == retval);
                         auto res = kvdbManager->getHandler(dbName);
                         auto& db = std::get<kvdb_manager::KVDBHandle>(res);
                         for (int i = 0; i < kMaxTestIterations; ++i)
                         {
                             db->deleteColumn(fmt::format("colname.{}", distrib(gen)));
                         }
                     }};

    create.join();
    write.join();
    read.join();
    del.join();
    kvdbManager->unloadDB(dbName);
}

TEST_F(KVDBTest, FillDBWithFileCheckContentWithDump)
{
    createJsonTestFile();

    auto resultString = kvdbManager->createFromJFile(kTestDB1Name, FILE_PATH);
    ASSERT_FALSE(resultString.has_value());

    auto kvdbDumpVariant = kvdbManager->jDumpDB(kTestDB1Name);
    ASSERT_FALSE(std::holds_alternative<base::Error>(kvdbDumpVariant));
    ASSERT_TRUE(std::holds_alternative<json::Json>(kvdbDumpVariant));

    // check content
    const auto kvdbContent = std::get<json::Json>(kvdbDumpVariant).getArray();
    ASSERT_TRUE(kvdbContent.has_value());
    ASSERT_EQ(kvdbContent.value().size(), 4);

    ASSERT_TRUE(kvdbContent.value().at(0).getString("/key").has_value());
    ASSERT_STREQ(kvdbContent.value().at(0).getString("/key").value().c_str(), "keyA");
    ASSERT_TRUE(kvdbContent.value().at(1).getString("/key").has_value());
    ASSERT_STREQ(kvdbContent.value().at(1).getString("/key").value().c_str(), "keyB");
    ASSERT_TRUE(kvdbContent.value().at(2).getString("/key").has_value());
    ASSERT_STREQ(kvdbContent.value().at(2).getString("/key").value().c_str(), "keyC");
    ASSERT_TRUE(kvdbContent.value().at(3).getString("/key").has_value());
    ASSERT_STREQ(kvdbContent.value().at(3).getString("/key").value().c_str(), "keyD");

    ASSERT_TRUE(kvdbContent.value().at(0).getString("/value").has_value());
    ASSERT_STREQ(kvdbContent.value().at(0).getString("/value").value().c_str(),
                 rawValueKeyA.c_str());
    ASSERT_TRUE(kvdbContent.value().at(1).getInt("/value").has_value());
    ASSERT_EQ(kvdbContent.value().at(1).getInt("/value").value(), rawValueKeyB);
    ASSERT_TRUE(kvdbContent.value().at(2).getArray("/value").has_value());
    ASSERT_STREQ(kvdbContent.value()
                     .at(2)
                     .getArray("/value")
                     .value()
                     .at(0)
                     .getString()
                     .value_or("value_not_found")
                     .c_str(),
                 rawValueKeyCA.c_str());
    ASSERT_STREQ(kvdbContent.value()
                     .at(2)
                     .getArray("/value")
                     .value()
                     .at(1)
                     .getString()
                     .value_or("value_not_found")
                     .c_str(),
                 rawValueKeyCB.c_str());
    ASSERT_STREQ(kvdbContent.value()
                     .at(2)
                     .getArray("/value")
                     .value()
                     .at(2)
                     .getString()
                     .value_or("value_not_found")
                     .c_str(),
                 rawValueKeyCC.c_str());
    ASSERT_TRUE(kvdbContent.value().at(3).getObject("/value").has_value());
    ASSERT_STREQ(
        std::get<0>(kvdbContent.value().at(3).getObject("/value").value()[0]).c_str(),
        "keyDA");
    ASSERT_STREQ(
        std::get<0>(kvdbContent.value().at(3).getObject("/value").value()[1]).c_str(),
        "keyDB");
    ASSERT_STREQ(
        std::get<0>(kvdbContent.value().at(3).getObject("/value").value()[2]).c_str(),
        "keyDC");
    ASSERT_TRUE(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[0])
                    .getString()
                    .has_value());
    ASSERT_STREQ(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[0])
                     .getString()
                     .value()
                     .c_str(),
                 rawValueKeyDA.c_str());
    ASSERT_TRUE(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[1])
                    .getInt()
                    .has_value());
    ASSERT_EQ(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[1])
                  .getInt()
                  .value(),
              rawValueKeyDB);
    ASSERT_TRUE(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[2])
                    .getArray()
                    .has_value());
    ASSERT_EQ(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[2])
                  .getArray()
                  .value()
                  .at(0)
                  .getInt()
                  .value_or(-1),
              rawValueKeyDC0);
    ASSERT_EQ(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[2])
                  .getArray()
                  .value()
                  .at(1)
                  .getInt()
                  .value_or(-1),
              rawValueKeyDC1);
    ASSERT_EQ(std::get<1>(kvdbContent.value().at(3).getObject("/value").value()[2])
                  .getArray()
                  .value()
                  .at(2)
                  .getInt()
                  .value_or(-1),
              rawValueKeyDC2);
}

TEST_F(KVDBTest, WriteKeySingleKV)
{
    const std::string newTestDBName {"NEW_TEST_DB"};

    auto errorOpt = kvdbManager->createFromJFile(newTestDBName);
    ASSERT_FALSE(errorOpt.has_value());
    auto retval = kvdbManager->writeRaw(newTestDBName, KEY, VALUE);
    ASSERT_FALSE(retval.has_value());

    auto kvdbHandleVariant = kvdbManager->getHandler(newTestDBName);

    ASSERT_FALSE(std::holds_alternative<base::Error>(kvdbHandleVariant));
    kvdb_manager::KVDBHandle kvdbHandle;
    ASSERT_NO_THROW(kvdbHandle = std::get<kvdb_manager::KVDBHandle>(kvdbHandleVariant));
    ASSERT_TRUE(kvdbHandle->hasKey(KEY));
    std::optional<std::string> valueRead;
    ASSERT_NO_THROW(valueRead = std::get<std::string>(kvdbHandle->read(KEY)));
    ASSERT_TRUE(valueRead);
    ASSERT_STREQ(valueRead.value().c_str(), VALUE.c_str());

    // clean to avoid error on rerun
    kvdbManager->unloadDB(newTestDBName);
}

TEST_F(KVDBTest, ListLoadedKVDBs)
{
    auto kvdbLists = kvdbManager->listDBs();
    ASSERT_EQ(kvdbLists.size(), 1);

    auto retval = kvdbManager->getHandler("NEW_DB", true);
    ASSERT_FALSE(std::holds_alternative<base::Error>(retval));
    kvdbLists = kvdbManager->listDBs();
    ASSERT_EQ(kvdbLists.size(), 2);

    retval = kvdbManager->getHandler("NEW_DB_2", true);
    ASSERT_FALSE(std::holds_alternative<base::Error>(retval));
    kvdbLists = kvdbManager->listDBs();
    ASSERT_EQ(kvdbLists.size(), 3);

    kvdbManager->unloadDB("NEW_DB_2");
    kvdbLists = kvdbManager->listDBs();

    ASSERT_EQ(kvdbLists.size(), 2);
    ASSERT_EQ(kvdbLists.at(0), "NEW_DB");
    ASSERT_EQ(kvdbLists.at(1), kTestDBName);

    kvdbManager->unloadDB("NEW_DB");
}

TEST_F(KVDBTest, ListAllKVDBs)
{
    auto kvdbLists = kvdbManager->listDBs();
    ASSERT_EQ(kvdbLists.size(), 1);

    auto errorOpt = kvdbManager->createFromJFile(kTestAlternativeDBName);
    ASSERT_FALSE(errorOpt.has_value());

    kvdbLists = kvdbManager->listDBs(false);
    ASSERT_EQ(kvdbLists.size(), 2);

    kvdbManager->unloadDB(kTestAlternativeDBName);
    kvdbLists = kvdbManager->listDBs(false);
    ASSERT_EQ(kvdbLists.size(), 2);
}

TEST_F(KVDBTest, GetWriteDeleteKeyValueThroughManager)
{
    std::string valueRead, resultValue;

    auto retval = kvdbManager->writeRaw(kTestDBName, KEY, VALUE);
    ASSERT_FALSE(retval.has_value());

    auto errorOpt = kvdbManager->createFromJFile(kTestAlternativeDBName);
    ASSERT_FALSE(errorOpt.has_value());

    retval = kvdbManager->writeRaw(kTestAlternativeDBName, KEY, VALUE);
    ASSERT_FALSE(retval.has_value());

    auto val = kvdbManager->getRawValue(kTestAlternativeDBName, KEY);
    ASSERT_FALSE(std::holds_alternative<base::Error>(val));
    ASSERT_EQ(std::get<std::string>(val), VALUE);

    auto deleteResult = kvdbManager->deleteKey(kTestAlternativeDBName, KEY);
    ASSERT_FALSE(deleteResult.has_value());

    // double delete shouldn't cause error
    deleteResult = kvdbManager->deleteKey(kTestAlternativeDBName, KEY);
    ASSERT_FALSE(deleteResult.has_value());

    auto retOpt = kvdbManager->deleteDB(kTestAlternativeDBName);
    ASSERT_EQ(retOpt, std::nullopt);
}

TEST_F(KVDBTest, GetWriteDeleteSingleKeyThroughManager)
{
    std::string valueRead, resultValue;
    bool retval;

    auto errorOpt = kvdbManager->createFromJFile(kTestAlternativeDBName);
    ASSERT_FALSE(errorOpt.has_value());

    // single key KVDB
    auto retWriteVal = kvdbManager->writeRaw(kTestAlternativeDBName, KEY);
    ASSERT_FALSE(retWriteVal.has_value());

    auto val = kvdbManager->getRawValue(kTestAlternativeDBName, KEY);
    ASSERT_EQ(std::get<std::string>(val), "null");

    auto deleteResult = kvdbManager->deleteKey(kTestAlternativeDBName, KEY);
    ASSERT_FALSE(deleteResult.has_value());

    val = kvdbManager->getRawValue(kTestAlternativeDBName, KEY);
    ASSERT_TRUE(std::holds_alternative<base::Error>(val));
}

TEST_F(KVDBTest, CreateAndFillKVDBfromFile)
{
    auto errorOpt = kvdbManager->createFromJFile(kTestAlternativeDBName);
    ASSERT_FALSE(errorOpt.has_value());

    errorOpt = kvdbManager->createFromJFile(kTestAlternativeDBName);
    ASSERT_STREQ(
        errorOpt.value().message.c_str(),
        fmt::format("Database '{}' already exists", kTestAlternativeDBName).c_str());
}

} // namespace
