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
const std::string kTestUnloadedDBName {"UNLOADED_TEST_DB"};

class KVDBTest : public ::testing::Test
{

protected:
    std::shared_ptr<KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        // cleaning directory in order to start without garbage.
        if (std::filesystem::exists(KVDB_PATH))
        {
            std::filesystem::remove_all(KVDB_PATH);
        }
        kvdbManager = {std::make_shared<KVDBManager>(KVDB_PATH)};
        kvdbManager->loadDB(kTestDBName);
    };

    virtual void TearDown()
    {
        kvdbManager->unloadDB(kTestDBName);
        kvdbManager->deleteDB(kTestUnloadedDBName);

        if (std::filesystem::exists(FILE_PATH))
        {
            std::filesystem::remove(FILE_PATH);
        }
    };
};

TEST_F(KVDBTest, CreateGetDeleteKvdbFile)
{
    KVDBHandle kvdbAddHandle;
    ASSERT_NO_THROW(kvdbAddHandle = kvdbManager->loadDB("TEST_DB_1"));
    ASSERT_TRUE(kvdbAddHandle);

    KVDBHandle kvdbGetHandle;
    ASSERT_NO_THROW(kvdbGetHandle = kvdbManager->getDB("TEST_DB_1"));
    ASSERT_TRUE(kvdbGetHandle);
    ASSERT_STREQ(kvdbGetHandle->getName().data(), "TEST_DB_1");
    ASSERT_TRUE(kvdbGetHandle->isReady());

    ASSERT_TRUE(kvdbManager->unloadDB("TEST_DB_1"));
    KVDBHandle kvdbDeleteHandle;
    ASSERT_NO_THROW(kvdbDeleteHandle = kvdbManager->getDB("TEST_DB_1"));
    ASSERT_EQ(kvdbDeleteHandle, nullptr);
}

TEST_F(KVDBTest, CreateColumn)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    auto kvdb = kvdbManager->getDB(kTestDBName);
    bool retval = kvdb->createColumn(COLUMN_NAME);
    ASSERT_TRUE(retval);
}

TEST_F(KVDBTest, CreateDeleteColumns)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    auto kvdb = kvdbManager->getDB(kTestDBName);
    bool retval = kvdb->createColumn(COLUMN_NAME);
    ASSERT_TRUE(retval);
    retval = kvdb->deleteColumn(COLUMN_NAME);
    ASSERT_TRUE(retval);
    retval = kvdb->deleteColumn(COLUMN_NAME);
    ASSERT_FALSE(retval);
}

TEST_F(KVDBTest, write)
{
    KVDBHandle kvdbHandle;
    ASSERT_NO_THROW(kvdbHandle = kvdbManager->getDB(kTestDBName));
    ASSERT_TRUE(kvdbHandle);

    bool retval;
    ASSERT_NO_THROW(retval = kvdbHandle->write("dummy_key", "dummy_value"));
    ASSERT_TRUE(retval);
}

TEST_F(KVDBTest, ReadWrite)
{
    std::string valueRead;
    bool retval;

    auto kvdb = kvdbManager->getDB(kTestDBName);

    retval = kvdb->write(KEY, VALUE);
    ASSERT_TRUE(retval);

    retval = kvdb->hasKey(KEY);
    ASSERT_TRUE(retval);

    valueRead = kvdb->read(KEY).value();
    ASSERT_EQ(valueRead, VALUE);

    retval = kvdb->readPinned(KEY, valueRead); // Check this...
    ASSERT_TRUE(retval);
    ASSERT_EQ(valueRead, VALUE);

    retval = kvdb->deleteKey(KEY);
    ASSERT_TRUE(retval);

    retval = kvdb->hasKey(KEY);
    ASSERT_FALSE(retval);

    ASSERT_FALSE(kvdb->read(KEY).has_value());

    // it returns true even if the key doesn't exist
    retval = kvdb->deleteKey(KEY);
    ASSERT_TRUE(retval);

    ASSERT_FALSE(kvdb->read(KEY).has_value());

    retval = kvdb->readPinned(KEY, valueRead);
    ASSERT_FALSE(retval);
    ASSERT_FALSE(kvdb->read(KEY).has_value());
}

// Key-only write
TEST_F(KVDBTest, KeyOnlyWrite)
{
    // TODO Update FH tests too
    bool retval;
    auto kvdb = kvdbManager->getDB(kTestDBName);

    retval = kvdb->hasKey(KEY);
    ASSERT_FALSE(retval);

    retval = kvdb->writeKeyOnly(KEY);
    ASSERT_TRUE(retval);

    retval = kvdb->hasKey(KEY);
    ASSERT_TRUE(retval);

    auto valueRead = kvdb->read(KEY);
    ASSERT_TRUE(valueRead.value().empty());

    retval = kvdb->deleteKey(KEY);
    ASSERT_TRUE(retval);

    retval = kvdb->hasKey(KEY);
    ASSERT_FALSE(retval);
}

TEST_F(KVDBTest, ReadWriteColumn)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    std::string valueRead;
    bool retval;

    auto kvdb = kvdbManager->getDB(kTestDBName);

    retval = kvdb->createColumn(COLUMN_NAME);
    ASSERT_TRUE(retval);

    retval = kvdb->write(KEY, VALUE, COLUMN_NAME);
    ASSERT_TRUE(retval);

    valueRead = kvdb->read(KEY, COLUMN_NAME).value();
    ASSERT_EQ(valueRead, VALUE);
}

TEST_F(KVDBTest, Transaction_ok)
{
    std::vector<std::pair<std::string, std::string>> vInput = {{"key1", "value1"},
                                                               {"key2", "value2"},
                                                               {"key3", "value3"},
                                                               {"key4", "value4"},
                                                               {"key5", "value5"}};
    bool retval;

    auto kvdb = kvdbManager->getDB(kTestDBName);
    retval = kvdb->writeToTransaction(vInput);
    ASSERT_TRUE(retval);
    for (auto pair : vInput)
    {
        std::string valueRead = kvdb->read(pair.first).value();
        ASSERT_EQ(valueRead, pair.second);
    }
}

TEST_F(KVDBTest, Transaction_invalid_input)
{
    bool retval;
    auto kvdb = kvdbManager->getDB(kTestDBName);

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
    std::string valueRead = kvdb->read(vPartialInput[1].first).value();
    ASSERT_EQ(valueRead, vPartialInput[1].second);
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

    auto kvdb = kvdbManager->getDB(kTestDBName);

    // default column
    retval = kvdb->write(KEY, VALUE);
    ASSERT_TRUE(retval);
    valueRead = kvdb->read(KEY).value();
    ASSERT_EQ(valueRead, VALUE);
    retval = kvdb->cleanColumn();
    ASSERT_TRUE(retval);
    ASSERT_FALSE(kvdb->read(KEY).has_value());

    // custom column
    retval = kvdb->createColumn(COLUMN_NAME);
    ASSERT_TRUE(retval);
    retval = kvdb->write(KEY, VALUE, COLUMN_NAME);
    ASSERT_TRUE(retval);
    valueRead = kvdb->read(KEY, COLUMN_NAME).value();
    ASSERT_EQ(valueRead, VALUE);
    retval = kvdb->cleanColumn(COLUMN_NAME);
    ASSERT_TRUE(retval);
    ASSERT_FALSE(kvdb->read(KEY, COLUMN_NAME).has_value());
}

TEST_F(KVDBTest, ValueKeyLength)
{
    auto kvdb = kvdbManager->getDB(kTestDBName);
    std::string valueRead;
    std::string valueWrite;
    bool retval;

    valueWrite = getRandomString(128, true);
    retval = kvdb->write(KEY, valueWrite);
    ASSERT_TRUE(retval);
    valueRead = kvdb->read(KEY).value();
    ASSERT_EQ(valueWrite, valueRead);

    valueWrite = getRandomString(512, true);
    retval = kvdb->write(KEY, valueWrite);
    ASSERT_TRUE(retval);
    valueRead = kvdb->read(KEY).value();
    ASSERT_EQ(valueWrite, valueRead);

    valueWrite = getRandomString(1024, true);
    retval = kvdb->write(KEY, valueWrite);
    ASSERT_TRUE(retval);
    valueRead = kvdb->read(KEY).value();
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
                                auto db = m->getDB(dbName);
                                if (db && !db->isValid())
                                {
                                    m->loadDB(dbName);
                                }
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
                              auto db = m->getDB(dbName);
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
                             auto db = m->getDB(dbName);
                             if (db && db->isValid())
                             {
                                 m->unloadDB(dbName);
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

    kvdbManager->loadDB(dbName);

    std::thread create {[&]
                        {
                            auto retval = pthread_barrier_wait(&barrier);
                            EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == retval
                                        || 0 == retval);
                            auto db = kvdbManager->getDB(dbName);
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
                           auto db = kvdbManager->getDB(dbName);
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
                          auto db = kvdbManager->getDB(dbName);
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
                         auto db = kvdbManager->getDB(dbName);
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

// TODO: fill test
TEST_F(KVDBTest, dumpContent)
{
    // create a json
    // save it in a file on a specific directory
    // create a DB with this path
    // dump it with method and compare

    // json can have multiple formats, look in
    //  /wazuh/src/engine/test/kvdb_input_files
}

TEST_F(KVDBTest, writeKeySingleKV)
{
    const std::string key {"dummy_key"};
    const std::string value {"dummy_value"};

    std::string resultValue;
    ASSERT_NO_THROW(resultValue = kvdbManager->CreateAndFillDBfromFile("NEW_TEST_DB"));
    ASSERT_STREQ(resultValue.c_str(), "OK");
    bool retval;
    ASSERT_NO_THROW(retval = kvdbManager->writeKey("NEW_TEST_DB", key, value));
    ASSERT_TRUE(retval);

    // TODO: this replicates what the helper does and should be improved
    KVDBHandle kvdbHandle;
    kvdbHandle = kvdbManager->getDB("NEW_TEST_DB");
    if (!kvdbHandle)
    {
        ASSERT_NO_THROW(kvdbManager->loadDB("NEW_TEST_DB", false));
    }
    kvdbHandle = kvdbManager->getDB("NEW_TEST_DB");
    ASSERT_TRUE(kvdbHandle);
    ASSERT_TRUE(kvdbHandle->hasKey(key));
    std::optional<std::string> valueRead;
    ASSERT_NO_THROW(valueRead = kvdbHandle->read(key));
    ASSERT_TRUE(valueRead);
    ASSERT_STREQ(valueRead.value().c_str(), value.c_str());

    // clean to avoid error on rerun
    ASSERT_NO_THROW(retval = kvdbManager->unloadDB("NEW_TEST_DB"));
    ASSERT_TRUE(retval);
}

TEST_F(KVDBTest, ListLoadedKVDBs)
{
    auto kvdbLists = kvdbManager->listDBs();
    ASSERT_EQ(kvdbLists.size(), 1);

    auto retval = kvdbManager->loadDB("NEW_DB");
    ASSERT_TRUE(retval);
    kvdbLists = kvdbManager->listDBs();
    ASSERT_EQ(kvdbLists.size(), 2);

    retval = kvdbManager->loadDB("NEW_DB_2");
    ASSERT_TRUE(retval);
    kvdbLists = kvdbManager->listDBs();
    ASSERT_EQ(kvdbLists.size(), 3);

    ASSERT_TRUE(kvdbManager->unloadDB("NEW_DB_2"));
    kvdbLists = kvdbManager->listDBs();

    ASSERT_EQ(kvdbLists.size(), 2);
    ASSERT_EQ(kvdbLists.at(0), "NEW_DB");
    ASSERT_EQ(kvdbLists.at(1), kTestDBName);

    ASSERT_TRUE(kvdbManager->unloadDB("NEW_DB"));
}

TEST_F(KVDBTest, ListAllKVDBs)
{
    auto kvdbLists = kvdbManager->listDBs();
    ASSERT_EQ(kvdbLists.size(), 1);

    auto resultValue = kvdbManager->CreateAndFillDBfromFile(kTestUnloadedDBName);
    ASSERT_STREQ(resultValue.c_str(), "OK");

    kvdbLists = kvdbManager->listDBs(false);
    ASSERT_EQ(kvdbLists.size(), 2);
}

TEST_F(KVDBTest, GetWriteDeleteKeyValueThroughManager)
{
    std::string valueRead, resultValue;
    bool retval;

    // adding key value to db loaded causes error
    retval = kvdbManager->writeKey(kTestDBName, KEY, VALUE);
    ASSERT_FALSE(retval);

    // create unloaded DB
    resultValue = kvdbManager->CreateAndFillDBfromFile(kTestUnloadedDBName);
    ASSERT_STREQ(resultValue.c_str(), "OK");

    retval = kvdbManager->writeKey(kTestUnloadedDBName, KEY, VALUE);
    ASSERT_TRUE(retval);

    auto val = kvdbManager->getKeyValue(kTestUnloadedDBName, KEY);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(val.value(), VALUE);

    retval = kvdbManager->deleteKey(kTestUnloadedDBName, KEY);
    ASSERT_TRUE(retval);

    retval = kvdbManager->deleteKey(kTestUnloadedDBName, KEY);
    ASSERT_FALSE(retval);

    auto retOpt = kvdbManager->deleteDB(kTestUnloadedDBName);
    ASSERT_TRUE(retOpt == std::nullopt);
}

TEST_F(KVDBTest, GetWriteDeleteSingleKeyThroughManager)
{
    std::string valueRead, resultValue;
    bool retval;

    resultValue = kvdbManager->CreateAndFillDBfromFile(kTestUnloadedDBName);
    ASSERT_STREQ(resultValue.c_str(), "OK");

    // single key KVDB
    retval = kvdbManager->writeKey(kTestUnloadedDBName, KEY);
    ASSERT_TRUE(retval);

    auto val = kvdbManager->getKeyValue(kTestUnloadedDBName, KEY);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(val.value(), "");

    ASSERT_NO_THROW(retval = kvdbManager->deleteKey(kTestUnloadedDBName, KEY));
    ASSERT_TRUE(retval);

    ASSERT_NO_THROW(val = kvdbManager->getKeyValue(kTestUnloadedDBName, KEY));
    ASSERT_FALSE(val.has_value());
}

TEST_F(KVDBTest, DoubleDeleteThroughManager)
{
    std::string valueRead, resultValue;
    bool retval;

    // create unloaded DB
    ASSERT_NO_THROW(resultValue =
                        kvdbManager->CreateAndFillDBfromFile(kTestUnloadedDBName));
    ASSERT_STREQ(resultValue.c_str(), "OK");

    ASSERT_NO_THROW(retval = kvdbManager->writeKey(kTestUnloadedDBName, KEY, VALUE));
    ASSERT_TRUE(retval);

    auto val = kvdbManager->getKeyValue(kTestUnloadedDBName, KEY);
    ASSERT_TRUE(val.has_value());
    ASSERT_EQ(val.value(), VALUE);

    ASSERT_NO_THROW(retval = kvdbManager->deleteKey(kTestUnloadedDBName, KEY));
    ASSERT_TRUE(retval);

    // double delete
    ASSERT_NO_THROW(retval = kvdbManager->deleteKey(kTestUnloadedDBName, KEY));
    ASSERT_FALSE(retval);
}

// TODO: fill test
TEST_F(KVDBTest, CreateAndFillKVDBfromFileOkWithFile)
{
    // create a json
    // save it in a file on a specific directory
    // create a DB with this path
    // dump it with method and compare

    // json can have multiple formats, look in
    //  /wazuh/src/engine/test/kvdb_input_files
}

TEST_F(KVDBTest, CreateAndFillKVDBfromFileCreatedEarlier)
{
    std::string retval;
    ASSERT_NO_THROW(retval = kvdbManager->CreateAndFillDBfromFile(kTestUnloadedDBName));
    ASSERT_STREQ(retval.c_str(), "OK");

    ASSERT_NO_THROW(retval = kvdbManager->CreateAndFillDBfromFile(kTestUnloadedDBName));
    ASSERT_STREQ(
        retval.c_str(),
        fmt::format("Database \"{}\" already exists", kTestUnloadedDBName).c_str());
}

TEST_F(KVDBTest, CreateAndFillKVDBfromFileCreatedAndLoadedEarlier)
{
    std::string retval;
    ASSERT_NO_THROW(retval = kvdbManager->CreateAndFillDBfromFile(kTestUnloadedDBName));
    ASSERT_STREQ(retval.c_str(), "OK");

    KVDBHandle kvdbHandle;
    ASSERT_NO_THROW(kvdbHandle = kvdbManager->loadDB(kTestUnloadedDBName));
    ASSERT_TRUE(kvdbHandle);

    ASSERT_NO_THROW(retval = kvdbManager->CreateAndFillDBfromFile(kTestUnloadedDBName));
    ASSERT_STREQ(
        retval.c_str(),
        fmt::format("Database \"{}\" is already in use", kTestUnloadedDBName).c_str());
}

TEST_F(KVDBTest, createKVDBfromCDBFileUnexistantFile)
{
    bool retval;
    ASSERT_NO_THROW(retval = kvdbManager->createDBfromCDB("/tmp/dummy"));
    ASSERT_FALSE(retval);
}

TEST_F(KVDBTest, createKVDBfromCDBFileDirectoryCollition)
{
    // file on same directory of kvdbManager initilization will generate error
    // TODO: replicate with jsons
    GTEST_SKIP();
    std::string filePath = "/tmp/DB_FROM_FILE";
    if (!std::filesystem::exists(filePath))
    {
        std::ofstream exampleFile(filePath);
        if (exampleFile.is_open())
        {
            exampleFile << "key1\n";
            exampleFile << "key2\n";
            exampleFile << "key3\n";
            exampleFile << "key4\n";
            exampleFile.close();
        }
    }

    bool retval;
    ASSERT_NO_THROW(retval = kvdbManager->createDBfromCDB(filePath));
    ASSERT_FALSE(retval);

    std::filesystem::remove(filePath);
}

TEST_F(KVDBTest, createKVDBfromCDBFileOkSingleKey)
{
    // file creation
    std::string dbName = "DB_FROM_FILE";
    std::string fileDir = "/tmp/aux_dir/";
    std::string filePath = fileDir + dbName;

    if (!std::filesystem::exists(fileDir))
    {
        std::filesystem::create_directory(fileDir);
    }

    if (!std::filesystem::exists(filePath))
    {
        std::ofstream exampleFile(filePath);
        if (exampleFile.is_open())
        {
            exampleFile << "key1:valA\n";
            exampleFile << "key2:valB\n";
            exampleFile << "key3:valC\n";
            exampleFile << "key4:valD\n";
            exampleFile.close();
        }
    }

    bool retval;
    ASSERT_NO_THROW(retval = kvdbManager->createDBfromCDB(filePath));
    ASSERT_TRUE(retval);

    // as this method is done throug loadDB it should be removed from list
    ASSERT_NO_THROW(retval = kvdbManager->unloadDB(dbName));
    ASSERT_TRUE(retval);

    std::filesystem::remove(filePath);
}

} // namespace
