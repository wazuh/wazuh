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
    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;

    virtual void SetUp()
    {
        // cleaning directory in order to start without garbage.
        if (std::filesystem::exists(KVDB_PATH))
        {
            std::filesystem::remove_all(KVDB_PATH);
        }
        kvdbManager = {std::make_shared<kvdb_manager::KVDBManager>(KVDB_PATH)};
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
    kvdb_manager::KVDBHandle kvdbAddHandle;
    ASSERT_NO_THROW(kvdbAddHandle = kvdbManager->loadDB("TEST_DB_1"));
    ASSERT_TRUE(kvdbAddHandle);

    kvdb_manager::KVDBHandle kvdbGetHandle;
    ASSERT_NO_THROW(kvdbGetHandle = kvdbManager->getDB("TEST_DB_1"));
    ASSERT_TRUE(kvdbGetHandle);
    ASSERT_STREQ(kvdbGetHandle->getName().data(), "TEST_DB_1");
    ASSERT_TRUE(kvdbGetHandle->isReady());

    kvdbManager->unloadDB("TEST_DB_1");
    kvdb_manager::KVDBHandle kvdbDeleteHandle;
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
    kvdb_manager::KVDBHandle kvdbHandle;
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
    ASSERT_STREQ(std::get<std::string>(kvdb->read(KEY)).c_str(),"");

    auto deleteResult = kvdb->deleteKey(KEY);
    ASSERT_FALSE(deleteResult.has_value());

    retval = kvdb->hasKey(KEY);
    ASSERT_FALSE(retval);
}

TEST_F(KVDBTest, ReadWriteColumn)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    bool retval;

    auto kvdb = kvdbManager->getDB(kTestDBName);

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

    auto kvdb = kvdbManager->getDB(kTestDBName);
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

    auto kvdb = kvdbManager->getDB(kTestDBName);

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
    auto kvdb = kvdbManager->getDB(kTestDBName);
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
    ASSERT_NO_THROW(resultValue = kvdbManager->CreateFromJFile("NEW_TEST_DB"));
    ASSERT_STREQ(resultValue.c_str(), "OK");
    auto retval = kvdbManager->writeRaw("NEW_TEST_DB", key, value);
    ASSERT_FALSE(retval.has_value());

    // TODO: this replicates what the helper does and should be improved
    kvdb_manager::KVDBHandle kvdbHandle;
    kvdbHandle = kvdbManager->getDB("NEW_TEST_DB");
    if (!kvdbHandle)
    {
        ASSERT_NO_THROW(kvdbManager->loadDB("NEW_TEST_DB", false));
    }
    kvdbHandle = kvdbManager->getDB("NEW_TEST_DB");
    ASSERT_TRUE(kvdbHandle);
    ASSERT_TRUE(kvdbHandle->hasKey(key));
    std::optional<std::string> valueRead;
    ASSERT_NO_THROW(valueRead = std::get<std::string>(kvdbHandle->read(key)));
    ASSERT_TRUE(valueRead);
    ASSERT_STREQ(valueRead.value().c_str(), value.c_str());

    // clean to avoid error on rerun
    kvdbManager->unloadDB("NEW_TEST_DB");
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

    auto resultValue = kvdbManager->CreateFromJFile(kTestUnloadedDBName);
    ASSERT_STREQ(resultValue.c_str(), "OK");

    kvdbLists = kvdbManager->listDBs(false);
    ASSERT_EQ(kvdbLists.size(), 2);
}

TEST_F(KVDBTest, GetWriteDeleteKeyValueThroughManager)
{
    std::string valueRead, resultValue;

    // adding key value to db loaded causes error
    auto retval = kvdbManager->writeRaw(kTestDBName, KEY, VALUE);
    ASSERT_FALSE(retval.has_value());

    // create unloaded DB
    resultValue = kvdbManager->CreateFromJFile(kTestUnloadedDBName);
    ASSERT_STREQ(resultValue.c_str(), "OK");

    retval = kvdbManager->writeRaw(kTestUnloadedDBName, KEY, VALUE);
    ASSERT_FALSE(retval);

    auto val = kvdbManager->getRawValue(kTestUnloadedDBName, KEY);
    ASSERT_FALSE(std::holds_alternative<base::Error>(val));
    ASSERT_EQ(std::get<std::string>(val), VALUE);

    auto deleteResult = kvdbManager->deleteKey(kTestUnloadedDBName, KEY);
    ASSERT_FALSE(deleteResult.has_value());

    deleteResult = kvdbManager->deleteKey(kTestUnloadedDBName, KEY);
    ASSERT_FALSE(deleteResult.has_value());

    auto retOpt = kvdbManager->deleteDB(kTestUnloadedDBName);
    ASSERT_TRUE(retOpt == std::nullopt);
}

TEST_F(KVDBTest, GetWriteDeleteSingleKeyThroughManager)
{
    std::string valueRead, resultValue;
    bool retval;

    resultValue = kvdbManager->CreateFromJFile(kTestUnloadedDBName);
    ASSERT_STREQ(resultValue.c_str(), "OK");

    // single key KVDB
    auto retWriteVal = kvdbManager->writeRaw(kTestUnloadedDBName, KEY);
    ASSERT_FALSE(retWriteVal.has_value());

    auto val = kvdbManager->getRawValue(kTestUnloadedDBName, KEY);
    ASSERT_EQ(std::get<std::string>(val), "null");

    auto deleteResult = kvdbManager->deleteKey(kTestUnloadedDBName, KEY);
    ASSERT_FALSE(deleteResult.has_value());

    val = kvdbManager->getRawValue(kTestUnloadedDBName, KEY);
    ASSERT_TRUE(std::holds_alternative<base::Error>(val));
}

TEST_F(KVDBTest, DoubleDeleteThroughManager)
{
    std::string valueRead, resultValue;
    bool retval;

    // create unloaded DB
    ASSERT_NO_THROW(resultValue =
                        kvdbManager->CreateFromJFile(kTestUnloadedDBName));
    ASSERT_STREQ(resultValue.c_str(), "OK");

    auto retWriteVal = kvdbManager->writeRaw(kTestUnloadedDBName, KEY, VALUE);
    ASSERT_FALSE(retWriteVal.has_value());

    auto val = kvdbManager->getRawValue(kTestUnloadedDBName, KEY);
    ASSERT_TRUE(std::holds_alternative<std::string>(val));
    ASSERT_EQ(std::get<std::string>(val), VALUE);

    auto deleteResult = kvdbManager->deleteKey(kTestUnloadedDBName, KEY);
    ASSERT_FALSE(deleteResult.has_value());

    // double delete isn't an error
    deleteResult = kvdbManager->deleteKey(kTestUnloadedDBName, KEY);
    ASSERT_FALSE(deleteResult.has_value());
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
    ASSERT_NO_THROW(retval = kvdbManager->CreateFromJFile(kTestUnloadedDBName));
    ASSERT_STREQ(retval.c_str(), "OK");

    ASSERT_NO_THROW(retval = kvdbManager->CreateFromJFile(kTestUnloadedDBName));
    ASSERT_STREQ(
        retval.c_str(),
        fmt::format("Database \"{}\" already exists", kTestUnloadedDBName).c_str());
}

TEST_F(KVDBTest, CreateAndFillKVDBfromFileCreatedAndLoadedEarlier)
{
    std::string retval;
    ASSERT_NO_THROW(retval = kvdbManager->CreateFromJFile(kTestUnloadedDBName));
    ASSERT_STREQ(retval.c_str(), "OK");

    kvdb_manager::KVDBHandle kvdbHandle;
    ASSERT_NO_THROW(kvdbHandle = kvdbManager->loadDB(kTestUnloadedDBName));
    ASSERT_TRUE(kvdbHandle);

    ASSERT_NO_THROW(retval = kvdbManager->CreateFromJFile(kTestUnloadedDBName));
    ASSERT_STREQ(
        retval.c_str(),
        fmt::format("Database \"{}\" is already in use", kTestUnloadedDBName).c_str());
}


} // namespace
