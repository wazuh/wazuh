#include <condition_variable>
#include <filesystem>
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
static const char* kTestDBName = "TEST_DB";
class KVDBTest : public ::testing::Test
{

protected:
    std::shared_ptr<KVDBManager> kvdbManager = std::make_shared<KVDBManager>("/tmp/");
    virtual void SetUp() { kvdbManager->addDb(kTestDBName); }

    virtual void TearDown() { kvdbManager->deleteDB(kTestDBName); }
};

TEST_F(KVDBTest, CreateDeleteKvdbFile)
{
    auto ret = kvdbManager->addDb("NEW_DB");
    ASSERT_TRUE(ret);
    auto newKvdb = kvdbManager->getDB("NEW_DB");
    ASSERT_EQ(newKvdb->getName(), "NEW_DB");
    ASSERT_TRUE(newKvdb->isReady());

    auto ret2 = kvdbManager->addDb("NEW_DB 2");
    ASSERT_TRUE(ret2);
    auto newKvdb2 = kvdbManager->getDB("NEW_DB 2");
    ASSERT_EQ(newKvdb2->getName(), "NEW_DB 2");
    ASSERT_TRUE(newKvdb2->isReady());
    kvdbManager->deleteDB("NEW_DB 2");

    kvdbManager->deleteDB("NEW_DB");
    auto deletedKvdb = kvdbManager->getDB("NEW_DB");
    ASSERT_EQ(deletedKvdb, nullptr);
}

TEST_F(KVDBTest, CreateDeleteColumns)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    auto kvdb = kvdbManager->getDB(kTestDBName);
    bool ret = kvdb->createColumn(COLUMN_NAME);
    ASSERT_TRUE(ret);
    ret = kvdb->deleteColumn(COLUMN_NAME);
    ASSERT_TRUE(ret);
    ret = kvdb->deleteColumn(COLUMN_NAME);
    ASSERT_FALSE(ret);
}

TEST_F(KVDBTest, ReadWrite)
{
    const std::string KEY = "dummy_key";
    const std::string VALUE = "dummy_value";
    std::string valueRead;
    bool ret;

    auto kvdb = kvdbManager->getDB(kTestDBName);

    ret = kvdb->write(KEY, VALUE);
    ASSERT_TRUE(ret);

    ret = kvdb->hasKey(KEY);
    ASSERT_TRUE(ret);

    valueRead = kvdb->read(KEY);
    ASSERT_EQ(valueRead, VALUE);

    ret = kvdb->readPinned(KEY, valueRead); // Check this...
    ASSERT_TRUE(ret);
    ASSERT_EQ(valueRead, VALUE);

    ret = kvdb->deleteKey(KEY);
    ASSERT_TRUE(ret);

    ret = kvdb->hasKey(KEY);
    ASSERT_FALSE(ret);

    valueRead = kvdb->read(KEY);
    ASSERT_TRUE(valueRead.empty());

    ret = kvdb->readPinned(KEY, valueRead);
    ASSERT_FALSE(ret);
    ASSERT_TRUE(valueRead.empty());
}

// Key-only write
TEST_F(KVDBTest, KeyOnlyWrite)
{
    // TODO Update FH tests too
    const std::string KEY = "dummy_key";
    bool ret;
    auto kvdb = kvdbManager->getDB(kTestDBName);

    ret = kvdb->hasKey(KEY);
    ASSERT_FALSE(ret);
    ret = kvdb->writeKeyOnly(KEY);
    ASSERT_TRUE(ret);
    ret = kvdb->hasKey(KEY);
    ASSERT_TRUE(ret);
}

TEST_F(KVDBTest, ReadWriteColumn)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    const std::string KEY = "dummy_key";
    const std::string VALUE = "dummy_value";
    std::string valueRead;
    bool ret;

    auto kvdb = kvdbManager->getDB(kTestDBName);

    ret = kvdb->createColumn(COLUMN_NAME);
    ASSERT_TRUE(ret);

    ret = kvdb->write(KEY, VALUE, COLUMN_NAME);
    ASSERT_TRUE(ret);

    valueRead = kvdb->read(KEY, COLUMN_NAME);
    ASSERT_EQ(valueRead, VALUE);
}

TEST_F(KVDBTest, Transaction_ok)
{
    std::vector<std::pair<std::string, std::string>> vInput = {{"key1", "value1"},
                                                               {"key2", "value2"},
                                                               {"key3", "value3"},
                                                               {"key4", "value4"},
                                                               {"key5", "value5"}};
    bool ret;

    auto kvdb = kvdbManager->getDB(kTestDBName);
    ret = kvdb->writeToTransaction(vInput);
    ASSERT_TRUE(ret);
    for (auto pair : vInput)
    {
        std::string valueRead = kvdb->read(pair.first);
        ASSERT_EQ(valueRead, pair.second);
    }
}

TEST_F(KVDBTest, Transaction_invalid_input)
{
    bool ret;
    auto kvdb = kvdbManager->getDB(kTestDBName);

    // Empty input
    std::vector<std::pair<std::string, std::string>> vEmptyInput = {};
    ret = kvdb->writeToTransaction(vEmptyInput);
    ASSERT_FALSE(ret);

    // Invalid Column name
    std::vector<std::pair<std::string, std::string>> vInput = {{"key1", "value1"}};
    ret = kvdb->writeToTransaction(vInput, "InexistentColumn");
    ASSERT_FALSE(ret);

    // Partial input
    std::vector<std::pair<std::string, std::string>> vPartialInput = {{"", "value1"},
                                                                      {"key2", "value2"}};
    ret = kvdb->writeToTransaction(vPartialInput);
    ASSERT_TRUE(ret);
    std::string valueRead = kvdb->read(vPartialInput[1].first);
    ASSERT_EQ(valueRead, vPartialInput[1].second);
}

// TODO Mock DB and create tests for:
//  Txn start error
//  Put error
//  Commit error

TEST_F(KVDBTest, CleanColumn)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    const std::string KEY = "dummy_key";
    const std::string VALUE = "dummy_value";
    std::string valueRead;
    bool ret;

    auto kvdb = kvdbManager->getDB(kTestDBName);

    // default column
    ret = kvdb->write(KEY, VALUE);
    ASSERT_TRUE(ret);
    valueRead = kvdb->read(KEY);
    ASSERT_EQ(valueRead, VALUE);
    ret = kvdb->cleanColumn();
    ASSERT_TRUE(ret);
    valueRead = kvdb->read(KEY);
    ASSERT_TRUE(valueRead.empty());

    // custom column
    ret = kvdb->createColumn(COLUMN_NAME);
    ASSERT_TRUE(ret);
    ret = kvdb->write(KEY, VALUE, COLUMN_NAME);
    ASSERT_TRUE(ret);
    valueRead = kvdb->read(KEY, COLUMN_NAME);
    ASSERT_EQ(valueRead, VALUE);
    ret = kvdb->cleanColumn(COLUMN_NAME);
    ASSERT_TRUE(ret);
    valueRead = kvdb->read(KEY, COLUMN_NAME);
    ASSERT_TRUE(valueRead.empty());
}

TEST_F(KVDBTest, ValueKeyLength)
{
    const std::string KEY = "dummy_key";
    auto kvdb = kvdbManager->getDB(kTestDBName);
    std::string valueRead;
    std::string valueWrite;
    bool ret;

    valueWrite = getRandomString(128, true);
    ret = kvdb->write(KEY, valueWrite);
    ASSERT_TRUE(ret);
    valueRead = kvdb->read(KEY);
    ASSERT_EQ(valueWrite, valueRead);

    valueWrite = getRandomString(512, true);
    ret = kvdb->write(KEY, valueWrite);
    ASSERT_TRUE(ret);
    valueRead = kvdb->read(KEY);
    ASSERT_EQ(valueWrite, valueRead);

    valueWrite = getRandomString(1024, true);
    ret = kvdb->write(KEY, valueWrite);
    ASSERT_TRUE(ret);
    valueRead = kvdb->read(KEY);
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
                            auto ret = pthread_barrier_wait(&barrier);
                            EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == ret || 0 == ret);
                            auto m = kvdbManager;
                            for (int i = 0; i < kMaxTestIterations; ++i)
                            {
                                auto db = m->getDB(dbName);
                                if (db && !db->isValid())
                                {
                                    m->addDb(dbName);
                                }
                            }
                        }};

    std::thread read {[&]
                      {
                          auto ret = pthread_barrier_wait(&barrier);
                          EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == ret || 0 == ret);
                          auto m = kvdbManager;
                          for (int i = 0; i < kMaxTestIterations; ++i)
                          {
                              auto db = m->getDB(dbName);
                          }
                      }};

    std::thread del {[&]
                     {
                         auto ret = pthread_barrier_wait(&barrier);
                         EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == ret || 0 == ret);
                         auto m = kvdbManager;
                         for (int i = 0; i < kMaxTestIterations; ++i)
                         {
                             auto db = m->getDB(dbName);
                             if (db && db->isValid())
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

    kvdbManager->addDb(dbName);

    std::thread create {[&]
                        {
                            auto ret = pthread_barrier_wait(&barrier);
                            EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == ret || 0 == ret);
                            auto db = kvdbManager->getDB(dbName);
                            for (int i = 0; i < kMaxTestIterations; ++i)
                            {
                                db->createColumn(fmt::format("colname.{}", distrib(gen)));
                            }
                        }};

    std::thread write {[&]
                       {
                           auto ret = pthread_barrier_wait(&barrier);
                           EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == ret || 0 == ret);
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
                          auto ret = pthread_barrier_wait(&barrier);
                          EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == ret || 0 == ret);
                          auto db = kvdbManager->getDB(dbName);
                          for (int i = 0; i < kMaxTestIterations; ++i)
                          {
                              db->read(fmt::format("key{}", distrib(gen)),
                                       fmt::format("colname.{}", distrib(gen)));
                          }
                      }};

    std::thread del {[&]
                     {
                         auto ret = pthread_barrier_wait(&barrier);
                         EXPECT_TRUE(PTHREAD_BARRIER_SERIAL_THREAD == ret || 0 == ret);
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
    kvdbManager->deleteDB(dbName);
}

TEST_F(KVDBTest, ListAvailableKVDBs)
{
    auto kvdbLists = kvdbManager->getAvailableKVDBs();
    ASSERT_EQ(kvdbLists.size(),1);

    auto ret = kvdbManager->addDb("NEW_DB");
    ASSERT_TRUE(ret);
    kvdbLists = kvdbManager->getAvailableKVDBs();
    ASSERT_EQ(kvdbLists.size(),2);

    ret = kvdbManager->addDb("NEW_DB_2");
    ASSERT_TRUE(ret);
    kvdbLists = kvdbManager->getAvailableKVDBs();
    ASSERT_EQ(kvdbLists.size(),3);

    kvdbManager->deleteDB("NEW_DB");
    kvdbLists = kvdbManager->getAvailableKVDBs();

    ASSERT_EQ(kvdbLists.size(),2);
    ASSERT_EQ(kvdbLists.at(0),"NEW_DB_2");
    ASSERT_EQ(kvdbLists.at(1),kTestDBName);
}

} // namespace
