#include <filesystem>

#include "gtest/gtest.h"
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>

// TODO: can we move this utility functions to headers accesible to tests and
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
class KVDBTest : public ::testing::Test
{

protected:
    KVDBManager &kvdbManager = KVDBManager::getInstance();

    KVDBTest()
    { // = default;
        // TODO: this init is done in order to receive the logs at the right
        // moment, insted we should be mocking these logs in each test
        logging::LoggingConfig logConfig;
        logConfig.logLevel = logging::LogLevel::Debug;
        logging::loggingInit(logConfig);
    }

    virtual ~KVDBTest()
    { // = default;
    }

    virtual void SetUp()
    {
        kvdbManager.createDB("TEST_DB");
    }

    virtual void TearDown()
    {
        kvdbManager.DeleteDB("TEST_DB");
    }
};

TEST_F(KVDBTest, CreateDeleteKvdFile)
{
    kvdbManager.createDB("NEW_DB");
    KVDB &newKvdb = kvdbManager.getDB("NEW_DB");
    ASSERT_EQ(newKvdb.getName(), "NEW_DB");
    ASSERT_EQ(newKvdb.getState(), KVDB::State::Open);

    kvdbManager.DeleteDB("NEW_DB");
    KVDB &deletedKvdb = kvdbManager.getDB("NEW_DB");
    ASSERT_EQ(deletedKvdb.getName(), "Invalid");
    ASSERT_EQ(deletedKvdb.getState(), KVDB::State::Invalid);
}

TEST_F(KVDBTest, CreateDeleteColumns)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    KVDB &kvdb = kvdbManager.getDB("TEST_DB");
    bool ret = kvdb.createColumn(COLUMN_NAME);
    ASSERT_TRUE(ret);
    ret = kvdb.deleteColumn(COLUMN_NAME);
    ASSERT_TRUE(ret);
    ret = kvdb.deleteColumn(COLUMN_NAME);
    ASSERT_FALSE(ret);

    ret = kvdb.deleteColumn(); // TODO "default" can be deleted? I dont think
                               // so...
}

TEST_F(KVDBTest, ReadWrite)
{
    const std::string KEY = "dummy_key";
    const std::string VALUE = "dummy_value";
    std::string valueRead;
    bool ret;

    KVDB &kvdb = kvdbManager.getDB("TEST_DB");

    ret = kvdb.write(KEY, VALUE);
    ASSERT_TRUE(ret);

    ret = kvdb.exist(KEY);
    ASSERT_TRUE(ret);

    valueRead = kvdb.read(KEY);
    ASSERT_EQ(valueRead, VALUE);

    ret = kvdb.readPinned(KEY, valueRead); // Check this...
    ASSERT_TRUE(ret);
    ASSERT_EQ(valueRead, VALUE);

    ret = kvdb.deleteKey(KEY);
    ASSERT_TRUE(ret);

    ret = kvdb.exist(KEY);
    ASSERT_FALSE(ret);

    valueRead = kvdb.read(KEY);
    ASSERT_TRUE(valueRead.empty());

    ret = kvdb.readPinned(KEY, valueRead); // Check this...
    ASSERT_FALSE(ret);
    ASSERT_TRUE(valueRead.empty());
}

TEST_F(KVDBTest, ReadWriteColumn)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    const std::string KEY = "dummy_key";
    const std::string VALUE = "dummy_value";
    std::string valueRead;
    bool ret;

    KVDB &kvdb = kvdbManager.getDB("TEST_DB");

    ret = kvdb.createColumn(COLUMN_NAME);
    ASSERT_TRUE(ret);

    ret = kvdb.write(KEY, VALUE, COLUMN_NAME);
    ASSERT_TRUE(ret);

    valueRead = kvdb.read(KEY, COLUMN_NAME);
    ASSERT_EQ(valueRead, VALUE);
}

TEST_F(KVDBTest, Transactions)
{
    std::vector<std::pair<std::string, std::string>> vPairs = {
        {"key1", "value1"},
        {"key2", "value2"},
        {"key3", "value3"},
        {"key4", "value4"},
        {"key5", "value5"}};
    std::string valueRead;
    bool ret;

    KVDB &kvdb = kvdbManager.getDB("TEST_DB");

    ret = kvdb.writeToTransaction(vPairs);
    ASSERT_TRUE(ret);

    for (auto pair : vPairs)
    {
        valueRead = kvdb.read(pair.first);
        ASSERT_EQ(valueRead, pair.second);
    }
}

TEST_F(KVDBTest, CleanColumn)
{
    const std::string COLUMN_NAME = "NEW_COLUMN";
    const std::string KEY = "dummy_key";
    const std::string VALUE = "dummy_value";
    std::string valueRead;
    bool ret;

    KVDB &kvdb = kvdbManager.getDB("TEST_DB");

    // default column
    ret = kvdb.write(KEY, VALUE);
    ASSERT_TRUE(ret);
    valueRead = kvdb.read(KEY);
    ASSERT_EQ(valueRead, VALUE);
    ret = kvdb.cleanColumn();
    ASSERT_TRUE(ret);
    valueRead = kvdb.read(KEY);
    ASSERT_TRUE(valueRead.empty());

    // custom column
    ret = kvdb.createColumn(COLUMN_NAME);
    ASSERT_TRUE(ret);
    ret = kvdb.write(KEY, VALUE, COLUMN_NAME);
    ASSERT_TRUE(ret);
    valueRead = kvdb.read(KEY, COLUMN_NAME);
    ASSERT_EQ(valueRead, VALUE);
    ret = kvdb.cleanColumn(COLUMN_NAME);
    ASSERT_TRUE(ret);
    valueRead = kvdb.read(KEY, COLUMN_NAME);
    ASSERT_TRUE(valueRead.empty());
}

TEST_F(KVDBTest, ValueKeyLength)
{
    const std::string KEY = "dummy_key";
    KVDB &kvdb = kvdbManager.getDB("TEST_DB");
    std::string valueRead;
    std::string valueWrite;
    bool ret;

    valueWrite = getRandomString(128, true);
    ret = kvdb.write(KEY, valueWrite);
    ASSERT_TRUE(ret);
    valueRead = kvdb.read(KEY);
    ASSERT_EQ(valueWrite, valueRead);

    valueWrite = getRandomString(512, true);
    ret = kvdb.write(KEY, valueWrite);
    ASSERT_TRUE(ret);
    valueRead = kvdb.read(KEY);
    ASSERT_EQ(valueWrite, valueRead);

    valueWrite = getRandomString(1024, true);
    ret = kvdb.write(KEY, valueWrite);
    ASSERT_TRUE(ret);
    valueRead = kvdb.read(KEY);
    ASSERT_EQ(valueWrite, valueRead);
}

TEST_F(KVDBTest, concurrent_write)
{
    // TODO: how to test a concurrent acces to Rocksdb, it must
    // * use kvdb methods
    //   * not possible to use transactions without commit
    // * block access to a DB while being used
    // * allow concurrent access to different DBs within RockdDB
}

} // namespace
