#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <store/mockDriver.hpp>
#include <store/mockStore.hpp>
#include <store/store.hpp>
#include <store/utils.hpp>

using namespace store;
using namespace store::mocks;

const json::Json jdoc_1A {R"({"name": "doc_1A"})"};

class StoreBuildTest : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }
};

class StoreTest : public ::testing::Test
{
protected:
    std::shared_ptr<MockDriver> driver;
    std::shared_ptr<Store> store;

    void SetUp() override
    {
        logging::testInit();
        driver = std::make_shared<MockDriver>();
        ASSERT_NO_THROW(store = std::make_shared<Store>(driver));
    }

    void TearDown() override {}
};

TEST_F(StoreBuildTest, NullDriver)
{
    std::shared_ptr<Store> store;
    ASSERT_THROW(store = std::make_shared<Store>(nullptr), std::runtime_error);
}

TEST_F(StoreBuildTest, ValidDriver)
{
    auto driver = std::make_shared<MockDriver>();
    std::shared_ptr<Store> store;
    ASSERT_NO_THROW(store = std::make_shared<Store>(driver));
}

/*******************************************************************************
                        Store::createDoc
*******************************************************************************/
TEST_F(StoreTest, createDoc_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, createDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(driverError()));
    ASSERT_TRUE(base::isError(store->createDoc("x", jdoc_1A)));
}

TEST_F(StoreTest, createDoc_ok)
{
    EXPECT_CALL(*driver, createDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->createDoc("x", jdoc_1A)));
}

/*******************************************************************************
                        Store::readDoc
*******************************************************************************/
TEST_F(StoreTest, readDoc_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, readDoc(base::Name("x"))).WillOnce(testing::Return(driverReadError<Doc>()));
    ASSERT_TRUE(base::isError(store->readDoc("x")));
}

TEST_F(StoreTest, readDoc_ok)
{
    EXPECT_CALL(*driver, readDoc(base::Name("x"))).WillOnce(testing::Return(driverReadDocResp(Doc(jdoc_1A))));
    auto res = store->readDoc("x");

    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(std::get<Doc>(res), jdoc_1A);
}

/*******************************************************************************
                        Store::updateDoc
*******************************************************************************/
TEST_F(StoreTest, updateDoc_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, updateDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(driverError()));
    ASSERT_TRUE(base::isError(store->updateDoc("x", jdoc_1A)));
}

TEST_F(StoreTest, updateDoc_ok)
{
    EXPECT_CALL(*driver, updateDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->updateDoc("x", jdoc_1A)));
}

/*******************************************************************************
                        Store::upsertDoc
*******************************************************************************/
TEST_F(StoreTest, upsertDoc_update_ok)
{
    EXPECT_CALL(*driver, existsDoc(base::Name("x"))).WillOnce(testing::Return(true));
    EXPECT_CALL(*driver, updateDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->upsertDoc("x", jdoc_1A)));
}

TEST_F(StoreTest, upsertDoc_create_ok)
{
    EXPECT_CALL(*driver, existsDoc(base::Name("x"))).WillOnce(testing::Return(false));
    EXPECT_CALL(*driver, createDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->upsertDoc("x", jdoc_1A)));
}

/*******************************************************************************
                        Store::deleteDoc
*******************************************************************************/
TEST_F(StoreTest, deleteDoc_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, deleteDoc(base::Name("x"))).WillOnce(testing::Return(driverError()));
    ASSERT_TRUE(base::isError(store->deleteDoc("x")));
}

TEST_F(StoreTest, deleteDoc_ok)
{
    EXPECT_CALL(*driver, deleteDoc(base::Name("x"))).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->deleteDoc("x")));
}

/*******************************************************************************
                        Store::readCol
*******************************************************************************/
TEST_F(StoreTest, readCol_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, readCol(base::Name("x"))).WillOnce(testing::Return(driverReadError<Col>()));
    ASSERT_TRUE(base::isError(store->readCol("x")));
}

TEST_F(StoreTest, readCol_ok)
{
    EXPECT_CALL(*driver, readCol(base::Name("x"))).WillOnce(testing::Return(driverReadColResp(Col {base::Name("a")})));
    auto res = store->readCol("x");

    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(std::get<Col>(res).size(), 1);
    ASSERT_EQ(std::get<Col>(res)[0], base::Name("a"));
}

/*******************************************************************************
                        Store::existsDoc
*******************************************************************************/
TEST_F(StoreTest, existsDoc_false)
{
    EXPECT_CALL(*driver, existsDoc(base::Name("x"))).WillOnce(testing::Return(false));
    ASSERT_FALSE(store->existsDoc("x"));
}

TEST_F(StoreTest, existsDoc_true)
{
    EXPECT_CALL(*driver, existsDoc(base::Name("x"))).WillOnce(testing::Return(true));
    ASSERT_TRUE(store->existsDoc("x"));
}

class StoreUtilsTest : public ::testing::Test
{
protected:
    const base::Name statusDoc {"engine/status/0"};
    std::shared_ptr<MockStore> mockStore;

    void SetUp() override
    {
        logging::testInit();
        mockStore = std::make_shared<MockStore>();
    }
};

TEST_F(StoreUtilsTest, updateStartStatusCreatesDocumentOnFirstStart)
{
    const std::string timestamp {"2026-07-02T05:24:45.886Z"};

    EXPECT_CALL(*mockStore, existsDoc(statusDoc)).WillOnce(testing::Return(false));
    EXPECT_CALL(*mockStore, upsertDoc(statusDoc, testing::_))
        .WillOnce(testing::Invoke(
            [&timestamp](const base::Name&, const store::Doc& status)
            {
                std::string firstStart;
                std::string lastStart;
                EXPECT_EQ(status.getString(firstStart, "/first_start"), json::RetGet::Success);
                EXPECT_EQ(status.getString(lastStart, "/last_start"), json::RetGet::Success);
                EXPECT_EQ(firstStart, timestamp);
                EXPECT_EQ(lastStart, timestamp);
                return storeOk();
            }));

    EXPECT_TRUE(store::utils::updateStartStatus(mockStore, timestamp));
}

TEST_F(StoreUtilsTest, updateStartStatusPreservesFirstStart)
{
    const std::string firstTimestamp {"2026-07-02T05:24:45.886Z"};
    const std::string currentTimestamp {"2026-07-02T05:36:17.128Z"};
    const store::Doc persisted {
        R"({"first_start":"2026-07-02T05:24:45.886Z","last_start":"2026-07-02T05:24:45.886Z"})"};

    EXPECT_CALL(*mockStore, existsDoc(statusDoc)).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockStore, readDoc(statusDoc)).WillOnce(testing::Return(storeReadDocResp(persisted)));
    EXPECT_CALL(*mockStore, upsertDoc(statusDoc, testing::_))
        .WillOnce(testing::Invoke(
            [&firstTimestamp, &currentTimestamp](const base::Name&, const store::Doc& status)
            {
                std::string firstStart;
                std::string lastStart;
                EXPECT_EQ(status.getString(firstStart, "/first_start"), json::RetGet::Success);
                EXPECT_EQ(status.getString(lastStart, "/last_start"), json::RetGet::Success);
                EXPECT_EQ(firstStart, firstTimestamp);
                EXPECT_EQ(lastStart, currentTimestamp);
                return storeOk();
            }));

    EXPECT_FALSE(store::utils::updateStartStatus(mockStore, currentTimestamp));
}

TEST_F(StoreUtilsTest, updateStartStatusRecreatesUnreadableDocumentResetsTimestamps)
{
    const std::string timestamp {"2026-07-02T05:36:17.128Z"};

    EXPECT_CALL(*mockStore, existsDoc(statusDoc)).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockStore, readDoc(statusDoc)).WillOnce(testing::Return(storeReadError<store::Doc>()));
    EXPECT_CALL(*mockStore, upsertDoc(statusDoc, testing::_))
        .WillOnce(testing::Invoke(
            [&timestamp](const base::Name&, const store::Doc& status)
            {
                std::string firstStart;
                std::string lastStart;
                EXPECT_EQ(status.getString(firstStart, "/first_start"), json::RetGet::Success);
                EXPECT_EQ(status.getString(lastStart, "/last_start"), json::RetGet::Success);
                EXPECT_EQ(firstStart, timestamp);
                EXPECT_EQ(lastStart, timestamp);
                return storeOk();
            }));

    EXPECT_FALSE(store::utils::updateStartStatus(mockStore, timestamp));
}

TEST_F(StoreUtilsTest, updateStartStatusRecreatesInvalidDocument)
{
    const std::string timestamp {"2026-07-02T05:36:17.128Z"};
    const store::Doc persisted {R"([])"};

    EXPECT_CALL(*mockStore, existsDoc(statusDoc)).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockStore, readDoc(statusDoc)).WillOnce(testing::Return(storeReadDocResp(persisted)));
    EXPECT_CALL(*mockStore, upsertDoc(statusDoc, testing::_))
        .WillOnce(testing::Invoke(
            [&timestamp](const base::Name&, const store::Doc& status)
            {
                std::string firstStart;
                EXPECT_EQ(status.getString(firstStart, "/first_start"), json::RetGet::Success);
                EXPECT_EQ(firstStart, timestamp);
                return storeOk();
            }));

    EXPECT_FALSE(store::utils::updateStartStatus(mockStore, timestamp));
}

TEST_F(StoreUtilsTest, updateStartStatusReturnsFalseOnPersistenceFailure)
{
    const std::string timestamp {"2026-07-02T05:24:45.886Z"};

    EXPECT_CALL(*mockStore, existsDoc(statusDoc)).WillOnce(testing::Return(false));
    EXPECT_CALL(*mockStore, upsertDoc(statusDoc, testing::_)).WillOnce(testing::Return(storeError()));

    EXPECT_FALSE(store::utils::updateStartStatus(mockStore, timestamp));
}

TEST_F(StoreUtilsTest, updateStartStatusReturnsFalseOnNullStore)
{
    const std::string timestamp {"2026-07-02T05:24:45.886Z"};

    EXPECT_FALSE(store::utils::updateStartStatus(nullptr, timestamp));
}
