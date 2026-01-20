#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <store/mockDriver.hpp>
#include <store/store.hpp>

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
