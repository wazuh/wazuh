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
                        Store::createInternalDoc
*******************************************************************************/
TEST_F(StoreTest, createInternalDoc_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, createDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(driverError()));
    ASSERT_TRUE(base::isError(store->createInternalDoc("x", jdoc_1A)));
}

TEST_F(StoreTest, createInternalDoc_ok)
{
    EXPECT_CALL(*driver, createDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->createInternalDoc("x", jdoc_1A)));
}

/*******************************************************************************
                        Store::readInternalDoc
*******************************************************************************/
TEST_F(StoreTest, readInternalDoc_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, readDoc(base::Name("x"))).WillOnce(testing::Return(driverReadError<Doc>()));
    ASSERT_TRUE(base::isError(store->readInternalDoc("x")));
}

TEST_F(StoreTest, readInternalDoc_ok)
{
    EXPECT_CALL(*driver, readDoc(base::Name("x"))).WillOnce(testing::Return(driverReadDocResp(Doc(jdoc_1A))));
    auto res = store->readInternalDoc("x");

    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(std::get<Doc>(res), jdoc_1A);
}

/*******************************************************************************
                        Store::updateInternalDoc
*******************************************************************************/
TEST_F(StoreTest, updateInternalDoc_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, updateDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(driverError()));
    ASSERT_TRUE(base::isError(store->updateInternalDoc("x", jdoc_1A)));
}

TEST_F(StoreTest, updateInternalDoc_ok)
{
    EXPECT_CALL(*driver, updateDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->updateInternalDoc("x", jdoc_1A)));
}

/*******************************************************************************
                        Store::upsertInternalDoc
*******************************************************************************/
TEST_F(StoreTest, upsertInternalDoc_update_ok)
{
    EXPECT_CALL(*driver, existsDoc(base::Name("x"))).WillOnce(testing::Return(true));
    EXPECT_CALL(*driver, updateDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->upsertInternalDoc("x", jdoc_1A)));
}

TEST_F(StoreTest, upsertInternalDoc_create_ok)
{
    EXPECT_CALL(*driver, existsDoc(base::Name("x"))).WillOnce(testing::Return(false));
    EXPECT_CALL(*driver, createDoc(base::Name("x"), jdoc_1A)).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->upsertInternalDoc("x", jdoc_1A)));
}

/*******************************************************************************
                        Store::deleteInternalDoc
*******************************************************************************/
TEST_F(StoreTest, deleteInternalDoc_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, deleteDoc(base::Name("x"))).WillOnce(testing::Return(driverError()));
    ASSERT_TRUE(base::isError(store->deleteInternalDoc("x")));
}

TEST_F(StoreTest, deleteInternalDoc_ok)
{
    EXPECT_CALL(*driver, deleteDoc(base::Name("x"))).WillOnce(testing::Return(std::nullopt));
    ASSERT_FALSE(base::isError(store->deleteInternalDoc("x")));
}

/*******************************************************************************
                        Store::readInternalCol
*******************************************************************************/
TEST_F(StoreTest, readInternalCol_fail)
{
    // Fail driver
    EXPECT_CALL(*driver, readCol(base::Name("x"))).WillOnce(testing::Return(driverReadError<Col>()));
    ASSERT_TRUE(base::isError(store->readInternalCol("x")));
}

TEST_F(StoreTest, readInternalCol_ok)
{
    EXPECT_CALL(*driver, readCol(base::Name("x"))).WillOnce(testing::Return(driverReadColResp(Col {base::Name("a")})));
    auto res = store->readInternalCol("x");

    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(std::get<Col>(res).size(), 1);
    ASSERT_EQ(std::get<Col>(res)[0], base::Name("a"));
}

/*******************************************************************************
                        Store::existsInternalDoc
*******************************************************************************/
TEST_F(StoreTest, existsInternalDoc_false)
{
    EXPECT_CALL(*driver, existsDoc(base::Name("x"))).WillOnce(testing::Return(false));
    ASSERT_FALSE(store->existsInternalDoc("x"));
}

TEST_F(StoreTest, existsInternalDoc_true)
{
    EXPECT_CALL(*driver, existsDoc(base::Name("x"))).WillOnce(testing::Return(true));
    ASSERT_TRUE(store->existsInternalDoc("x"));
}
