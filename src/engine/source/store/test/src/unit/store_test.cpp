#include <gtest/gtest.h>

#include <store/store.hpp>
#include <store/mockDriver.hpp>

using namespace store;
using namespace store::mocks;

void inline initLogging()
{
    static bool initialized = false;

    if (!initialized)
    {
        // Logging setup
        logging::LoggingConfig logConfig;
        logConfig.logLevel = "off";
        logConfig.filePath = "";
        logging::loggingInit(logConfig);
        initialized = true;
    }
}

class StoreBuildTest : public ::testing::Test
{
    protected:

    void SetUp() override
    {
        initLogging();
    }
};

class StoreTest : public ::testing::Test
{
protected:
    std::shared_ptr<MockDriver> driver;
    std::shared_ptr<Store> store;

    void SetUp() override
    {
        initLogging();
        driver = std::make_shared<MockDriver>();
        EXPECT_CALL(*driver, readRoot()).WillOnce(testing::Return(driverReadColResp({})));
        store = std::make_shared<Store>(driver);
    }

    void TearDown() override
    {
    }

};

TEST_F(StoreBuildTest, EmptyStore)
{
    auto driver = std::make_shared<MockDriver>();
    EXPECT_CALL(*driver, readRoot()).WillOnce(testing::Return(driverReadColResp({})));
    std::shared_ptr<Store> store;
    ASSERT_NO_THROW(store = std::make_shared<Store>(driver));
    ASSERT_EQ(store->listNamespaces().size(), 0);
}

TEST_F(StoreBuildTest, NullDriver)
{
    std::shared_ptr<Store> store;
    ASSERT_THROW(store = std::make_shared<Store>(nullptr), std::runtime_error);
}

TEST_F(StoreBuildTest, WithNs)
{
    // TODO implement
    GTEST_SKIP();
    auto driver = std::make_shared<MockDriver>();
    auto expectedResp = driverReadColResp({"ns1", "ns2"});
    base::Name expectedNs1("ns1");
    base::Name expectedNs2("ns2");
    Col Ns1Col {"ns1/doc"};
    Col Ns2Col {"ns2/doc"};
    auto expectedNs = base::getResponse<Col>(expectedResp);
    EXPECT_CALL(*driver, readRoot()).WillOnce(testing::Return(expectedNs));
    EXPECT_CALL(*driver, existsCol(expectedNs1)).WillOnce(testing::Return(true));
    EXPECT_CALL(*driver, existsCol(expectedNs2)).WillOnce(testing::Return(true));
    EXPECT_CALL(*driver, readCol(expectedNs1)).WillOnce(testing::Return(driverReadColResp(Ns1Col)));
    EXPECT_CALL(*driver, readCol(expectedNs2)).WillOnce(testing::Return(driverReadColResp(Ns2Col)));
    EXPECT_CALL(*driver, existsDoc(Ns1Col[0])).WillOnce(testing::Return(true));
    EXPECT_CALL(*driver, existsDoc(Ns2Col[0])).WillOnce(testing::Return(true));
    EXPECT_CALL(*driver, readDoc(Ns1Col[0])).WillOnce(testing::Return(driverReadDocResp({})));
    EXPECT_CALL(*driver, readDoc(Ns2Col[0])).WillOnce(testing::Return(driverReadDocResp({})));

    ON_CALL(*driver, existsCol(testing::_)).WillByDefault(testing::Return(false));
    ON_CALL(*driver, existsDoc(testing::_)).WillByDefault(testing::Return(false));

    std::shared_ptr<Store> store;
    ASSERT_NO_THROW(store = std::make_shared<Store>(driver));
    ASSERT_EQ(store->listNamespaces().size(), 2);
    ASSERT_TRUE(store->listNamespaces()[0].name() == expectedNs[0]);
    ASSERT_TRUE(store->listNamespaces()[1].name() == expectedNs[1]);
}