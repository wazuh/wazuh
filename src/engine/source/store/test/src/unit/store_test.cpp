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

// Internal root namespace
const base::Name nsPrefix ("namespaces"); // Prefix in the store for the namespaces

// Add prefix to the col names
base::Name addPrefix(const base::Name& name)
{
    return nsPrefix + name;
}
Col addPrefix(const Col& col)
{
    Col newCol;
    for (const auto& name : col)
    {
        newCol.push_back(addPrefix(name));
    }
    return newCol;
}

// Remove prefix from the col names
base::Name removePrefix(const base::Name& name, std::size_t level = 1)
{
    if (name.parts().size() <= level)
    {
        throw std::runtime_error("Cannot remove prefix from name: " + name.fullName());
    }
    auto it = name.parts().begin();
    std::advance(it, level);
    return  base::Name(std::vector<std::string> {it, name.parts().end()});
}

Col removePrefix(const Col& col, std::size_t level = 1)
{
    Col newCol;
    for (const auto& name : col)
    {
        newCol.push_back(removePrefix(name, level));
    }
    return newCol;
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
    base::Name nsPrefix;

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
    EXPECT_CALL(*driver, existsCol(base::Name("namespaces"))).WillOnce(testing::Return(false));
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
    auto driver = std::make_shared<MockDriver>();

    base::Name ns1 ("ns1");
    base::Name ns2 ("ns2");
    base::Name fullNs1 = addPrefix(ns1);
    base::Name fullNs2 = addPrefix(ns2);
    auto expectedResp = driverReadColResp(fullNs1, fullNs2);

    base::Name rNs1Doc = fullNs1 + base::Name("doc");
    base::Name rNs2Doc = fullNs2 + base::Name("doc2");
    Col Ns1Col {rNs1Doc};
    Col Ns2Col {rNs2Doc};
    auto expectedNs = base::getResponse<Col>(expectedResp);

    EXPECT_CALL(*driver, existsCol(base::Name("namespaces"))).WillOnce(testing::Return(true));
    // Return 2 namespaces
    EXPECT_CALL(*driver, readCol(base::Name("namespaces"))).WillOnce(testing::Return(expectedResp));

    // Check if ns1 is a namespace
    EXPECT_CALL(*driver, existsCol(fullNs1)).WillOnce(testing::Return(true));

    // - Visit ns1
    EXPECT_CALL(*driver, existsDoc(fullNs1)).WillOnce(testing::Return(false));
    // - - Get the doc in ns1
    EXPECT_CALL(*driver, readCol(fullNs1)).WillOnce(testing::Return(driverReadColResp(Ns1Col)));
    // - - visit and check if doc in ns1 is a collection or document
    EXPECT_CALL(*driver, existsDoc(rNs1Doc)).WillOnce(testing::Return(true));

    // Check if ns2 is a namespace
    EXPECT_CALL(*driver, existsCol(fullNs2)).WillOnce(testing::Return(true));

    // - Visit ns2
    EXPECT_CALL(*driver, existsDoc(fullNs2)).WillOnce(testing::Return(false));
    // - - Get the doc in ns2
    EXPECT_CALL(*driver, readCol(fullNs2)).WillOnce(testing::Return(driverReadColResp(Ns2Col)));
    // - - visit and check if doc in ns2 is a collection or document
    EXPECT_CALL(*driver, existsDoc(rNs2Doc)).WillOnce(testing::Return(true));

    std::shared_ptr<Store> store;
    ASSERT_NO_THROW(store = std::make_shared<Store>(driver));
    ASSERT_EQ(store->listNamespaces().size(), 2);
    ASSERT_TRUE(store->listNamespaces()[0].name() == ns1);
    ASSERT_TRUE(store->listNamespaces()[1].name() == ns2);
}
