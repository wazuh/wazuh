#include <gtest/gtest.h>

#include <handler.hpp>

namespace
{
const std::string g_maxmindDbPath {MMDB_PATH_TEST};
const std::string g_ipFullData {"1.2.3.4"};
const std::string g_ipMinimalData {"1.2.3.5"};
const std::string g_ipNotFound {"1.2.3.6"};
} // namespace

class HandlerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();
    }
};

TEST_F(HandlerTest, openOk)
{
    mmdb::Handler handler(g_maxmindDbPath);
    ASSERT_FALSE(handler.isAvailable());
    auto error = handler.open();
    ASSERT_FALSE(error);
    ASSERT_TRUE(handler.isAvailable());
}

TEST_F(HandlerTest, openFail)
{
    mmdb::Handler handler("invalid_path");
    ASSERT_FALSE(handler.isAvailable());
    auto error = handler.open();
    ASSERT_TRUE(error);
    ASSERT_FALSE(handler.isAvailable());
}

TEST_F(HandlerTest, close)
{
    mmdb::Handler handler(g_maxmindDbPath);
    ASSERT_FALSE(handler.isAvailable());
    auto error = handler.open();
    ASSERT_FALSE(error);
    ASSERT_TRUE(handler.isAvailable());
    handler.close();
    ASSERT_FALSE(handler.isAvailable());
}

TEST_F(HandlerTest, lookupOk)
{
    mmdb::Handler handler(g_maxmindDbPath);
    auto error = handler.open();
    ASSERT_FALSE(error);
    ASSERT_TRUE(handler.isAvailable());

    ASSERT_TRUE(handler.lookup(g_ipFullData)->hasData());
    ASSERT_TRUE(handler.lookup(g_ipMinimalData)->hasData());
    ASSERT_FALSE(handler.lookup(g_ipNotFound)->hasData());
    ASSERT_THROW(handler.lookup("invalid_ip"), std::runtime_error);
}
