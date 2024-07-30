#include <gtest/gtest.h>

#include <base/logging.hpp>

#include <mmdb/manager.hpp>

namespace
{
const std::string g_maxmindDbPath {MMDB_PATH_TEST};
} // namespace

class ManagerTest : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }
};

TEST_F(ManagerTest, create)
{
    ASSERT_NO_THROW(mmdb::Manager manager);
}

TEST_F(ManagerTest, addHandler)
{
    mmdb::Manager manager;
    ASSERT_NO_THROW(manager.addHandler("test", g_maxmindDbPath));                  // OK
    ASSERT_THROW(manager.addHandler("test", g_maxmindDbPath), std::runtime_error); // Handler already exists
}

TEST_F(ManagerTest, removeHandler)
{
    mmdb::Manager manager;
    manager.addHandler("test", g_maxmindDbPath);
    ASSERT_NO_THROW(manager.removeHandler("test")); // OK
    ASSERT_NO_THROW(manager.removeHandler("test")); // OK, handler does not exist but it is not an error
}

TEST_F(ManagerTest, getHandler)
{
    mmdb::Manager manager;
    manager.addHandler("test", g_maxmindDbPath);
    auto handler = manager.getHandler("test");
    ASSERT_FALSE(base::isError(handler));
    ASSERT_TRUE(base::getResponse(handler) != nullptr);
    handler = manager.getHandler("test2");

    ASSERT_TRUE(base::isError(handler));
    ASSERT_EQ(base::getError(handler).message, "Handler does not exist");
}
