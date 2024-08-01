#include <gtest/gtest.h>

#include <base/logging.hpp>

#include <mmdb/manager.hpp>

class HandlerTest : public ::testing::Test
{
protected:
    std::shared_ptr<mmdb::IHandler> m_handler;
    const std::string ipFullData {"1.2.3.4"};
    const std::string ipMinimalData {"1.2.3.5"};
    const std::string ipNotFound {"1.2.3.6"};

    void SetUp() override
    {
        logging::testInit();
        mmdb::Manager manager;
        ASSERT_NO_THROW(manager.addHandler("test", MMDB_PATH_TEST));
        m_handler = base::getResponse(manager.getHandler("test"));
    }
};

TEST_F(HandlerTest, isAvailable)
{
    ASSERT_TRUE(m_handler->isAvailable());
}

TEST_F(HandlerTest, lookupOk)
{
    ASSERT_TRUE(m_handler->lookup(ipFullData)->hasData());
    ASSERT_TRUE(m_handler->lookup(ipMinimalData)->hasData());
    ASSERT_FALSE(m_handler->lookup(ipNotFound)->hasData());
    ASSERT_THROW(m_handler->lookup("invalid_ip"), std::runtime_error);
}
