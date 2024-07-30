#include <gtest/gtest.h>

#include <base/logging.hpp>

#include <mmdb/manager.hpp>


namespace
{

constexpr auto JSON_IP_FULLDATA {R"(
{
  "test_array": [
    "a",
    "b",
    "c"
  ],
  "test_boolean": true,
  "test_bytes": "abcd",
  "test_double": 37.386,
  "test_map": {
    "test_str1": "Wazuh",
    "test_str2": "Wazuh2"
  },
  "test_uint128": "0x0000000000000000ab54a98ceb1f0ad2",
  "test_uint16": 123,
  "test_uint32": 94043,
  "test_uint64": "1234567890"
}
)"};

constexpr auto JSON_IP_MINDATA  {R"(
{
  "test_map": {
    "test_str1": "Missing values"
  }
}
)"};

class ResultTest : public ::testing::Test
{
protected:
    std::shared_ptr<mmdb::IHandler> m_handler;

    const std::string m_ipFullData {"1.2.3.4"};
    const std::string m_ipMinimalData {"1.2.3.5"};
    const std::string m_ipNotFound {"1.2.3.6"};

    json::Json m_jDumpFull {};
    json::Json m_jDumpMinimal {};

    void SetUp() override
    {
        logging::testInit();
        mmdb::Manager manager;
        ASSERT_NO_THROW(manager.addHandler("test", MMDB_PATH_TEST));
        m_handler = base::getResponse(manager.getHandler("test"));

        m_jDumpFull = json::Json {JSON_IP_FULLDATA};
        m_jDumpFull.setFloat(122.0838, "/test_float");
        m_jDumpMinimal = json::Json  {JSON_IP_MINDATA};
    }
};

} // namespace
TEST_F(ResultTest, hasData)
{
    ASSERT_TRUE(m_handler->lookup(m_ipFullData)->hasData());
    ASSERT_TRUE(m_handler->lookup(m_ipMinimalData)->hasData());
    ASSERT_FALSE(m_handler->lookup(m_ipNotFound)->hasData());
}

TEST_F(ResultTest, mmdump)
{
    ASSERT_EQ(m_handler->lookup(m_ipFullData)->mmDump(), m_jDumpFull);
    ASSERT_EQ(m_handler->lookup(m_ipMinimalData)->mmDump(), m_jDumpMinimal);
    ASSERT_EQ(m_handler->lookup(m_ipNotFound)->mmDump(), json::Json {});
}

TEST_F(ResultTest, getString)
{

    auto res = m_handler->lookup(m_ipFullData)->getString("test_map.test_str2");
    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(base::getResponse(res), "Wazuh2");
    res = m_handler->lookup(m_ipMinimalData)->getString("test_map.test_str2");
    ASSERT_TRUE(base::isError(res));
}

TEST_F(ResultTest, getUint32)
{
    auto res = m_handler->lookup(m_ipFullData)->getUint32("test_uint32");
    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(base::getResponse(res), 94043);
    res = m_handler->lookup(m_ipMinimalData)->getUint32("test_uint32");
    ASSERT_TRUE(base::isError(res));
}

TEST_F(ResultTest, getDouble)
{
    auto res = m_handler->lookup(m_ipFullData)->getDouble("test_double");
    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(base::getResponse(res), 37.386);
    res = m_handler->lookup(m_ipMinimalData)->getDouble("test_double");
    ASSERT_TRUE(base::isError(res));
}

TEST_F(ResultTest, getAsJson)
{
    auto res = m_handler->lookup(m_ipFullData);
    ASSERT_TRUE(res->hasData());

    // No support for arrays and maps
    auto j = res->getAsJson("test_array");
    ASSERT_TRUE(base::isError(j));

    j = res->getAsJson("test_map");
    ASSERT_TRUE(base::isError(j));

    // Supported types
    // Boolean
    j = res->getAsJson("test_boolean");
    ASSERT_FALSE(base::isError(j));
    ASSERT_EQ(base::getResponse(j), json::Json {"true"});

    // Bytes
    j = res->getAsJson("test_bytes");
    ASSERT_FALSE(base::isError(j));
    ASSERT_EQ(base::getResponse(j), json::Json {R"("abcd")"});

    // Double
    j = res->getAsJson("test_double");
    ASSERT_FALSE(base::isError(j));
    ASSERT_EQ(base::getResponse(j), json::Json {"37.386"});

    // Uint128
    j = res->getAsJson("test_uint128");
    ASSERT_FALSE(base::isError(j));
    ASSERT_EQ(base::getResponse(j), json::Json {R"("0x0000000000000000ab54a98ceb1f0ad2")"});

    // Uint16
    j = res->getAsJson("test_uint16");
    ASSERT_FALSE(base::isError(j));
    ASSERT_EQ(base::getResponse(j), json::Json {"123"});

    // Uint32
    j = res->getAsJson("test_uint32");
    ASSERT_FALSE(base::isError(j));
    ASSERT_EQ(base::getResponse(j), json::Json {"94043"});

    // Uint64
    j = res->getAsJson("test_uint64");
    ASSERT_FALSE(base::isError(j));
    ASSERT_EQ(base::getResponse(j), json::Json {R"("1234567890")"});
}
