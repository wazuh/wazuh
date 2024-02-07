#include <gtest/gtest.h>

#include <handler.hpp>

namespace
{
const std::string g_maxmindDbPath {MMDB_PATH_TEST};
const std::string g_ipFullData {"1.2.3.4"};
const std::string g_ipMinimalData {"1.2.3.5"};
const std::string g_ipNotFound {"1.2.3.6"};

json::Json g_jIpFullData {R"(
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

const json::Json g_jIpMinimalDataJDUMP {R"(
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

    void SetUp() override
    {
        logging::testInit();
        auto handler = std::make_shared<mmdb::Handler>(g_maxmindDbPath);
        auto error = handler->open();
        if (error)
        {
            throw std::runtime_error(error.value().message);
        }
        m_handler = handler;

        // Fix floating point precision
        g_jIpFullData.setFloat(122.0838, "/test_float");
    }
};

} // namespace
TEST_F(ResultTest, hasData)
{
    ASSERT_TRUE(m_handler->lookup(g_ipFullData)->hasData());
    ASSERT_TRUE(m_handler->lookup(g_ipMinimalData)->hasData());
    ASSERT_FALSE(m_handler->lookup(g_ipNotFound)->hasData());
}

TEST_F(ResultTest, mmdump)
{
    ASSERT_EQ(m_handler->lookup(g_ipFullData)->mmDump(), g_jIpFullData);
    ASSERT_EQ(m_handler->lookup(g_ipMinimalData)->mmDump(), g_jIpMinimalDataJDUMP);
    ASSERT_EQ(m_handler->lookup(g_ipNotFound)->mmDump(), json::Json {});
}

TEST_F(ResultTest, getString)
{

    auto res = m_handler->lookup(g_ipFullData)->getString("test_map.test_str2");
    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(base::getResponse(res), "Wazuh2");
    res = m_handler->lookup(g_ipMinimalData)->getString("test_map.test_str2");
    ASSERT_TRUE(base::isError(res));
}

TEST_F(ResultTest, getUint32)
{
    auto res = m_handler->lookup(g_ipFullData)->getUint32("test_uint32");
    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(base::getResponse(res), 94043);
    res = m_handler->lookup(g_ipMinimalData)->getUint32("test_uint32");
    ASSERT_TRUE(base::isError(res));
}

TEST_F(ResultTest, getDouble)
{
    auto res = m_handler->lookup(g_ipFullData)->getDouble("test_double");
    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(base::getResponse(res), 37.386);
    res = m_handler->lookup(g_ipMinimalData)->getDouble("test_double");
    ASSERT_TRUE(base::isError(res));
}

TEST_F(ResultTest, getAsJson)
{
    auto res = m_handler->lookup(g_ipFullData);
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

TEST_F(ResultTest, getArrayStr)
{
    auto res = m_handler->lookup(g_ipFullData)->getString("test_array.0");
    ASSERT_FALSE(base::isError(res));
    ASSERT_EQ(base::getResponse(res), "a");
}
