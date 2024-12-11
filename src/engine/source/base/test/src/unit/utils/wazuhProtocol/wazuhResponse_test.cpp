#include <gtest/gtest.h>

#include <base/utils/wazuhProtocol/wazuhResponse.hpp>

TEST(WazuhResponse, constructor)
{
    const json::Json jdata {R"({"test": "data"})"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_EQ(wresponse.data(), jdata);
    EXPECT_EQ(wresponse.error(), error);
    EXPECT_EQ(wresponse.message(), message);
}

TEST(WazuhResponse, toString)
{
    const json::Json jdata {R"({"test": "data"})"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_EQ(wresponse.toString(), R"({"data":{"test":"data"},"error":0,"message":"test message"})");
}

TEST(WazuhResponse, toStringNoMessage)
{
    const json::Json jdata {R"({"test": "data"})"};
    const int error {0};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error};
    EXPECT_EQ(wresponse.toString(), R"({"data":{"test":"data"},"error":0})");
}

TEST(WazuhResponse, toStringEmptyMessage)
{
    const json::Json jdata {R"({"test": "data"})"};
    const int error {0};
    const std::string message {""};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_EQ(wresponse.toString(), R"({"data":{"test":"data"},"error":0})");
}

TEST(WazuhResponse, toStringEmptyData)
{
    const json::Json jdata {R"({})"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_EQ(wresponse.toString(), R"({"data":{},"error":0,"message":"test message"})");
}

TEST(WazuhResponse, toStringArrayData)
{
    const json::Json jdata {R"([{"test": "data"}])"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_EQ(wresponse.toString(), R"({"data":[{"test":"data"}],"error":0,"message":"test message"})");
}

TEST(WazuhResponse, toStringEmptyDataEmptyMessage)
{
    const json::Json jdata {R"({})"};
    const int error {0};
    const std::string message {""};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_EQ(wresponse.toString(), R"({"data":{},"error":0})");
}

TEST(WazuhResponse, validateOkObject)
{
    const json::Json jdata {R"({"test": "data"})"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(WazuhResponse, validateOkArray)
{
    const json::Json jdata {R"([{"test": "data"}])"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(WazuhResponse, validateOkEmptyObject)
{
    const json::Json jdata {R"({})"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(WazuhResponse, validateOkEmptyArray)
{
    const json::Json jdata {R"([])"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(WazuhResponse, validateOkEmptyMessage)
{
    const json::Json jdata {R"({"test": "data"})"};
    const int error {0};
    const std::string message {""};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(WazuhResponse, validateOkEmptyData)
{
    const json::Json jdata {R"({})"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(WazuhResponse, validateOkEmptyDataEmptyMessage)
{
    const json::Json jdata {R"({})"};
    const int error {0};
    const std::string message {""};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_TRUE(wresponse.isValid());
}

TEST(WazuhResponse, validateErrorInvalidDataStr)
{
    const json::Json jdata {R"("test")"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_FALSE(wresponse.isValid());
}

TEST(WazuhResponse, validateErrorInvalidDataInt)
{
    const json::Json jdata {R"(1)"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_FALSE(wresponse.isValid());
}

TEST(WazuhResponse, validateErrorInvalidDataBool)
{
    const json::Json jdata {R"(true)"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_FALSE(wresponse.isValid());
}

TEST(WazuhResponse, validateErrorInvalidDataNull)
{
    const json::Json jdata {R"(null)"};
    const int error {0};
    const std::string message {"test message"};
    const base::utils::wazuhProtocol::WazuhResponse wresponse {jdata, error, message};
    EXPECT_FALSE(wresponse.isValid());
}
