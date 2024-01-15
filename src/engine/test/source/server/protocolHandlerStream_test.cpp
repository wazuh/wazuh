#include <gtest/gtest.h>

#include "server/protocolHandlers/wStream.hpp"

using namespace engineserver::ph;

class WStreamTest : public ::testing::Test
{
public:
    void mockMessageHandler(const std::string& message, std::function<void(const std::string&)> callback)
    {
        auto response =  "RESPONSE: " + message;
        callback(response);
    }

    WStream wstream{std::bind(&WStreamTest::mockMessageHandler, this, std::placeholders::_1, std::placeholders::_2)};
};

std::string uintToLittleEndianBytes(unsigned int num) {
    std::string result(4, '\0');

    for (int i = 0; i < 4; ++i) {
        result[i] = static_cast<char>(num & 0xFF);
        num >>= 8;
    }

    return result;
}

TEST_F(WStreamTest, onDataProcessing)
{
    std::string payload = "HELLO";
    std::string header = uintToLittleEndianBytes(payload.size());
    std::string data = header + payload;

    auto result = wstream.onData(data);

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result.value().size(), 1);
    EXPECT_EQ((*result)[0], "HELLO");

    std::string payload2("WORLD");
    std::string header2 = uintToLittleEndianBytes(payload2.size());
    std::string data2 = header2 + payload2;

    auto result2 = wstream.onData(data2);

    ASSERT_TRUE(result2.has_value());
    ASSERT_EQ(result2.value().size(), 1);
    EXPECT_EQ((*result2)[0], "WORLD");
}

TEST_F(WStreamTest, onDataProcessingPartialData)
{
    std::string payload("HELLO WORLD");
    std::string header = uintToLittleEndianBytes(payload.size());

    std::string parcialData1 = header + payload.substr(0, 5);
    auto result1 = wstream.onData(parcialData1);

    ASSERT_FALSE(result1.has_value()) << "Partial data should not be processed but it was: " << result1.value().size();

    std::string parcialData2 = payload.substr(5);
    auto result2 = wstream.onData(parcialData2);

    ASSERT_TRUE(result2.has_value());
    ASSERT_EQ(result2->size(), 1);
    EXPECT_EQ((*result2)[0], "HELLO WORLD");
}

TEST_F(WStreamTest, onMessageProcessing)
{
    std::string response;
    auto callbackFn = [&response](const std::string& res)
    {
        response = res;
    };
    wstream.onMessage("TEST", callbackFn);
    EXPECT_EQ(response, "RESPONSE: TEST");
}

TEST_F(WStreamTest, streamToSend)
{
    std::string message("HELLO");
    auto [buffer, size] = wstream.streamToSend(std::make_shared<std::string>(message));

    auto headerExpected = uintToLittleEndianBytes(message.size());

    EXPECT_EQ(headerExpected, std::string(buffer.get(), 4));
    auto payloadExpected = std::string(buffer.get() + 4, size - 4);
    EXPECT_EQ(payloadExpected, message);
}

TEST_F(WStreamTest, getBusyResponse)
{
    auto [buffer, size] = wstream.getBusyResponse();
    std::string expected("BUSY");
    auto headerExpected = uintToLittleEndianBytes(expected.size());

    EXPECT_EQ(headerExpected, std::string(buffer.get(), 4));
    auto payloadExpected = std::string(buffer.get() + 4, size - 4);
    EXPECT_EQ(payloadExpected, expected);
}

TEST_F(WStreamTest, getErrorResponse)
{
    std::string error = wstream.getErrorResponse();
    EXPECT_EQ(error, "ERROR");
}

TEST_F(WStreamTest, onDataPayloadSizeExceeded)
{
    int maxPayloadSize = 1024 * 1024 * 10;
    WStream wstream2(std::bind(&WStreamTest::mockMessageHandler, this, std::placeholders::_1, std::placeholders::_2), maxPayloadSize);

    int exceededSize = maxPayloadSize + 1;
    std::string data("\x00\xA0\x96\x01", 4); // Exceeded size encoded in 4 bytes
    EXPECT_THROW(wstream2.onData(data), std::runtime_error);
}
