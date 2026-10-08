/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "socketWrapper_test.hpp"
#include "osPrimitives.hpp"
#include "socketWrapper.hpp"
#include <algorithm>
#include <cstdint>
#include <gmock/gmock.h>

void SocketWrapperTest::SetUp() {};
void SocketWrapperTest::TearDown() {};

using testing::_;
using testing::DoAll;
using testing::Invoke;
using testing::Return;
using testing::SetArgPointee;
using testing::SetArrayArgument;

class OSWrapper
{
public:
    OSWrapper() = default;
    ~OSWrapper() = default;

    MOCK_METHOD(int, socket, (int, int, int));
    MOCK_METHOD(int, bind, (int, const struct sockaddr*, socklen_t));
    MOCK_METHOD(int, listen, (int, int));
    MOCK_METHOD(int, accept, (int, struct sockaddr*, socklen_t*));
    MOCK_METHOD(int, connect, (int, const struct sockaddr*, socklen_t));
    MOCK_METHOD(int, setsockopt, (int, int, int, const void*, socklen_t));
    MOCK_METHOD(int, close, (int));
    MOCK_METHOD(ssize_t, recv, (int, void*, size_t, int));
    MOCK_METHOD(ssize_t, send, (int, const void*, size_t, int));
    MOCK_METHOD(int, shutdown, (int, int));
};

TEST_F(SocketWrapperTest, SocketWrapperTestInstance)
{
    Socket<OSWrapper> socketWrapper;
}

TEST_F(SocketWrapperTest, UnixAddressPathToLong)
{
    constexpr auto MAX_SUN_PATH = 108;
    std::string path(MAX_SUN_PATH + 10, 'a');
    EXPECT_THROW(UnixAddress::builder().address(path).build(), std::runtime_error);
}

TEST_F(SocketWrapperTest, ConnectSuccess)
{
    Socket<OSWrapper> socketWrapper;
    EXPECT_CALL(socketWrapper, socket(_, _, _)).WillOnce(Return(123));
    EXPECT_CALL(socketWrapper, connect(123, _, _)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, setsockopt(123, _, _, _, _)).Times(2);

    EXPECT_CALL(socketWrapper, close(123)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, shutdown(123, _)).WillOnce(Return(0));

    auto unixAddress {UnixAddress::builder().address("test_socket").build()};
    EXPECT_NO_THROW({ socketWrapper.connect(unixAddress.data()); });
}

TEST_F(SocketWrapperTest, ConnectFailure)
{
    Socket<OSWrapper> socketWrapper;
    EXPECT_CALL(socketWrapper, socket(_, _, _)).WillOnce(Return(123));
    EXPECT_CALL(socketWrapper, connect(123, _, _)).WillOnce(Return(-1));
    EXPECT_CALL(socketWrapper, close(123)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, shutdown(123, _)).WillOnce(Return(0));

    auto unixAddress {UnixAddress::builder().address("test_socket").build()};
    EXPECT_THROW({ socketWrapper.connect(unixAddress.data()); }, std::runtime_error);
}

TEST_F(SocketWrapperTest, ConnectFailureSocketCreation)
{
    Socket<OSWrapper> socketWrapper;
    EXPECT_CALL(socketWrapper, socket(_, _, _)).WillOnce(Return(-1));

    auto unixAddress {UnixAddress::builder().address("test_socket").build()};
    EXPECT_THROW({ socketWrapper.connect(unixAddress.data()); }, std::runtime_error);
}

TEST_F(SocketWrapperTest, ConnectInProgress)
{
    Socket<OSWrapper> socketWrapper;
    EXPECT_CALL(socketWrapper, socket(_, _, _)).WillOnce(Return(123));
    EXPECT_CALL(socketWrapper, connect(123, _, _)).WillOnce(Return(-1));
    EXPECT_CALL(socketWrapper, close(123)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, shutdown(123, _)).WillOnce(Return(0));

    auto unixAddress {UnixAddress::builder().address("test_socket").build()};
    EXPECT_THROW({ socketWrapper.connect(unixAddress.data()); }, std::runtime_error);
}

TEST_F(SocketWrapperTest, DISABLED_ReadSuccess)
{
    // Create a mock object.
    Socket<OSWrapper> socketWrapper;

    // Set up the test data.
    const int sock = 123;
    const ssize_t metaDataSize = PACKET_FIELD_SIZE;
    const std::vector<char> header(HEADER_FIELD_SIZE, 0);
    std::vector<char> data(10, 0);
    for (size_t i = 0; i < data.size(); i++)
    {
        data[i] = i + '0';
    }

    const ssize_t packetSize = header.size() + data.size();

    // Set up the expectations.
    EXPECT_CALL(socketWrapper, recv(sock, _, _, _))
        .WillOnce(DoAll(Invoke(
                            [&packetSize](int, void* buffer, size_t size, int)
                            {
                                std::copy((char*)&packetSize, (char*)&packetSize + size, (char*)buffer);
                                return size;
                            }),
                        Return(metaDataSize)))
        .WillOnce(DoAll(Invoke(
                            [&data, &header](int, void* buffer, size_t size, int)
                            {
                                std::copy(header.begin(), header.end(), (char*)buffer);
                                std::copy(data.begin(), data.end(), (char*)buffer + HEADER_FIELD_SIZE);
                                return size;
                            }),
                        Return(packetSize)));

    // Set up the callback.
    std::function<void(const int, const char*, uint32_t, const char*, uint32_t)> callbackBody =
        [&](const int sock, const char* bodyData, uint32_t bodySize, const char*, uint32_t headerSize)
    {
        EXPECT_EQ(sock, 123);
        EXPECT_EQ(headerSize, 0u);
        EXPECT_EQ(bodySize, data.size());
        EXPECT_STREQ(bodyData, data.data());
    };
    // Connect expect calls
    EXPECT_CALL(socketWrapper, socket(_, _, _)).WillOnce(Return(123));
    EXPECT_CALL(socketWrapper, connect(123, _, _)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, setsockopt(123, _, _, _, _)).Times(2);

    EXPECT_CALL(socketWrapper, close(123)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, shutdown(123, _)).WillOnce(Return(0));

    // Connect call.
    auto unixAddress {UnixAddress::builder().address("test_socket").build()};
    EXPECT_NO_THROW({ socketWrapper.connect(unixAddress.data()); });

    // Read header.
    EXPECT_NO_THROW({ socketWrapper.read(callbackBody); });

    // Read body
    EXPECT_NO_THROW({ socketWrapper.read(callbackBody); });
}

TEST_F(SocketWrapperTest, DISABLED_ReadPartialHeader)
{
    // Create a mock object.
    Socket<OSWrapper> socketWrapper;

    // Set up the test data.
    const int sock = 123;
    const ssize_t metaDataSize = PACKET_FIELD_SIZE;
    const std::vector<char> header(HEADER_FIELD_SIZE, 0);
    std::vector<char> data(10, 0);
    for (size_t i = 0; i < data.size(); i++)
    {
        data[i] = i + '0';
    }

    const ssize_t packetSize = header.size() + data.size();

    // Set up the expectations.
    EXPECT_CALL(socketWrapper, recv(sock, _, _, _))
        .WillOnce(DoAll(Invoke([&packetSize](int, void* buffer, size_t size, int)
                               { std::copy((char*)&packetSize, (char*)&packetSize + (size / 2), (char*)buffer); }),
                        Return(metaDataSize / 2)))
        .WillOnce(
            DoAll(Invoke([&packetSize](int, void* buffer, size_t size, int)
                         { std::copy((char*)&packetSize + (size / 2), (char*)&packetSize + size, (char*)buffer); }),
                  Return(metaDataSize / 2)))
        .WillOnce(DoAll(Invoke(
                            [&data, &header](int, void* buffer, size_t, int)
                            {
                                std::copy(header.begin(), header.end(), (char*)buffer);
                                std::copy(data.begin(), data.end(), (char*)buffer + HEADER_FIELD_SIZE);
                            }),
                        Return(packetSize)));

    // Set up the callback.
    std::function<void(const int, const char*, uint32_t, const char*, uint32_t)> callbackBody =
        [&](const int sock, const char* bodyData, uint32_t bodySize, const char*, uint32_t headerSize)
    {
        EXPECT_EQ(sock, 123);
        EXPECT_EQ(headerSize, 0u);
        EXPECT_EQ(bodySize, data.size());
        EXPECT_STREQ(bodyData, data.data());
    };
    // Connect expect calls
    EXPECT_CALL(socketWrapper, socket(_, _, _)).WillOnce(Return(123));
    EXPECT_CALL(socketWrapper, connect(123, _, _)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, setsockopt(123, _, _, _, _)).Times(2);

    EXPECT_CALL(socketWrapper, close(123)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, shutdown(123, _)).WillOnce(Return(0));

    // Connect call.
    auto unixAddress {UnixAddress::builder().address("test_socket").build()};
    EXPECT_NO_THROW({ socketWrapper.connect(unixAddress.data()); });

    // Read header.
    EXPECT_NO_THROW({ socketWrapper.read(callbackBody); });

    // Read header.
    EXPECT_NO_THROW({ socketWrapper.read(callbackBody); });

    // Read body
    EXPECT_NO_THROW({ socketWrapper.read(callbackBody); });
}

TEST_F(SocketWrapperTest, DISABLED_ReadPartialBody)
{
    // Create a mock object.
    Socket<OSWrapper> socketWrapper;

    // Set up the test data.
    const int sock = 123;
    const ssize_t metaDataSize = PACKET_FIELD_SIZE;
    const std::vector<char> header(HEADER_FIELD_SIZE, 0);
    std::vector<char> data(10, 0);
    for (size_t i = 0; i < data.size(); i++)
    {
        data[i] = i + '0';
    }

    const ssize_t packetSize = header.size() + data.size();

    // Set up the expectations.
    EXPECT_CALL(socketWrapper, recv(sock, _, _, _))
        .WillOnce(DoAll(Invoke([&packetSize](int, void* buffer, size_t size, int)
                               { std::copy((char*)&packetSize, (char*)&packetSize + size, (char*)buffer); }),
                        Return(metaDataSize / 2)))
        .WillOnce(DoAll(Invoke(
                            [&data, &header](int, void* buffer, size_t, int)
                            {
                                std::copy(header.begin(), header.end(), (char*)buffer);
                                std::copy(
                                    data.begin(), data.begin() + data.size() / 2, (char*)buffer + HEADER_FIELD_SIZE);
                            }),
                        Return(packetSize)))
        .WillOnce(DoAll(Invoke(
                            [&data, &header](int, void* buffer, size_t, int)
                            {
                                std::copy(data.begin() + data.size() / 2,
                                          data.end(),
                                          (char*)buffer + HEADER_FIELD_SIZE + data.size() / 2);
                            }),
                        Return(packetSize)));

    // Set up the callback.
    std::function<void(const int, const char*, uint32_t, const char*, uint32_t)> callbackBody =
        [&](const int sock, const char* bodyData, uint32_t bodySize, const char*, uint32_t headerSize)
    {
        EXPECT_EQ(sock, 123);
        EXPECT_EQ(headerSize, 0u);
        EXPECT_EQ(bodySize, data.size());
        EXPECT_STREQ(bodyData, data.data());
    };
    // Connect expect calls
    EXPECT_CALL(socketWrapper, socket(_, _, _)).WillOnce(Return(123));
    EXPECT_CALL(socketWrapper, connect(123, _, _)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, setsockopt(123, _, _, _, _)).Times(2);

    EXPECT_CALL(socketWrapper, close(123)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, shutdown(123, _)).WillOnce(Return(0));

    // Connect call.
    auto unixAddress {UnixAddress::builder().address("test_socket").build()};
    EXPECT_NO_THROW({ socketWrapper.connect(unixAddress.data()); });

    // Read header.
    EXPECT_NO_THROW({ socketWrapper.read(callbackBody); });

    // Read body.
    EXPECT_NO_THROW({ socketWrapper.read(callbackBody); });

    // Read body.
    EXPECT_NO_THROW({ socketWrapper.read(callbackBody); });
}

TEST_F(SocketWrapperTest, DISABLED_ReadSuccessBufferIncrement)
{
    // Create a mock object.
    Socket<OSWrapper> socketWrapper;

    // Set up the test data.
    const int sock = 123;
    const ssize_t metaDataSize = PACKET_FIELD_SIZE;
    const std::vector<char> header(HEADER_FIELD_SIZE, 0);
    const size_t initialRecvBufferSize = socketWrapper.recvBufferSize();
    const size_t targetSize = socketWrapper.recvBufferSize() * 2;
    std::vector<char> data(targetSize - HEADER_FIELD_SIZE, 0);
    for (size_t i = 0; i < data.size(); i++)
    {
        data[i] = i + '0';
    }

    const ssize_t packetSize = header.size() + data.size();

    // Set up the expectations.
    EXPECT_CALL(socketWrapper, recv(sock, _, _, _))
        .WillOnce(DoAll(Invoke(
                            [&packetSize](int, void* buffer, size_t size, int)
                            {
                                std::copy((char*)&packetSize, (char*)&packetSize + size, (char*)buffer);
                                return size;
                            }),
                        Return(metaDataSize)))
        .WillOnce(DoAll(Invoke(
                            [&data, &header](int, void* buffer, size_t size, int)
                            {
                                std::copy(header.begin(), header.end(), (char*)buffer);
                                std::copy(data.begin(), data.end(), (char*)buffer + HEADER_FIELD_SIZE);
                                return size;
                            }),
                        Return(packetSize)));

    // Set up the callback.
    std::function<void(const int, const char*, uint32_t, const char*, uint32_t)> callbackBody =
        [&](const int sock, const char* bodyData, uint32_t bodySize, const char*, uint32_t headerSize)
    {
        EXPECT_EQ(sock, 123);
        EXPECT_EQ(headerSize, 0u);
        EXPECT_EQ(bodySize, data.size());
        EXPECT_STREQ(bodyData, data.data());
    };
    // Connect expect calls
    EXPECT_CALL(socketWrapper, socket(_, _, _)).WillOnce(Return(123));
    EXPECT_CALL(socketWrapper, connect(123, _, _)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, setsockopt(123, _, _, _, _)).Times(2);

    EXPECT_CALL(socketWrapper, close(123)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, shutdown(123, _)).WillOnce(Return(0));

    // Connect call.
    auto unixAddress {UnixAddress::builder().address("test_socket").build()};
    EXPECT_NO_THROW({ socketWrapper.connect(unixAddress.data()); });

    // Read header.
    EXPECT_NO_THROW({ socketWrapper.read(callbackBody); });

    // Buffer is increased
    EXPECT_EQ(socketWrapper.recvBufferSize(), targetSize + 1);

    // Read body
    EXPECT_NO_THROW({ socketWrapper.read(callbackBody); });

    // Buffer is decreased to the original value.
    EXPECT_EQ(socketWrapper.recvBufferSize(), initialRecvBufferSize);
}

namespace
{
    // Answers one recv() with the given bytes, as the peer would deliver them.
    auto recvBytes(const std::vector<char>& bytes)
    {
        return [bytes](int, void* buffer, size_t size, int) -> ssize_t
        {
            EXPECT_GE(size, bytes.size());
            std::copy(bytes.begin(), bytes.end(), static_cast<char*>(buffer));
            return static_cast<ssize_t>(bytes.size());
        };
    }

    // Answers recv() with "nothing more to read", which ends a read() call.
    ssize_t recvWouldBlock(int, void*, size_t, int)
    {
        errno = EAGAIN;
        return SOCKET_ERROR;
    }

    std::vector<char> lengthPrefix(const uint32_t size)
    {
        std::vector<char> bytes(PACKET_FIELD_SIZE);
        std::memcpy(bytes.data(), &size, sizeof(size));
        return bytes;
    }

    const std::function<void(const int, const char*, uint32_t, const char*, uint32_t)> UNEXPECTED_CALLBACK =
        [](const int, const char*, uint32_t, const char*, uint32_t)
    {
        FAIL() << "Callback must not be called for a malformed packet";
    };
} // namespace

TEST_F(SocketWrapperTest, ReadRejectsLengthPrefixThatWrapsTheResize)
{
    constexpr int SOCK {123};
    Socket<OSWrapper, SizeHeaderProtocol> socketWrapper {SOCK};

    // 0xFFFFFFFF + 1 wrapped to 0: the buffer was emptied and recv() was then asked for 4 GiB.
    EXPECT_CALL(socketWrapper, recv(SOCK, _, PACKET_FIELD_SIZE, _))
        .WillOnce(Invoke(recvBytes(lengthPrefix(UINT32_MAX))));
    EXPECT_CALL(socketWrapper, shutdown(SOCK, _)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, close(SOCK)).WillOnce(Return(0));

    EXPECT_THROW(socketWrapper.read(UNEXPECTED_CALLBACK), std::runtime_error);
    EXPECT_EQ(socketWrapper.recvBufferSize(), static_cast<size_t>(BUFFER_MAX_SIZE));
}

TEST_F(SocketWrapperTest, ReadRejectsLengthPrefixAboveTheMaximum)
{
    constexpr int SOCK {123};
    Socket<OSWrapper, SizeHeaderProtocol> socketWrapper {SOCK};

    // 0x7FFFFFFF used to allocate a 2 GiB buffer.
    EXPECT_CALL(socketWrapper, recv(SOCK, _, PACKET_FIELD_SIZE, _))
        .WillOnce(Invoke(recvBytes(lengthPrefix(RECEIVE_PACKET_MAX_SIZE + 1))))
        .WillOnce(Invoke(recvBytes(lengthPrefix(INT32_MAX))));
    EXPECT_CALL(socketWrapper, shutdown(SOCK, _)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, close(SOCK)).WillOnce(Return(0));

    EXPECT_THROW(socketWrapper.read(UNEXPECTED_CALLBACK), std::runtime_error);
    EXPECT_EQ(socketWrapper.recvBufferSize(), static_cast<size_t>(BUFFER_MAX_SIZE));

    // The rejection resets the framing: the next read starts again at a length prefix.
    EXPECT_THROW(socketWrapper.read(UNEXPECTED_CALLBACK), std::runtime_error);
    EXPECT_EQ(socketWrapper.recvBufferSize(), static_cast<size_t>(BUFFER_MAX_SIZE));
}

TEST_F(SocketWrapperTest, ReadAcceptsLengthPrefixAtTheMaximum)
{
    constexpr int SOCK {123};
    Socket<OSWrapper, SizeHeaderProtocol> socketWrapper {SOCK};

    EXPECT_CALL(socketWrapper, recv(SOCK, _, _, _))
        .WillOnce(Invoke(recvBytes(lengthPrefix(RECEIVE_PACKET_MAX_SIZE))))
        .WillOnce(Invoke(recvWouldBlock));
    EXPECT_CALL(socketWrapper, shutdown(SOCK, _)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, close(SOCK)).WillOnce(Return(0));

    EXPECT_NO_THROW(socketWrapper.read(UNEXPECTED_CALLBACK));
    EXPECT_EQ(socketWrapper.recvBufferSize(), static_cast<size_t>(RECEIVE_PACKET_MAX_SIZE) + 1);
}

TEST_F(SocketWrapperTest, ReadDeliversPacketAndShrinksTheBuffer)
{
    constexpr int SOCK {123};
    Socket<OSWrapper, SizeHeaderProtocol> socketWrapper {SOCK};

    const std::vector<char> body(BUFFER_MAX_SIZE * 2, 'x');
    bool called {false};

    EXPECT_CALL(socketWrapper, recv(SOCK, _, _, _))
        .WillOnce(Invoke(recvBytes(lengthPrefix(static_cast<uint32_t>(body.size())))))
        .WillOnce(Invoke(recvBytes(body)))
        .WillOnce(Invoke(recvWouldBlock));
    EXPECT_CALL(socketWrapper, shutdown(SOCK, _)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, close(SOCK)).WillOnce(Return(0));

    EXPECT_NO_THROW(socketWrapper.read(
        [&](const int sock, const char* data, uint32_t dataSize, const char*, uint32_t headerSize)
        {
            called = true;
            EXPECT_EQ(sock, SOCK);
            EXPECT_EQ(headerSize, 0u);
            ASSERT_EQ(dataSize, body.size());
            EXPECT_TRUE(std::equal(body.begin(), body.end(), data));
        }));
    EXPECT_TRUE(called);
    EXPECT_EQ(socketWrapper.recvBufferSize(), static_cast<size_t>(BUFFER_MAX_SIZE));
}

TEST_F(SocketWrapperTest, ReadRejectsInnerHeaderLargerThanThePacket)
{
    constexpr int SOCK {123};
    Socket<OSWrapper, AppendHeaderProtocol> socketWrapper {SOCK};

    // 8-byte packet whose header-size field claims 0xFFFFFFFF bytes of header.
    std::vector<char> packet(8, 'x');
    const uint32_t headerSize {UINT32_MAX};
    std::memcpy(packet.data(), &headerSize, sizeof(headerSize));

    EXPECT_CALL(socketWrapper, recv(SOCK, _, _, _))
        .WillOnce(Invoke(recvBytes(lengthPrefix(static_cast<uint32_t>(packet.size())))))
        .WillOnce(Invoke(recvBytes(packet)));
    EXPECT_CALL(socketWrapper, shutdown(SOCK, _)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, close(SOCK)).WillOnce(Return(0));

    EXPECT_THROW(socketWrapper.read(UNEXPECTED_CALLBACK), std::runtime_error);
}

TEST_F(SocketWrapperTest, ReadRejectsPacketShorterThanTheHeaderSizeField)
{
    constexpr int SOCK {123};
    Socket<OSWrapper, AppendHeaderProtocol> socketWrapper {SOCK};

    // AppendHeaderProtocol needs at least the 4-byte header-size field inside the packet.
    EXPECT_CALL(socketWrapper, recv(SOCK, _, _, _))
        .WillOnce(Invoke(recvBytes(lengthPrefix(2))))
        .WillOnce(Invoke(recvBytes({0, 0})));
    EXPECT_CALL(socketWrapper, shutdown(SOCK, _)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, close(SOCK)).WillOnce(Return(0));

    EXPECT_THROW(socketWrapper.read(UNEXPECTED_CALLBACK), std::runtime_error);
}

TEST_F(SocketWrapperTest, ReadDeliversInnerHeaderAndBody)
{
    constexpr int SOCK {123};
    Socket<OSWrapper, AppendHeaderProtocol> socketWrapper {SOCK};

    const std::string header {"hdr"};
    const std::string body {"body"};
    std::vector<char> packet(HEADER_FIELD_SIZE);
    const auto headerSize {static_cast<uint32_t>(header.size())};
    std::memcpy(packet.data(), &headerSize, sizeof(headerSize));
    packet.insert(packet.end(), header.begin(), header.end());
    packet.insert(packet.end(), body.begin(), body.end());
    bool called {false};

    EXPECT_CALL(socketWrapper, recv(SOCK, _, _, _))
        .WillOnce(Invoke(recvBytes(lengthPrefix(static_cast<uint32_t>(packet.size())))))
        .WillOnce(Invoke(recvBytes(packet)))
        .WillOnce(Invoke(recvWouldBlock));
    EXPECT_CALL(socketWrapper, shutdown(SOCK, _)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, close(SOCK)).WillOnce(Return(0));

    EXPECT_NO_THROW(socketWrapper.read(
        [&](const int, const char* data, uint32_t dataSize, const char* hdr, uint32_t hdrSize)
        {
            called = true;
            EXPECT_EQ(std::string(hdr, hdrSize), header);
            EXPECT_EQ(std::string(data, dataSize), body);
        }));
    EXPECT_TRUE(called);
}
