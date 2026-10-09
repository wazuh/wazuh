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

TEST_F(SocketWrapperTest, ReadRejectsLengthThatWouldWrapToZero)
{
    // Create a mock object.
    Socket<OSWrapper> socketWrapper;

    // Set up the test data: a declared length of UINT32_MAX, which would make
    // m_totalReadSize + 1 wrap to 0 and resize the buffer down instead of up.
    const int sock = 123;
    const ssize_t metaDataSize = PACKET_FIELD_SIZE;
    const PacketFieldType packetSize = UINT32_MAX;

    // Only the header read is expected: a correct fix must reject the length
    // before ever attempting a second (body) recv() call.
    EXPECT_CALL(socketWrapper, recv(sock, _, _, _))
        .WillOnce(DoAll(Invoke(
                            [&packetSize](int, void* buffer, size_t size, int)
                            {
                                std::copy((char*)&packetSize, (char*)&packetSize + size, (char*)buffer);
                                return size;
                            }),
                        Return(metaDataSize)));

    std::function<void(const int, const char*, uint32_t, const char*, uint32_t)> callbackBody =
        [&](const int, const char*, uint32_t, const char*, uint32_t) { FAIL() << "callback should not run"; };

    // Connect expect calls
    EXPECT_CALL(socketWrapper, socket(_, _, _)).WillOnce(Return(123));
    EXPECT_CALL(socketWrapper, connect(123, _, _)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, setsockopt(123, _, _, _, _)).Times(2);

    EXPECT_CALL(socketWrapper, close(123)).WillOnce(Return(0));
    EXPECT_CALL(socketWrapper, shutdown(123, _)).WillOnce(Return(0));

    // Connect call.
    auto unixAddress {UnixAddress::builder().address("test_socket").build()};
    EXPECT_NO_THROW({ socketWrapper.connect(unixAddress.data()); });

    // Read header: declared length is UINT32_MAX, must throw instead of
    // proceeding to read a body into an undersized buffer.
    EXPECT_THROW({ socketWrapper.read(callbackBody); }, std::runtime_error);

    // The buffer was never resized down to 0 nor grown to UINT32_MAX+1.
    EXPECT_EQ(socketWrapper.recvBufferSize(), BUFFER_MAX_SIZE);
}

TEST_F(SocketWrapperTest, ReadRejectsHeaderSizeThatMovesOffsetPastMessage)
{
    // 0xFFFFFFFC and above make 4 + headerSize reach 2^32 or more: they must be rejected too, not
    // wrapped around by a 32-bit comparison.
    for (const PacketFieldType maliciousHeaderSize : {0xFFFFFFF0u, 0xFFFFFFFCu, 0xFFFFFFFFu})
    {
        // Create a mock object.
        Socket<OSWrapper> socketWrapper;

        // Set up the test data: a small, well-formed total length (no 4 GiB send needed), whose
        // body embeds a header-size field claiming to be huge. dataOffset (4 + headerSize) then
        // moves past the declared total length.
        const int sock = 123;
        const ssize_t metaDataSize = PACKET_FIELD_SIZE;
        const PacketFieldType packetSize = 8;

        std::vector<char> body(8, 0);
        std::copy(
            (char*)&maliciousHeaderSize, (char*)&maliciousHeaderSize + sizeof(maliciousHeaderSize), body.data());

        // Both the header and body reads are expected: a correct fix only rejects the message
        // once the embedded header size is known, after the body has arrived.
        EXPECT_CALL(socketWrapper, recv(sock, _, _, _))
            .WillOnce(DoAll(Invoke(
                                [&packetSize](int, void* buffer, size_t size, int)
                                {
                                    std::copy((char*)&packetSize, (char*)&packetSize + size, (char*)buffer);
                                    return size;
                                }),
                            Return(metaDataSize)))
            .WillOnce(DoAll(Invoke(
                                [&body](int, void* buffer, size_t size, int)
                                {
                                    std::copy(body.begin(), body.end(), (char*)buffer);
                                    return size;
                                }),
                            Return((ssize_t)body.size())));

        std::function<void(const int, const char*, uint32_t, const char*, uint32_t)> callbackBody =
            [&](const int, const char*, uint32_t, const char*, uint32_t) { FAIL() << "callback should not run"; };

        // Connect expect calls
        EXPECT_CALL(socketWrapper, socket(_, _, _)).WillOnce(Return(123));
        EXPECT_CALL(socketWrapper, connect(123, _, _)).WillOnce(Return(0));
        EXPECT_CALL(socketWrapper, setsockopt(123, _, _, _, _)).Times(2);

        EXPECT_CALL(socketWrapper, close(123)).WillOnce(Return(0));
        EXPECT_CALL(socketWrapper, shutdown(123, _)).WillOnce(Return(0));

        // Connect call.
        auto unixAddress {UnixAddress::builder().address("test_socket").build()};
        EXPECT_NO_THROW({ socketWrapper.connect(unixAddress.data()); });

        // read() drains both the header and the body in this one call (it only stops looping on
        // EAGAIN/EWOULDBLOCK or an error), so the throw is expected here, not on a second call.
        // The embedded header size pushes dataOffset past m_totalReadSize: must throw instead of
        // calling back with an out-of-bounds pointer and an underflowed size.
        EXPECT_THROW({ socketWrapper.read(callbackBody); }, std::runtime_error);
    }
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
                            [&data, &header](int, void* buffer, size_t, int) {
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
