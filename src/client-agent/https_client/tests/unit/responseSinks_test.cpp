/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * The response sinks' own byte cap. With curl 8.20 enforcing the same cap first
 * (CURLOPT_MAXFILESIZE_LARGE), no transfer reaches it any more, so it is pinned here, called the
 * way curl calls it.
 */

#include "responseSinks.hpp"

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>

namespace
{
    size_t writeBody(BodySink& sink, std::string piece)
    {
        return writeToBodySink(piece.data(), 1, piece.size(), &sink);
    }

    size_t writeFile(FileSink& sink, std::string piece)
    {
        return writeToFileSink(piece.data(), 1, piece.size(), &sink);
    }

    class FileSinkTest : public ::testing::Test
    {
        protected:
            void SetUp() override
            {
                m_file = std::fopen(m_path.c_str(), "wb");
                ASSERT_NE(nullptr, m_file);
            }

            void TearDown() override
            {
                closeFile();
                std::remove(m_path.c_str());
            }

            void closeFile()
            {
                if (m_file != nullptr)
                {
                    std::fclose(m_file);
                    m_file = nullptr;
                }
            }

            std::string contents()
            {
                closeFile();
                std::ifstream file {m_path, std::ios::binary};
                return std::string {std::istreambuf_iterator<char> {file}, std::istreambuf_iterator<char> {}};
            }

            const std::string m_path {::testing::TempDir() + "hc_response_sink.tmp"};
            std::FILE* m_file {nullptr};
    };
} // namespace

TEST(BodySinkTest, TakesABodyThatEndsExactlyAtTheCap)
{
    std::string body;
    BodySink sink {&body, 8};

    EXPECT_EQ(5u, writeBody(sink, "abcde"));
    EXPECT_EQ(3u, writeBody(sink, "fgh"));
    EXPECT_EQ("abcdefgh", body);
}

TEST(BodySinkTest, RefusesThePieceThatWouldCrossTheCapAndKeepsWhatCameBefore)
{
    std::string body;
    BodySink sink {&body, 8};

    EXPECT_EQ(5u, writeBody(sink, "abcde"));
    EXPECT_EQ(0u, writeBody(sink, "fghi"));
    EXPECT_EQ("abcde", body);
}

TEST(BodySinkTest, ZeroMeansUnlimited)
{
    std::string body;
    BodySink sink {&body, 0};

    EXPECT_EQ(4096u, writeBody(sink, std::string(4096, 'x')));
    EXPECT_EQ(4096u, body.size());
}

TEST_F(FileSinkTest, TakesABodyThatEndsExactlyAtTheCap)
{
    FileSink sink {m_file, 0, 8};

    EXPECT_EQ(5u, writeFile(sink, "abcde"));
    EXPECT_EQ(3u, writeFile(sink, "fgh"));
    EXPECT_EQ(8u, sink.written);
    EXPECT_EQ("abcdefgh", contents());
}

TEST_F(FileSinkTest, RefusesThePieceThatWouldCrossTheCapAndKeepsWhatCameBefore)
{
    FileSink sink {m_file, 0, 8};

    EXPECT_EQ(5u, writeFile(sink, "abcde"));
    EXPECT_EQ(0u, writeFile(sink, "fghi"));
    EXPECT_EQ(5u, sink.written);
    EXPECT_EQ("abcde", contents());
}

TEST_F(FileSinkTest, ZeroMeansUnlimited)
{
    FileSink sink {m_file, 0, 0};

    EXPECT_EQ(4096u, writeFile(sink, std::string(4096, 'x')));
    EXPECT_EQ(4096u, contents().size());
}
