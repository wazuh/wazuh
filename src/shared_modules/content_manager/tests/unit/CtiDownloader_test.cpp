/*
 * Wazuh Content Manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Dec 01, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "CtiDownloader_test.hpp"
#include "CtiDownloader.hpp"
#include "HTTPRequest.hpp"
#include "fakes/fakeServer.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <memory>

const auto OK_STATUS = R"([{"stage":"CtiDummyDownloader","status":"ok"}])"_json;
const auto FAIL_STATUS = R"([{"stage":"CtiDummyDownloader","status":"fail"}])"_json;

constexpr auto CONTENT_TYPE {"raw"};
constexpr auto FAKE_CTI_URL {"http://localhost:4444/snapshot/consumers"};
constexpr auto RAW_URL {"http://localhost:4444/raw"};

constexpr auto DEFAULT_LAST_OFFSET {0};
constexpr auto DEFAULT_LAST_SNAPSHOT_LINK {""};

/**
 * @class CtiDummyDownloader
 *
 * @brief Dummy class for testing purposes.
 *
 */
class CtiDummyDownloader final : public CtiDownloader
{
private:
    /**
     * @brief Stores the CTI base parameters.
     *
     * @param context Updater context.
     */
    void download(UpdaterContext& context) override
    {
        const auto parameters {
            getCtiBaseParameters(context.spUpdaterBaseContext->configData.at("url").get_ref<const std::string&>())};
        m_lastOffset = parameters.lastOffset;
        m_lastSnapshotLink = parameters.lastSnapshotLink;
        m_lastSnapshotOffset = parameters.lastSnapshotOffset;
    }

    int m_lastOffset {DEFAULT_LAST_OFFSET};                      ///< Last offset downloaded from CTI.
    std::string m_lastSnapshotLink {DEFAULT_LAST_SNAPSHOT_LINK}; ///< Last snapshot link downloaded from CTI.
    int m_lastSnapshotOffset {DEFAULT_LAST_OFFSET};              ///< Last offset within the snapshot.

public:
    /**
     * @brief Class constructor.
     *
     * @param urlRequest Object to perform the HTTP requests to the CTI API.
     */
    explicit CtiDummyDownloader(IURLRequest& urlRequest)
        : CtiDownloader(urlRequest, "CtiDummyDownloader")
    {
    }

    /**
     * @brief Returns the CTI last offset.
     *
     * @return int Last offset.
     */
    int getLastOffset() const
    {
        return m_lastOffset;
    }

    /**
     * @brief Returns the snapshot last offset.
     *
     * @return int Last snapshot offset.
     */
    int getLastSnapshotOffset() const
    {
        return m_lastSnapshotOffset;
    }

    /**
     * @brief Returns the CTI last snapshot link.
     *
     * @return std::string Last snapshot link.
     */
    std::string getLastSnapshotLink() const
    {
        return m_lastSnapshotLink;
    }
};

void CtiDownloaderTest::SetUp()
{
    m_shouldRun = true;

    // Create base context.
    auto spBaseContext {std::make_shared<UpdaterBaseContext>(m_shouldRun)};
    spBaseContext->configData["url"] = FAKE_CTI_URL;

    // Create updater context.
    m_spUpdaterContext = std::make_shared<UpdaterContext>();
    m_spUpdaterContext->spUpdaterBaseContext = spBaseContext;
}

void CtiDownloaderTest::TearDown()
{
    // Clear fake server errors queue.
    m_spFakeServer->clearErrorsQueue();
}

void CtiDownloaderTest::SetUpTestSuite()
{
    if (!m_spFakeServer)
    {
        m_spFakeServer = std::make_unique<FakeServer>("localhost", 4444);
    }
}

void CtiDownloaderTest::TearDownTestSuite()
{
    m_spFakeServer.reset();
}

/**
 * @brief Tests the correct instantiation of the class.
 *
 */
TEST_F(CtiDownloaderTest, Instantiation)
{
    EXPECT_NO_THROW(std::make_shared<CtiDummyDownloader>(HTTPRequest::instance()));
    EXPECT_NO_THROW(CtiDummyDownloader(HTTPRequest::instance()));
}

/**
 * @brief Tests the correct download of the base parameters.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownload)
{
    auto downloader {CtiDummyDownloader(HTTPRequest::instance())};

    ASSERT_NO_THROW(downloader.handleRequest(m_spUpdaterContext));

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check expected base parameters.
    EXPECT_EQ(downloader.getLastOffset(), 3);
    EXPECT_EQ(downloader.getLastSnapshotLink(), "localhost:4444/" + SNAPSHOT_FILE_NAME);
    EXPECT_EQ(downloader.getLastSnapshotOffset(), 3);
}

/**
 * @brief Tests the correct download of the parameters with the retry feature.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadWithRetry)
{
    // Push server error.
    m_spFakeServer->pushError(500);
    m_spFakeServer->pushError(550);

    auto downloader {CtiDummyDownloader(HTTPRequest::instance())};

    ASSERT_NO_THROW(downloader.handleRequest(m_spUpdaterContext));

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check expected base parameters.
    EXPECT_EQ(downloader.getLastOffset(), 3);
    EXPECT_EQ(downloader.getLastSnapshotLink(), "localhost:4444/" + SNAPSHOT_FILE_NAME);
    EXPECT_EQ(downloader.getLastSnapshotOffset(), 3);
}

/**
 * @brief Tests the download of the base parameters with a bad response from the server, where no parameters are
 * present.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadBadResponseFromServer)
{
    m_spUpdaterContext->spUpdaterBaseContext->configData["url"] = RAW_URL;

    ASSERT_THROW(CtiDummyDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext), std::runtime_error);

    // Set expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = FAIL_STATUS;
    expectedData["type"] = CONTENT_TYPE;

    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the download of the base parameters with a client error.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadClientError)
{
    // Push client error.
    m_spFakeServer->pushError(400);

    ASSERT_THROW(CtiDummyDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext), std::runtime_error);

    // Set expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = FAIL_STATUS;
    expectedData["type"] = CONTENT_TYPE;

    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the interruption of the download of the base parameters.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadInterrupted)
{
    auto downloader {CtiDummyDownloader(HTTPRequest::instance())};

    m_shouldRun = false;
    ASSERT_NO_THROW(downloader.handleRequest(m_spUpdaterContext));

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check expected base parameters.
    EXPECT_EQ(downloader.getLastOffset(), DEFAULT_LAST_OFFSET);
    EXPECT_EQ(downloader.getLastSnapshotLink(), DEFAULT_LAST_SNAPSHOT_LINK);
    EXPECT_EQ(downloader.getLastSnapshotOffset(), DEFAULT_LAST_OFFSET);
}
