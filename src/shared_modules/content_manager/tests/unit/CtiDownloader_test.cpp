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
#include <chrono>
#include <memory>

const auto OK_STATUS = R"([{"stage":"CtiDummyDownloader","status":"ok"}])"_json;
const auto FAIL_STATUS = R"([{"stage":"CtiDummyDownloader","status":"fail"}])"_json;

constexpr auto CONTENT_TYPE {"raw"};
constexpr auto FAKE_CTI_URL {"http://localhost:4444/snapshot/consumers"};
constexpr auto RAW_URL {"http://localhost:4444/raw"};

constexpr auto TOO_MANY_REQUESTS_RETRY_TIME {1};
constexpr auto TOO_MANY_REQUESTS_RETRY_TIME_MS {TOO_MANY_REQUESTS_RETRY_TIME * 1000};
constexpr auto GENERIC_ERROR_INITIAL_RETRY_TIME_MS {GENERIC_ERROR_INITIAL_RETRY_TIME * 1000};

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
        m_parameters = std::make_shared<CtiBaseParameters>(
            getCtiBaseParameters(context.spUpdaterBaseContext->configData.at("url").get_ref<const std::string&>()));
    }

    std::shared_ptr<CtiBaseParameters> m_parameters; ///< Parameters used on tests.

public:
    /**
     * @brief Class constructor.
     *
     * @param urlRequest Object to perform the HTTP requests to the CTI API.
     * @param tooManyRequestsRetryTime Time between retries when a "too many requests" error is received.
     */
    explicit CtiDummyDownloader(IURLRequest& urlRequest,
                                unsigned int tooManyRequestsRetryTime = TOO_MANY_REQUESTS_DEFAULT_RETRY_TIME)
        : CtiDownloader(urlRequest, "CtiDummyDownloader", tooManyRequestsRetryTime)
    {
    }

    /**
     * @brief Returns the CTI base parameters.
     *
     * @return CtiBaseParameters Downloaded parameters.
     */
    std::shared_ptr<CtiBaseParameters> getParameters() const
    {
        return m_parameters;
    }
};

void CtiDownloaderTest::SetUp()
{
    // Create base context.
    auto spBaseContext {std::make_shared<UpdaterBaseContext>(
        m_spStopActionCondition,
        [](const std::string& msg, std::shared_ptr<ConditionSync> shouldStop) -> FileProcessingResult {
            return {0, "", false};
        })};
    spBaseContext->configData["url"] = FAKE_CTI_URL;

    // Create updater context.
    m_spUpdaterContext = std::make_shared<UpdaterContext>();
    m_spUpdaterContext->spUpdaterBaseContext = spBaseContext;
}

void CtiDownloaderTest::TearDown()
{
    // Clear fake server errors queue and records.
    m_spFakeServer->clearErrorsQueue();
    m_spFakeServer->clearRecords();
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
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check expected base parameters.
    const auto parameters {downloader.getParameters()};
    EXPECT_EQ(parameters->lastOffset.value(), 3);
    EXPECT_EQ(parameters->lastSnapshotLink.value(), "localhost:4444/" + SNAPSHOT_FILE_NAME);
    EXPECT_EQ(parameters->lastSnapshotOffset.value(), 3);
}

/**
 * @brief Tests the correct download of the parameters with the retry feature when a 5XX error is received.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadWithRetryGenericServerError)
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
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check expected base parameters.
    const auto parameters {downloader.getParameters()};
    EXPECT_EQ(parameters->lastOffset.value(), 3);
    EXPECT_EQ(parameters->lastSnapshotLink.value(), "localhost:4444/" + SNAPSHOT_FILE_NAME);
    EXPECT_EQ(parameters->lastSnapshotOffset.value(), 3);

    // Check amount of queries and timestamps.
    const auto& records {m_spFakeServer->getRecords()};
    ASSERT_EQ(records.size(), 3);
    const auto& firstQueryTimestamp {records.front().timestamp};
    const auto& lastQueryTimestamp {records.back().timestamp};
    const auto milliseconds {
        std::chrono::duration_cast<std::chrono::milliseconds>(lastQueryTimestamp - firstQueryTimestamp).count()};
    auto minExpectedSleepTime = TOO_MANY_REQUESTS_RETRY_TIME_MS * 2;
    // We accept a small margin of error in the sleep time.
    minExpectedSleepTime *= 0.9;
    EXPECT_GE(milliseconds, minExpectedSleepTime);
}

/**
 * @brief Tests the correct download of the parameters with the retry feature when a "too many requests" error is
 * received.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadWithRetryTooManyRequestsError)
{
    // Push error.
    m_spFakeServer->pushError(429);

    auto downloader {CtiDummyDownloader(HTTPRequest::instance(), TOO_MANY_REQUESTS_RETRY_TIME)};

    ASSERT_NO_THROW(downloader.handleRequest(m_spUpdaterContext));

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check expected base parameters.
    const auto parameters {downloader.getParameters()};
    EXPECT_EQ(parameters->lastOffset.value(), 3);
    EXPECT_EQ(parameters->lastSnapshotLink.value(), "localhost:4444/" + SNAPSHOT_FILE_NAME);
    EXPECT_EQ(parameters->lastSnapshotOffset.value(), 3);

    // Check amount of queries and timestamps.
    const auto& records {m_spFakeServer->getRecords()};
    ASSERT_EQ(records.size(), 2);
    const auto& firstQueryTimestamp {records.front().timestamp};
    const auto& lastQueryTimestamp {records.back().timestamp};
    const auto milliseconds {
        std::chrono::duration_cast<std::chrono::milliseconds>(lastQueryTimestamp - firstQueryTimestamp).count()};
    auto minExpectedSleepTime = TOO_MANY_REQUESTS_RETRY_TIME_MS;
    // We accept a small margin of error in the sleep time.
    minExpectedSleepTime *= 0.9;
    EXPECT_GE(milliseconds, minExpectedSleepTime);
}

/**
 * @brief Tests the correct download of the parameters with the retry feature when different server errors are received.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadWithRetryDifferentErrors)
{
    // Push error.
    m_spFakeServer->pushError(429);
    m_spFakeServer->pushError(550);
    m_spFakeServer->pushError(429);

    auto downloader {CtiDummyDownloader(HTTPRequest::instance(), TOO_MANY_REQUESTS_RETRY_TIME)};

    ASSERT_NO_THROW(downloader.handleRequest(m_spUpdaterContext));

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check expected base parameters.
    const auto parameters {downloader.getParameters()};
    EXPECT_EQ(parameters->lastOffset.value(), 3);
    EXPECT_EQ(parameters->lastSnapshotLink.value(), "localhost:4444/" + SNAPSHOT_FILE_NAME);
    EXPECT_EQ(parameters->lastSnapshotOffset.value(), 3);

    // Check amount of queries and timestamps.
    const auto& records {m_spFakeServer->getRecords()};
    ASSERT_EQ(records.size(), 4);
    const auto& firstQueryTimestamp {records.front().timestamp};
    const auto& lastQueryTimestamp {records.back().timestamp};
    const auto milliseconds {
        std::chrono::duration_cast<std::chrono::milliseconds>(lastQueryTimestamp - firstQueryTimestamp).count()};
    auto minExpectedSleepTime = TOO_MANY_REQUESTS_RETRY_TIME_MS * 2 + GENERIC_ERROR_INITIAL_RETRY_TIME_MS;
    // We accept a small margin of error in the sleep time.
    minExpectedSleepTime *= 0.9;
    EXPECT_GE(milliseconds, minExpectedSleepTime);
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
    expectedData["offset"] = 0;

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
    expectedData["offset"] = 0;

    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check amount of queries.
    ASSERT_EQ(m_spFakeServer->getRecords().size(), 1);
}

/**
 * @brief Tests the interruption of the download of the base parameters.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadInterrupted)
{
    auto downloader {CtiDummyDownloader(HTTPRequest::instance())};

    m_spStopActionCondition->set(true);
    ASSERT_NO_THROW(downloader.handleRequest(m_spUpdaterContext));

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check expected base parameters.
    const auto parameters {downloader.getParameters()};
    EXPECT_FALSE(parameters->lastOffset.has_value());
    EXPECT_FALSE(parameters->lastSnapshotLink.has_value());
    EXPECT_FALSE(parameters->lastSnapshotOffset.has_value());
}

/**
 * @brief Tests the download of metadata with invalid JSON format.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadMetadataInvalidFormat)
{
    std::string mockMetadata = R"({data":{})";
    m_spFakeServer->setCtiMetadata(std::move(mockMetadata));

    auto downloader {CtiDummyDownloader(HTTPRequest::instance())};
    ASSERT_THROW(downloader.handleRequest(m_spUpdaterContext), std::runtime_error);

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = FAIL_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the download of metadata with missing last_snapshot_offset key.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadMetadataMissingLastSnapshotOffsetKey)
{
    std::string mockMetadata = R"(
        {
            "data":
            {
                "ignored_key": true,
                "last_offset": 100,
                "last_snapshot_link": "some_link"
            }
        }
    )";
    m_spFakeServer->setCtiMetadata(std::move(mockMetadata));

    auto downloader {CtiDummyDownloader(HTTPRequest::instance())};
    ASSERT_NO_THROW(downloader.handleRequest(m_spUpdaterContext));

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check expected base parameters.
    const auto parameters {downloader.getParameters()};
    EXPECT_EQ(parameters->lastOffset.value(), 100);
    EXPECT_EQ(parameters->lastSnapshotLink.value(), "some_link");
    EXPECT_FALSE(parameters->lastSnapshotOffset.has_value());
}

/**
 * @brief Tests the download of metadata with missing last_snapshot_link key.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadMetadataMissingLastSnapshotLinkKey)
{
    std::string mockMetadata = R"(
        {
            "data":
            {
                "ignored_key": true,
                "last_offset": 100,
                "last_snapshot_offset": 50
            }
        }
    )";
    m_spFakeServer->setCtiMetadata(std::move(mockMetadata));

    auto downloader {CtiDummyDownloader(HTTPRequest::instance())};
    ASSERT_NO_THROW(downloader.handleRequest(m_spUpdaterContext));

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check expected base parameters.
    const auto parameters {downloader.getParameters()};
    EXPECT_EQ(parameters->lastOffset.value(), 100);
    EXPECT_FALSE(parameters->lastSnapshotLink.has_value());
    EXPECT_EQ(parameters->lastSnapshotOffset.value(), 50);
}

/**
 * @brief Tests the download of metadata with missing last_offset key.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadMetadataMissingLastOffsetKey)
{
    std::string mockMetadata = R"(
        {
            "data":
            {
                "ignored_key": true,
                "last_snapshot_link": "some_link",
                "last_snapshot_offset": 50
            }
        }
    )";
    m_spFakeServer->setCtiMetadata(std::move(mockMetadata));

    auto downloader {CtiDummyDownloader(HTTPRequest::instance())};
    ASSERT_NO_THROW(downloader.handleRequest(m_spUpdaterContext));

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check expected base parameters.
    const auto parameters {downloader.getParameters()};
    EXPECT_FALSE(parameters->lastOffset.has_value());
    EXPECT_EQ(parameters->lastSnapshotLink.value(), "some_link");
    EXPECT_EQ(parameters->lastSnapshotOffset.value(), 50);
}

/**
 * @brief Tests the download of metadata with an empty last_snapshot_link key.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadMetadataEmptyLastSnapshotLinkKey)
{
    std::string mockMetadata = R"(
        {
            "data":
            {
                "ignored_key": true,
                "last_snapshot_link": "",
                "last_snapshot_offset": 50,
                "last_offset": 100
            }
        }
    )";
    m_spFakeServer->setCtiMetadata(std::move(mockMetadata));

    auto downloader {CtiDummyDownloader(HTTPRequest::instance())};
    ASSERT_NO_THROW(downloader.handleRequest(m_spUpdaterContext));

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check expected base parameters.
    const auto parameters {downloader.getParameters()};
    EXPECT_EQ(parameters->lastOffset.value(), 100);
    EXPECT_FALSE(parameters->lastSnapshotLink.has_value());
    EXPECT_EQ(parameters->lastSnapshotOffset.value(), 50);
}

/**
 * @brief Tests the download of metadata without 'data' key.
 *
 */
TEST_F(CtiDownloaderTest, BaseParametersDownloadMetadataMissingDataKey)
{
    std::string mockMetadata = R"(
        {
            "metadata":
            {
                "ignored_key": true,
                "last_snapshot_link": "some_link",
                "last_snapshot_offset": 50,
                "last_offset": 100
            }
        }
    )";
    m_spFakeServer->setCtiMetadata(std::move(mockMetadata));

    auto downloader {CtiDummyDownloader(HTTPRequest::instance())};
    ASSERT_THROW(downloader.handleRequest(m_spUpdaterContext), std::runtime_error);

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = FAIL_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}
