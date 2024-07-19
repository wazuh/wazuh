/*
 * Wazuh Content Manager
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 30, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CTI_DOWNLOADER_HPP
#define _CTI_DOWNLOADER_HPP

#include "../sharedDefs.hpp"
#include "IURLRequest.hpp"
#include "componentsHelper.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

static const unsigned int TOO_MANY_REQUESTS_DEFAULT_RETRY_TIME {90};
static const unsigned int GENERIC_ERROR_INITIAL_RETRY_TIME {1};

/**
 * @brief CTI download error types.
 *
 */
enum class CtiErrorType
{
    NO_ERROR,
    GENERIC_SERVER_ERROR,
    TOO_MANY_REQUESTS
};

/**
 * @brief Custom exception used to identify server HTTP errors when downloading from the CTI server.
 *
 */
class cti_server_error : public std::exception // NOLINT
{
    const std::string m_errorMessage; ///< Exception message.
    const CtiErrorType m_errorType;   ///< Exception error type.

public:
    /**
     * @brief Class constructor.
     *
     * @param errorMessage Exception message.
     * @param errorType Error code.
     */
    explicit cti_server_error(std::string errorMessage, CtiErrorType errorType)
        : m_errorMessage(std::move(errorMessage))
        , m_errorType(errorType)
    {
    }

    /**
     * @brief Returns the exception message.
     *
     * @return const char* Message.
     */
    const char* what() const noexcept override
    {
        return m_errorMessage.c_str();
    }

    /**
     * @brief Returns the type of error.
     *
     * @return const CtiErrorType Error type.
     */
    const CtiErrorType type() const noexcept
    {
        return m_errorType;
    }
};

/**
 * @class CtiDownloader
 *
 * @brief Class in charge of downloading the content from the API as a step of a chain of responsibility.
 *
 */
class CtiDownloader : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
protected:
    /**
     * @brief Struct that represents the parameters needed by the downloaders for starting its tasks.
     *
     */
    struct CtiBaseParameters
    {
        std::optional<int> lastOffset {};               ///< Last available offset from CTI.
        std::optional<std::string> lastSnapshotLink {}; ///< Last snapshot URL from CTI.
        std::optional<int> lastSnapshotOffset {};       ///< Last offset within the last snapshot.
    };

    /**
     * @brief Get the CTI API base parameters.
     *
     * @param ctiURL Base URL from where to download the CTI parameters.
     * @return struct CtiBaseParameters Base parameters of the CTI API.
     */
    CtiBaseParameters getCtiBaseParameters(const std::string& ctiURL)
    {
        nlohmann::json rawMetadata;

        // Routine that stores the necessary parameters.
        const auto onSuccess {[&rawMetadata](const std::string& response)
                              {
                                  logDebug2(WM_CONTENTUPDATER, "CTI raw metadata: '%s'", response.c_str());

                                  if (!nlohmann::json::accept(response))
                                  {
                                      throw std::runtime_error {"Invalid CTI metadata format"};
                                  }

                                  auto responseJSON = nlohmann::json::parse(response);
                                  if (!responseJSON.contains("data"))
                                  {
                                      throw std::runtime_error {"No 'data' field in CTI metadata"};
                                  }

                                  rawMetadata = std::move(responseJSON.at("data"));
                              }};

        // Make a get request to the API to get the consumer offset.
        performQueryWithRetry(ctiURL, onSuccess);

        // Return if interrupted.
        if (m_spUpdaterContext->spUpdaterBaseContext->spStopCondition->check())
        {
            return CtiBaseParameters();
        }

        // Lambda that validates a metadata field.
        const auto isKeyValueValid {
            [&rawMetadata](const std::string& key)
            {
                if (!rawMetadata.contains(key))
                {
                    logWarn(WM_CONTENTUPDATER, "Missing CTI metadata key: %s.", key.c_str());
                    return false;
                }

                const auto& data {rawMetadata.at(key)};
                if (data.is_null() || (data.is_string() && data.get_ref<const std::string&>().empty()))
                {
                    logWarn(WM_CONTENTUPDATER, "Null or empty CTI metadata value for key: %s.", key.c_str());
                    return false;
                }

                return true;
            }};

        CtiBaseParameters parameters;
        parameters.lastOffset = isKeyValueValid("last_offset")
                                    ? std::optional<int>(rawMetadata.at("last_offset").get<int>())
                                    : std::nullopt;
        parameters.lastSnapshotLink =
            isKeyValueValid("last_snapshot_link")
                ? std::optional<std::string>(rawMetadata.at("last_snapshot_link").get<std::string>())
                : std::nullopt;
        parameters.lastSnapshotOffset = isKeyValueValid("last_snapshot_offset")
                                            ? std::optional<int>(rawMetadata.at("last_snapshot_offset").get<int>())
                                            : std::nullopt;
        return parameters;
    }

    /**
     * @brief Loop for retrying the downloads from the server until the download is successful, there is an HTTP error
     * different from 5xx, or in case of an interruption.
     *
     * @param URL URL to download from.
     * @param onSuccess Callback on success download.
     * @param queryParameters Parameters to the GET query.
     * @param outputFilepath File where to store the downloaded content.
     */
    void performQueryWithRetry(const std::string& URL,
                               const std::function<void(const std::string&)>& onSuccess,
                               const std::string& queryParameters = "",
                               const std::string& outputFilepath = "") const
    {
        // On download error routine.
        const auto onError {
            [](const std::string& message, const long statusCode)
            {
                const std::string exceptionMessage {"Error " + std::to_string(statusCode) + " from server: " + message};

                if (statusCode == 429)
                {
                    throw cti_server_error {exceptionMessage, CtiErrorType::TOO_MANY_REQUESTS};
                }

                if (statusCode >= 500 && statusCode <= 599)
                {
                    throw cti_server_error {exceptionMessage, CtiErrorType::GENERIC_SERVER_ERROR};
                }
                throw std::runtime_error {exceptionMessage};
            }};

        unsigned int sleepTime {0};
        unsigned int retryAttempt;
        auto lastErrorType {CtiErrorType::NO_ERROR};
        auto& stopCondition {m_spUpdaterContext->spUpdaterBaseContext->spStopCondition};

        while (!stopCondition->waitFor(std::chrono::seconds(sleepTime)))
        {
            try
            {
                m_urlRequest.get(HttpURL(URL + queryParameters),
                                 onSuccess,
                                 onError,
                                 outputFilepath,
                                 DEFAULT_HEADERS,
                                 {},
                                 m_spUpdaterContext->spUpdaterBaseContext->httpUserAgent);
                return;
            }
            catch (const cti_server_error& e)
            {
                logDebug1(WM_CONTENTUPDATER, e.what());

                switch (e.type())
                {
                    case CtiErrorType::GENERIC_SERVER_ERROR:
                    {
                        if (CtiErrorType::GENERIC_SERVER_ERROR == lastErrorType)
                        {
                            // Increase sleep time exponentially, up to the threshold
                            constexpr auto SLEEP_TIME_THRESHOLD {30};
                            if (sleepTime < SLEEP_TIME_THRESHOLD)
                            {
                                sleepTime = std::min(SLEEP_TIME_THRESHOLD, static_cast<int>(std::pow(2, retryAttempt)));
                                ++retryAttempt;
                            }
                        }
                        else
                        {
                            // First time with this particular error.
                            sleepTime = GENERIC_ERROR_INITIAL_RETRY_TIME;
                            retryAttempt = 0;
                        }
                        break;
                    }

                    case CtiErrorType::TOO_MANY_REQUESTS:
                    {
                        sleepTime = m_tooManyRequestsRetryTime;
                        break;
                    }

                    // LCOV_EXCL_START
                    default:
                        throw std::runtime_error {"Invalid CTI error type"};
                        // LCOV_EXCL_STOP
                }

                lastErrorType = e.type();

                logDebug1(WM_CONTENTUPDATER, "Retrying download in %d seconds", sleepTime);
            }
        }
    }

    /**
     * @brief Virtual method that downloads content from CTI.
     *
     * @param context Updater context.
     */
    virtual void download(UpdaterContext& context) = 0;

    IURLRequest& m_urlRequest;                          ///< Interface to perform HTTP requests.
    const std::string m_componentName;                  ///< Stage name.
    std::shared_ptr<UpdaterContext> m_spUpdaterContext; ///< Updater context.
    const unsigned int m_tooManyRequestsRetryTime; ///< Time between retries when receiving a "too many requests" error.

public:
    // LCOV_EXCL_START
    ~CtiDownloader() override = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Class constructor.
     *
     * @param urlRequest Object to perform the HTTP requests to the CTI API.
     * @param componentName Component name used to update the stage status.
     * @param tooManyRequestsRetryTime Time between retries when a "too many requests" error is received.
     */
    explicit CtiDownloader(IURLRequest& urlRequest,
                           std::string componentName,
                           unsigned int tooManyRequestsRetryTime = TOO_MANY_REQUESTS_DEFAULT_RETRY_TIME)
        : m_urlRequest(urlRequest)
        , m_componentName(std::move(componentName))
        , m_tooManyRequestsRetryTime(tooManyRequestsRetryTime)
    {
    }

    /**
     * @brief Download the content from the CTI API.
     *
     * @param context Updater context.
     * @return std::shared_ptr<UpdaterContext>
     */
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        logDebug1(WM_CONTENTUPDATER, "%s - Starting process", m_componentName.c_str());

        m_spUpdaterContext = context;

        try
        {
            download(*context);
        }
        catch ([[maybe_unused]] const std::exception& e)
        {
            // Push fail status.
            Components::pushStatus(m_componentName, Components::Status::STATUS_FAIL, *context);
            throw;
        }

        // Push success status.
        Components::pushStatus(m_componentName, Components::Status::STATUS_OK, *context);
        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(context);
    }
};

#endif // _CTI_DOWNLOADER_HPP
