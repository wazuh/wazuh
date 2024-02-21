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

/**
 * @brief Custom exception used to identify server HTTP errors when downloading from the CTI server.
 *
 */
class cti_server_error : public std::exception // NOLINT
{
    std::string m_errorMessage; ///< Exception message.

public:
    /**
     * @brief Class constructor.
     *
     * @param errorMessage Exception message.
     */
    explicit cti_server_error(std::string errorMessage)
        : m_errorMessage(std::move(errorMessage))
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
                    logWarn(WM_CONTENTUPDATER, "Missing CTI metadata key: %s", key.c_str());
                    return false;
                }

                const auto& data {rawMetadata.at(key)};
                if (data.is_null() || (data.is_string() && data.get_ref<const std::string&>().empty()))
                {
                    logWarn(WM_CONTENTUPDATER, "Null or empty CTI metadata value for key: %s", key.c_str());
                    return false;
                }

                return true;
            }};

        CtiBaseParameters parameters;
        parameters.lastOffset =
            isKeyValueValid("last_offset") ? std::optional(rawMetadata.at("last_offset").get<int>()) : std::nullopt;
        parameters.lastSnapshotLink = isKeyValueValid("last_snapshot_link")
                                          ? std::optional(rawMetadata.at("last_snapshot_link").get<std::string>())
                                          : std::nullopt;
        parameters.lastSnapshotOffset = isKeyValueValid("last_snapshot_offset")
                                            ? std::optional(rawMetadata.at("last_snapshot_offset").get<int>())
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

                // If there is an error from the server, throw a different exception.
                if (statusCode >= 500 && statusCode <= 599)
                {
                    throw cti_server_error {exceptionMessage};
                }
                throw std::runtime_error {exceptionMessage};
            }};

        constexpr auto INITIAL_SLEEP_TIME {0};
        auto sleepTime {INITIAL_SLEEP_TIME};
        auto retryAttempt {0};
        auto retry {true};
        auto& stopCondition {m_spUpdaterContext->spUpdaterBaseContext->spStopCondition};

        while (retry && !(stopCondition->waitFor(std::chrono::seconds(sleepTime))))
        {
            try
            {
                m_urlRequest.get(HttpURL(URL + queryParameters), onSuccess, onError, outputFilepath);
                retry = false;
            }
            catch (const cti_server_error& e)
            {
                constexpr auto SLEEP_TIME_THRESHOLD {30};

                logError(WM_CONTENTUPDATER, e.what());

                // Increase sleep time exponentially, up to the threshold
                if (sleepTime < SLEEP_TIME_THRESHOLD)
                {
                    sleepTime = std::min(SLEEP_TIME_THRESHOLD, static_cast<int>(std::pow(2, retryAttempt)));
                    ++retryAttempt;
                }
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

public:
    // LCOV_EXCL_START
    ~CtiDownloader() override = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Class constructor.
     *
     * @param urlRequest Object to perform the HTTP requests to the CTI API.
     * @param componentName Component name used to update the stage status.
     */
    explicit CtiDownloader(IURLRequest& urlRequest, std::string componentName)
        : m_urlRequest(urlRequest)
        , m_componentName(std::move(componentName))
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
