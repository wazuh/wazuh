/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include "UNIXSocketRequest.hpp"
#include "curlWrapper.hpp"

void UNIXSocketRequest::download(const URL &url,
                                 const std::string &outputFile,
                                 std::function<void(const std::string &)> onError)
{
    try
    {
        GetRequest::builder()
            .url(url.url())
            .unixSocketPath(url.unixSocketPath())
            .outputFile(outputFile)
            .execute();
    }
    catch (const std::exception &ex)
    {
        onError(ex.what());
    }
}

void UNIXSocketRequest::post(const URL &url,
                             const nlohmann::json &data,
                             std::function<void(const std::string &)> onSuccess,
                             std::function<void(const std::string &)> onError)
{
    try
    {
        auto req { PostRequest::builder() };
        req.url(url.url())
            .unixSocketPath(url.unixSocketPath())
            .postData(data)
            .execute();

        onSuccess(req.response());
    }
    catch (const std::exception &ex)
    {
        onError(ex.what());
    }
}

void UNIXSocketRequest::get(const URL &url,
                            std::function<void(const std::string &)> onSuccess,
                            std::function<void(const std::string &)> onError)
{
    try
    {
        auto req { GetRequest::builder() };
        req.url(url.url())
            .unixSocketPath(url.unixSocketPath())
            .execute();

        onSuccess(req.response());
    }
    catch (const std::exception &ex)
    {
        onError(ex.what());
    }
}

void UNIXSocketRequest::update(const URL &url,
                               const nlohmann::json &data,
                               std::function<void(const std::string &)> onSuccess,
                               std::function<void(const std::string &)> onError)
{
    try
    {
        auto req { PutRequest::builder() };
        req.url(url.url())
            .unixSocketPath(url.unixSocketPath())
            .postData(data)
            .execute();

        onSuccess(req.response());
    }
    catch (const std::exception &ex)
    {
        onError(ex.what());
    }
}

void UNIXSocketRequest::delete_(const URL &url,
                                std::function<void(const std::string &)> onSuccess,
                                std::function<void(const std::string &)> onError)
{
    try
    {
        auto req { DeleteRequest::builder() };
        req.url(url.url())
            .unixSocketPath(url.unixSocketPath())
            .execute();

        onSuccess(req.response());
    }
    catch (const std::exception &ex)
    {
        onError(ex.what());
    }
}

