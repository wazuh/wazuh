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
                           std::function<void(const std::string &)>/* onSuccess*/,
                           std::function<void(const std::string &)> onError)
{
    // TODO: implement
    std::cout << "Downloading Sync " << url.url() << " outputFile: " << outputFile << std::endl;
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
    std::cout << "Posting Sync " << url.url() << std::endl;
    try
    {
        auto req { PostRequest::builder() };
        req.url(url.url())
            .unixSocketPath(url.unixSocketPath())
            .postData<PostRequest>(data)
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
    std::cout << "Getting Sync" << url.url() << std::endl;
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
    std::cout << "Updating Sync " << url.url() << std::endl;
    try
    {
        auto req { PutRequest::builder() };
        req.url(url.url())
            .unixSocketPath(url.unixSocketPath())
            .postData<PutRequest>(data)
            .execute();

        onSuccess(req.response());
    }
    catch (const std::exception &ex)
    {
        onError(ex.what());
    }
}

void UNIXSocketRequest::delete_(const URL &url,
                          const nlohmann::json &data,
                          std::function<void(const std::string &)> onSuccess,
                          std::function<void(const std::string &)> onError)
{
    std::cout << "Deleting Sync " << url.url() << std::endl;
    try
    {
        auto req { DeleteRequest::builder() };
        req.url(url.url())
            .unixSocketPath(url.unixSocketPath())
            .postData<DeleteRequest>(data)
            .execute();

        onSuccess(req.response());
    }
    catch (const std::exception &ex)
    {
        onError(ex.what());
    }
}

