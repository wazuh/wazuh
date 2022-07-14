/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 12, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HTTP_REQUEST_HPP
#define _HTTP_REQUEST_HPP

#include <functional>
#include <iostream>
#include <string>
#include "IURLRequest.hpp"
#include "json.hpp"
#include "singleton.hpp"

class HTTPRequest final : public IURLRequest, public Singleton<HTTPRequest>
{
    public:
        void download(const URL &url,
                      const std::string &fileName,
                      std::function<void(const std::string &)> onError = [](auto){});
        void post(const URL &url,
                  const nlohmann::json &data,
                  std::function<void(const std::string &)> onSuccess,
                  std::function<void(const std::string &)> onError = [](auto){});
        void get(const URL &url,
                 std::function<void(const std::string &)> onSuccess,
                 std::function<void(const std::string &)> onError = [](auto){});
        void update(const URL &url,
                    const nlohmann::json &data,
                    std::function<void(const std::string &)> onSuccess,
                    std::function<void(const std::string &)> onError = [](auto){});
        void delete_(const URL &url,
                     std::function<void(const std::string &)> onSuccess,
                     std::function<void(const std::string &)> onError = [](auto){});
};

#endif // _HTTP_REQUEST_HPP
