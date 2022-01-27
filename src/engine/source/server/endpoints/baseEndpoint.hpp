/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BASE_ENDPOINT_H_
#define _BASE_ENDPOINT_H_

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>

namespace engineserver::endpoints
{

class BaseEndpoint
{
protected:
    rxcpp::subjects::subject<nlohmann::json> m_subject;
    rxcpp::subscriber<nlohmann::json> m_subscriber;
    std::string m_path;

    explicit BaseEndpoint(const std::string & path);

public:
    virtual ~BaseEndpoint();
    /**
     * @brief Get the Observable object
     *
     * @return auto Observable object
     */
    rxcpp::observable<nlohmann::json> output(void) const;

    virtual void run(void) = 0;
    virtual void close(void) = 0;
};

enum EndpointType
{
    TCP,
    UDP,
    SOCKET
};

EndpointType stringToEndpoint(const std::string & endpointName);

std::unique_ptr<BaseEndpoint> create(const std::string & type, const std::string & config);

} // namespace engineserver::endpoints

#endif // _BASE_ENDPOINT_H_
