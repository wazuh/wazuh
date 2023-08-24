/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 18, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _IREQUEST_IMPLEMENTATOR_HPP
#define _IREQUEST_IMPLEMENTATOR_HPP

#include <string>

enum OPTION_REQUEST_TYPE
{
    OPT_URL,
    OPT_CAINFO,
    OPT_TIMEOUT,
    OPT_WRITEDATA,
    OPT_USERAGENT,
    OPT_POSTFIELDS,
    OPT_WRITEFUNCTION,
    OPT_POSTFIELDSIZE,
    OPT_CUSTOMREQUEST,
    OPT_UNIX_SOCKET_PATH,
    OPT_FAILONERROR,
    OPT_FOLLOW_REDIRECT,
    OPT_MAX_REDIRECTIONS,
    OPT_VERIFYPEER,
};

/**
 * @brief This class is a interface for IRequestImplementator.
 * It provides a simple interface to perform HTTP requests.
 */
class IRequestImplementator
{
public:
    virtual ~IRequestImplementator() = default;
    /**
     * @brief Virtual method to set options to the handle.
     * @param optIndex The option index.
     * @param ptr The option value.
     */
    virtual void setOption(const OPTION_REQUEST_TYPE optIndex, void* ptr) = 0;

    /**
     * @brief Virtual method to set options to the handle.
     * @param optIndex The option index.
     * @param opt The option value.
     */
    virtual void setOption(const OPTION_REQUEST_TYPE optIndex, const std::string& opt) = 0;

    /**
     * @brief Virtual method to set options to the handle.
     * @param optIndex The option index.
     * @param opt The option value.
     */
    virtual void setOption(const OPTION_REQUEST_TYPE optIndex, const long opt) = 0;

    /**
     * @brief Virtual method to perform the request.
     */
    virtual void execute() = 0;

    /**
     * @brief Virtual method to get the value of the last request.
     * @return The value of the last request.
     */
    virtual inline const std::string response() = 0;

    /**
     * @brief Virtual method to add a header to the handle.
     * @param header The header to be added.
     */
    virtual void appendHeader(const std::string& header) = 0;
};

#endif // _IREQUEST_IMPLEMENTATOR_HPP
