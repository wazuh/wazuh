/*
 * Wazuh Migration
 * Copyright (C) 2015, Wazuh Inc.
 * July 15, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CVE_FETCHERS_PARAMETERS_HPP
#define _CVE_FETCHERS_PARAMETERS_HPP

#include <string>
#include <json.hpp>

class AbstractParameter{
    public:
        AbstractParameter() = default;
        AbstractParameter(const std::string &key, const nlohmann::json &value);
        virtual ~AbstractParameter() = default;

        std::string key() { return m_key; };
        virtual std::string value() = 0;
        virtual bool hasValue() = 0;
        virtual void nextValue() = 0; 
        virtual void restart() = 0;

        protected:
        std::string m_key;
};

class FixedParameter : public AbstractParameter
{
public:
    std::string value() override { return m_values[index]; };
    bool hasValue() override { return index < m_values.size(); }
    void nextValue() override { index++; }
    void restart() override { index = 0; }
    
    FixedParameter(const std::string &key, const nlohmann::json &value)
    {
        m_key = key;
        m_values = value.at("value").get<std::vector<std::string>>();
        index = 0;
    }
    virtual ~FixedParameter() = default;

private:
    std::vector<std::string> m_values;
    size_t index;
};

#endif //_CVE_FETCHERS_PARAMETERS_HPP