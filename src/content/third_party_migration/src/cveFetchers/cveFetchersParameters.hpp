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

class AbstractParameter
{
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

class IncrementalParameter : public AbstractParameter
{
public:
    std::string value() override { return std::to_string(range_current); };
    bool hasValue() override { return range_current <= range_end; }
    void nextValue() override { range_current += range_step; }
    void restart() override { range_current = range_begin; }

    IncrementalParameter(const std::string &key, const nlohmann::json &value)
    {
        m_key = key;
        range_begin = value.at("value")[0].get<int>();
        range_end = value.at("value")[1].get<int>();
        range_step = 1;
        range_current = range_begin;
    }
    virtual ~IncrementalParameter() = default;

private:
    int range_begin{};
    int range_end{};
    int range_step{};
    int range_current{};
};

#endif //_CVE_FETCHERS_PARAMETERS_HPP