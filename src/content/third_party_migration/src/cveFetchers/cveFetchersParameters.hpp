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
        std::string value() override { return m_values[m_index]; };
        bool hasValue() override { return m_index < m_values.size(); }
        void nextValue() override { m_index++; }
        void restart() override { m_index = 0; }

        FixedParameter(const std::string &key, const nlohmann::json &value)
        {
            m_key = key;

            if(value.at("value").is_array()) {
                m_values = value.at("value").get<std::vector<std::string>>();
            }
            else {
                m_values.emplace_back(value.at("value").get<std::string>());
            }

            m_index = 0;
        }

        virtual ~FixedParameter() = default;

    private:
        std::vector<std::string> m_values;
        size_t m_index;
};

class IncrementalParameter : public AbstractParameter
{
    public:
        std::string value() override { return std::to_string(m_range_current); };
        bool hasValue()     override { return m_range_current <= m_range_end; }
        void restart()      override { m_range_current = m_range_begin; }
        void nextValue()    override { m_range_current += m_range_step; }

        IncrementalParameter(const std::string &key, const nlohmann::json &value)
        {
            m_key = key;
            
            for (auto const &parameter : value.at("value").items())
            {
                std::string value = parameter.value();

                if (parameter.key() == "start"){
                    m_range_begin = std::stoi(value);
                }
                else if (parameter.key() == "end"){
                    m_range_end = std::stoi(value);
                }
                else if (parameter.key() == "step"){
                    m_range_step = std::stoi(value);
                }
                else {
                    throw std::runtime_error{"unsupported parameter key: " + parameter.key() + '.'};                    
                }
            }
        }
        virtual ~IncrementalParameter() = default;

    private:
        int m_range_begin{};
        int m_range_end{};
        int m_range_step{};
        int m_range_current{};
};

#endif //_CVE_FETCHERS_PARAMETERS_HPP