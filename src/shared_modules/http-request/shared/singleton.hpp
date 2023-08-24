/*
 * Wazuh Utils - Singleton template
 * Copyright (C) 2015, Wazuh Inc.
 * May 20, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SINGLETON_HPP
#define _SINGLETON_HPP

/**
 * @brief This class is a template for singleton classes.
 *
 * @tparam T Type of the singleton class.
 */
template<typename T>
class Singleton
{
    public:
        /**
         * @brief Returns the instance of the singleton class.
         * @return Instance of the singleton class.
         */
        static T& instance()
        {
            static T s_instance;
            return s_instance;
        }
    protected:
        Singleton() = default;
        virtual ~Singleton() = default;
        Singleton(const Singleton&) = delete;
        Singleton& operator=(const Singleton&) = delete;
};

#endif // _SINGLETON_HPP

