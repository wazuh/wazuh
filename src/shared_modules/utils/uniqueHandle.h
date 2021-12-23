/*
 * Wazuh Utils
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 25, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <memory>

template <typename T, T TNullValue = T()>
class UniqueHandle
{
public:
    UniqueHandle(std::nullptr_t = nullptr)
        : m_handle(TNullValue)
    {
    }

    UniqueHandle(T handle)
        : m_handle(handle)
    {
    }

    explicit operator bool() const
    {
        return m_handle != TNullValue;
    }

    operator T&()
    {
        return m_handle;
    }

    operator const T&() const
    {
        return m_handle;
    }

    T* operator&()
    {
        return &m_handle;
    }

    const T* operator&() const
    {
        return &m_handle;
    }

    friend bool operator==(const UniqueHandle& lhs, const UniqueHandle& rhs)
    {
        return lhs.m_handle == rhs.m_handle;
    }

    friend bool operator!=(const UniqueHandle& lhs, const UniqueHandle& rhs)
    {
        return lhs.m_handle != rhs.m_handle;
    }

    friend bool operator==(const UniqueHandle& lhs, std::nullptr_t)
    {
        return lhs.m_handle == TNullValue;
    }

    friend bool operator!=(const UniqueHandle& lhs, std::nullptr_t)
    {
        return lhs.m_handle != TNullValue;
    }

    friend bool operator==(std::nullptr_t, const UniqueHandle& rhs)
    {
        return rhs.m_handle == TNullValue;
    }

    friend bool operator!=(std::nullptr_t, const UniqueHandle& rhs)
    {
        return rhs.m_handle != TNullValue;
    }

private:
    T m_handle;
};

