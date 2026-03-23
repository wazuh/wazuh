/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * May 16, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DEFER_H_
#define _DEFER_H_

#define DEFER(...)        auto CONCAT(__defer_auto_defer__, __COUNTER__) = deferFunc(__VA_ARGS__)
#define DEFER_STATIC(...) static auto CONCAT(__defer_auto_defer__, __COUNTER__) = deferFunc(__VA_ARGS__)

#define CONCAT(x, y)      CONCAT_IMPL(x, y)
#define CONCAT_IMPL(x, y) x##y

/**
 * @brief A Defer object calls a function object in its destructor
 *
 * This is a templated class that can store any type of function object. When the
 * Defer object is destroyed (i.e., when it goes out of scope), its destructor
 * calls the stored function object. This is useful for performing cleanup
 * operations or releasing resources at the end of a scope.
 *
 * @tparam F The type of the function object to be stored
 */
template<typename F>
class Defer final
{
public:
    /**
     * @brief Constructor that stores a function object
     * @param f The function object to be stored
     */
    explicit Defer(F f)
        : m_f(f)
    {
    }

    /**
     * @brief Destructor that calls the stored function object
     */
    ~Defer()
    {
        m_f();
    }

private:
    F m_f; ///< The stored function object
};

/**
 * @brief Create a Defer object that stores a function object
 *
 * This is a templated function that creates a Defer object and stores a given
 * function object in it. It is intended to be used in conjunction with a lambda
 * function to provide a simple implementation of a defer statement.
 *
 * @tparam F The type of the function object to be stored
 * @param f The function object to be stored
 * @return A Defer object that stores the given function object
 */
template<typename F>
Defer<F> deferFunc(F f)
{
    return Defer<F>(f);
}

#endif // _DEFER_H_
