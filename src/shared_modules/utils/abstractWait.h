/*
 * Utils abstract wait
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _ABSTRACT_WAIT_HPP
#define _ABSTRACT_WAIT_HPP

#include <future>
#include <thread>

class IWait
{
    public:
        virtual ~IWait() = default;
        virtual void set_value() = 0;
        virtual void wait() = 0;
};

class PromiseWaiting final : public IWait
{
        std::promise<void> m_promise;

    public:
        explicit PromiseWaiting() {};

        virtual ~PromiseWaiting() = default;

        virtual void set_value() override
        {
            m_promise.set_value();
        }

        virtual void wait() override
        {
            m_promise.get_future().wait();
        }
};


class BusyWaiting final : public IWait
{
        std::atomic<bool> end;

    public:
        explicit BusyWaiting() : end {false} {};

        virtual ~BusyWaiting() = default;

        virtual void set_value() override
        {
            end = true;
        }

        virtual void wait() override
        {
            while (!end.load())
            {
                std::this_thread::sleep_for(std::chrono::seconds{1});
            }
        }
};


#endif // _ABSTRACT_WAIT_HPP
