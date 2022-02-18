/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 *  program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _THREAD_POOL_HPP_
#define _THREAD_POOL_HPP_

#include <chrono>
#include <rxcpp/rx.hpp>

namespace threadpool
{

struct ThreadPool : public rxcpp::schedulers::scheduler_interface
{
private:
    typedef ThreadPool this_type;
    ThreadPool(const this_type &);

    struct loop_worker : public rxcpp::schedulers::worker_interface
    {
    private:
        typedef loop_worker this_type;
        loop_worker(const this_type &);

        typedef rxcpp::schedulers::detail::schedulable_queue<typename clock_type::time_point> queue_item_time;

        typedef queue_item_time::item_type item_type;

        rxcpp::composite_subscription lifetime;
        rxcpp::schedulers::worker controller;
        std::shared_ptr<const rxcpp::schedulers::scheduler_interface> alive;

    public:
        virtual ~loop_worker();

        loop_worker(rxcpp::composite_subscription cs, rxcpp::schedulers::worker w,
                    std::shared_ptr<const rxcpp::schedulers::scheduler_interface> alive);

        virtual clock_type::time_point now() const;

        virtual void schedule(const rxcpp::schedulers::schedulable & scbl) const;

        virtual void schedule(clock_type::time_point when, const rxcpp::schedulers::schedulable & scbl) const;
    };

    mutable rxcpp::schedulers::thread_factory factory;
    rxcpp::schedulers::scheduler newthread;
    mutable std::atomic<std::size_t> count;
    rxcpp::composite_subscription loops_lifetime;
    std::vector<rxcpp::schedulers::worker> loops;
    int nThreads;

    void initThreads(void);

public:
    ThreadPool(int _nThreads = 1);
    explicit ThreadPool(int _nThreads, rxcpp::schedulers::thread_factory tf);
    virtual ~ThreadPool();

    virtual clock_type::time_point now() const;

    virtual rxcpp::schedulers::worker create_worker(rxcpp::composite_subscription cs) const;
};

} // namespace threadpool

#endif // _THREAD_POOL_HPP_
