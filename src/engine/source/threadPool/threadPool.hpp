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

#include <rxcpp/rx.hpp>

namespace threadpool
{

using rxcpp::composite_subscription;
using rxcpp::schedulers::scheduler_interface;
using rxcpp::schedulers::thread_factory;
using rxcpp::schedulers::worker;

struct threadPool : public scheduler_interface
{
private:
    typedef threadPool this_type;
    threadPool(const this_type &);

    struct loop_worker : public rxcpp::schedulers::worker_interface
    {
    private:
        typedef loop_worker this_type;
        loop_worker(const this_type &);

        typedef rxcpp::schedulers::detail::schedulable_queue<typename clock_type::time_point> queue_item_time;

        typedef queue_item_time::item_type item_type;

        composite_subscription lifetime;
        worker controller;
        std::shared_ptr<const scheduler_interface> alive;

    public:
        virtual ~loop_worker()
        {
        }

        loop_worker(composite_subscription cs, worker w, std::shared_ptr<const scheduler_interface> alive)
            : lifetime(cs), controller(w), alive(alive)
        {
            auto token = controller.add(cs);
            cs.add([token, w]() { w.remove(token); });
        }

        virtual clock_type::time_point now() const
        {
            return clock_type::now();
        }

        virtual void schedule(const rxcpp::schedulers::schedulable & scbl) const
        {
            controller.schedule(lifetime, scbl.get_action());
        }

        virtual void schedule(clock_type::time_point when, const rxcpp::schedulers::schedulable & scbl) const
        {
            controller.schedule(when, lifetime, scbl.get_action());
        }
    };

    mutable thread_factory factory;
    rxcpp::schedulers::scheduler newthread;
    mutable std::atomic<std::size_t> count;
    composite_subscription loops_lifetime;
    std::vector<worker> loops;
    int nThreads;

    void initThreads(void);

public:
    threadPool(int _nThreads = 1)
        : nThreads(_nThreads), factory([](std::function<void()> start) { return std::thread(std::move(start)); }),
          newthread(rxcpp::schedulers::make_new_thread()), count(0)
    {
        initThreads();
    }
    explicit threadPool(int _nThreads, thread_factory tf)
        : nThreads(_nThreads), factory(tf), newthread(rxcpp::schedulers::make_new_thread(tf)), count(0)
    {
        initThreads();
    }
    virtual ~threadPool()
    {
        loops_lifetime.unsubscribe();
    }

    virtual clock_type::time_point now() const
    {
        return clock_type::now();
    }

    virtual worker create_worker(composite_subscription cs) const
    {
        return worker(cs, std::make_shared<loop_worker>(cs, loops[++count % loops.size()], this->shared_from_this()));
    }
};

} // namespace threadpool

#endif // _THREAD_POOL_HPP_
