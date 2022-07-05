/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef PIPELINE_NODES_IMP_H
#define PIPELINE_NODES_IMP_H
#include <functional>
#include "threadDispatcher.h"
#include "pipelinePattern.h"

namespace Utils
{
    template
    <
        typename Input,
        typename Functor = std::function<void(const Input&)>,
        template <class, class> class Dispatcher = SyncDispatcher
        >
    class ReadNode : public Dispatcher<Input, Functor>
    {
        public:
            ReadNode(Functor functor)
                : DispatcherType{ functor }
            {}
            ReadNode(Functor functor,
                     const unsigned int numberOfThreads)
                : DispatcherType{ functor, numberOfThreads, UNLIMITED_QUEUE_SIZE }
            {}
            // LCOV_EXCL_START
            ~ReadNode() = default;
            // LCOV_EXCL_STOP
            void receive(const Input& data)
            {
                DispatcherType::push(data);
            }
        private:
            using DispatcherType = Dispatcher<Input, Functor>;
            using ReadNodeType = ReadNode<Input, Functor, Dispatcher>;
    };

    template
    <
        typename Input,
        typename Output,
        typename Reader,
        typename Functor = std::function<Output(const Input&)>,
        template <class, class> class Dispatcher = SyncDispatcher
        >
    class ReadWriteNode : public Utils::IPipelineWriter<Output, Reader>
        , public Dispatcher<Input, std::function<void(const Input&)>>
    {
        public:
            ReadWriteNode(Functor functor)
                : DispatcherType{ std::bind(&RWNodeType::doTheWork, this, std::placeholders::_1) }
                , m_functor{functor}
            {}
            ReadWriteNode(Functor functor,
                          const unsigned int numberOfThreads)
                : DispatcherType{ std::bind(&RWNodeType::doTheWork, this, std::placeholders::_1), numberOfThreads, UNLIMITED_QUEUE_SIZE }
                , m_functor{functor}
            {}
            // LCOV_EXCL_START
            ~ReadWriteNode() = default;
            // LCOV_EXCL_STOP
            void receive(const Input& data)
            {
                DispatcherType::push(data);
            }
        private:
            using DispatcherType = Dispatcher<Input, std::function<void(const Input&)>>;
            using RWNodeType = ReadWriteNode<Input, Output, Reader, Functor, Dispatcher>;
            using WriterType = Utils::IPipelineWriter<Output, Reader>;

            void doTheWork(const Input& data)
            {
                WriterType::send(m_functor(data));
            }
            Functor m_functor;
    };
}// namespace Utils

#endif //PIPELINE_NODES_IMP_H
