/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROUTER_H
#define _ROUTER_H

#include <algorithm>
#include <map>
#include <string>
#include <type_traits>

#include <fmt/format.h>
#include <rxcpp/rx.hpp>

#include <baseTypes.hpp>

#include "rxcppFactory.hpp"

namespace router
{

/**
 * @brief Represents a route and manages subscription
 *
 */
struct Route
{
    std::string m_name;
    std::string m_to;
    std::function<bool(base::Event)> m_from;
    rxcpp::composite_subscription m_subscription;

    Route() = default;
    Route(const Route& other) = delete;
    Route& operator=(const Route& other) = delete;

    /**
     * @brief Construct a new Route object
     *
     * @param name Name of the route
     * @param environment Environment name wich receives filtered events
     * @param filter_function Filter events to send to environment
     * @param subscription Subscription to handle status
     */
    Route(const std::string& name,
          const std::string& environment,
          std::function<bool(base::Event)> filter_function,
          rxcpp::composite_subscription subscription) noexcept
        : m_name(name)
        , m_to(environment)
        , m_from(filter_function)
        , m_subscription(subscription)
    {
    }

    /**
     * @brief Construct a new Route object
     *
     * @param other
     */
    Route(Route&& other) noexcept
        : m_name {std::move(other.m_name)}
        , m_to {std::move(other.m_to)}
        , m_from {std::move(other.m_from)}
        , m_subscription {std::move(other.m_subscription)}
    {
    }

    /**
     * @brief Move assignation new Route object
     *
     * @param other
     * @return Route&
     */
    Route& operator=(Route&& other) noexcept
    {
        this->m_name = std::move(other.m_name);
        this->m_from = std::move(other.m_from);
        this->m_to = std::move(other.m_to);
        this->m_subscription = std::move(other.m_subscription);
        return *this;
    }

    ~Route()
    {
        if (!this->m_subscription.get_weak().expired()
            && this->m_subscription.is_subscribed())
        {
            this->m_subscription.unsubscribe();
        }
    }
};

/**
 * @brief Defines environment as subject
 *
 */
struct Environment
{
    std::string m_name;
    builder::internals::Expression m_expression;
    rxcppBackend::RxcppController m_controller;

    Environment() = default;

    // TODO: implement move semantics
    /**
     * @brief Construct a new Environment object
     *
     * @param name
     * @param lifter
     * @param debugSinks
     */
    Environment(std::string name,
                builder::internals::Expression expression,
                rxcppBackend::RxcppController&& controller)
        : m_name(name)
        , m_expression(expression)
        , m_controller(std::move(controller))
    {
    }
};

/**
 * @brief Router
 *
 * The Router manages the environments which are ready to be enabled, ie.
 * receive events from the server. Particularily, it can:
 *  - Create a new environment from its Catalog definition by calling the
 * Builder
 *  - Route events received to an environment which is able to accept it
 *  - Enable an environment so it can accept events
 *  - Disable an environment so it can stop accepting events
 *
 * In case there is no environment enabled, the  router will drop the
 * events, freeing all resources associated to them.
 *
 * An environment is a set of decoders, rules, filters and outputs which are set
 * up to work together and a filter to decide which events to accept.
 *
 * @tparam Builder injected builder type to build environments
 */
template<class Builder>
class Router
{

    // // Assert Builder satisfies expected interface/functionality
    // // First check if Builder is callable with a string as an argument
    // static_assert(std::is_invocable_v<Builder, std::string>,
    //               "Error, Builder type is not callable with signature: "
    //               "Builder(std::string)");
    // // Obtain return type of Builder call
    // using builder_ret_type = decltype(std::declval<Builder>()(std::string {}));
    // // Assert builder_ret_type implements the functionality needed by the router

    // // Assert has a getLifter method
    // static_assert(
    //     std::is_member_function_pointer_v<decltype(&builder_ret_type::getLifter)>,
    //     "Error, type returned by Builder does not implement "
    //     "getLifter function");
    // // Assert getLifter returns a lifter
    // static_assert(std::is_same_v<decltype(std::declval<builder_ret_type>().getLifter()),
    //                              base::Lifter>,
    //               "Error, getLifter method does not return function with signature: "
    //               "std::function<Observable(Observable)>");

    // // Assert has a getTraceSinks method
    // static_assert(
    //     std::is_member_function_pointer_v<decltype(&builder_ret_type::getTraceSinks)>,
    //     "Error, type returned by Builder does not implement "
    //     "getTraceSinks function");
    // // Assert getTraceSinks methods returns a map<string, observable<string>>
    // static_assert(
    //     std::is_same_v<decltype(std::declval<builder_ret_type>().getTraceSinks()),
    //                    std::map<std::string, rxcpp::observable<std::string>>>,
    //     "Error, getTraceSinks method does not satisfy signature: "
    //     "std::function<std::map<std::string, "
    //     "rxcpp::observable<std::string>>()>");

private:
    using ServerOutputObs = rxcpp::observable<rxcpp::observable<std::string>>;

    std::map<std::string, Environment> m_environments;
    std::map<std::string, Route> m_routes;
    rxcpp::subjects::subject<rxcppBackend::RxcppEvent> m_subj;
    rxcpp::subscriber<rxcppBackend::RxcppEvent> m_input;
    Builder m_builder;

public:
    void ingestEvent(base::Event&& event)
    {
        m_input.on_next(std::make_shared<base::result::Result<base::Event>>(base::result::makeSuccess(std::move(event))));
    }

    /**
     * @brief Construct a new Router object
     *
     * @param builder Injected Builder object
     */
    Router(const Builder& builder) noexcept
        : m_builder {builder}
        , m_input {m_subj.get_subscriber()}
    {
    }

    /**
     * @brief Add a route
     *
     * @param environment Where events are forwarded
     * @param route Name of the route
     * @param filterFunction Filter function to select forwarded envent
     */
    void add(
        const std::string& route,
        const std::string& environment,
        const std::function<bool(const base::Event&)> filterFunction = [](auto e)
        { return true; })
    {
        // Assert route with same name not exists
        if (this->m_routes.count(route) > 0)
        {
            throw std::invalid_argument("Error, route " + route + " is already in use");
        }

        // Build environment if neccesary
        if (this->m_environments.count(environment) == 0)
        {
            auto envObject = this->m_builder.buildEnvironment(environment);
            auto envController = rxcppBackend::buildRxcppPipeline(envObject);

            this->m_environments.emplace(environment,
                                         Environment(environment,
                                                     envObject.getExpression(),
                                                     std::move(envController)));
        }

        // Route filtered events to enviroment, Router subject implements
        // multicasting (we need to call get_observable for each filter added)

        auto filterFn = [filterFunction](rxcppBackend::RxcppEvent e)
        {
            return e->setStatus(filterFunction(e->payload()));
        };

        auto envInput = this->m_environments.at(environment).m_controller.m_envInput;
        auto subscription =
            this->m_subj.get_observable().filter(filterFunction).subscribe(envInput);

        // Add route to list
        this->m_routes[route] = Route(route, environment, filterFunction, subscription);
    }

    /**
     * @brief Delete route
     *
     * @param route Name of the route to be deleted
     */
    void remove(const std::string& route)
    {
        // Assert route exists
        if (this->m_routes.count(route) == 0)
        {
            throw std::invalid_argument(
                "Error, route " + route
                + " cannot be deleted because is not registered");
        }

        // Delete route and delete environment if not referenced by any other
        // route
        std::string environment {this->m_routes[route].m_to};
        this->m_routes.erase(route);

        if (none_of(this->m_routes.cbegin(),
                    this->m_routes.cend(),
                    [environment](const auto& r)
                    { return r.second.m_to == environment; }))
        {
            this->m_environments.erase(environment);
        }
    }

    /**
     * @brief Obtain Router subscriber to inject events.
     *
     * @return const rxcpp::subscriber<json::Document>&
     */
    const rxcpp::subscriber<rxcppBackend::RxcppEvent>& input() const
    {
        return this->m_input;
    }

    /**
     * @brief Get const reference of environments registered
     *
     * @return const std::map<std::string, Environment>&
     */
    const std::map<std::string, Environment>& environments() const noexcept
    {
        return this->m_environments;
    }

    /**
     * @brief Get const reference of routes registered
     *
     * @return const std::map<std::string, Route>
     */
    const std::map<std::string, Route>& routes() const noexcept
    {
        return this->m_routes;
    }

    /**
     * @brief Subscribe to specified trace sink.
     *
     * @param environment
     * @param asset
     * @param subscriberOnNext
     */
    void subscribeTraceSink(std::string environment,
                            std::string asset,
                            std::function<void(std::string)> subscriberOnNext)
    {
        if (m_environments.count(environment) > 0)
        {
            auto subscriber =
                rxcpp::make_subscriber<std::string>([=](auto s) { subscriberOnNext(s); });
            m_environments[environment].m_controller.listenOnTrace(asset, subscriber);
        }
        else
        {
            throw std::runtime_error(fmt::format(
                "Error subscribing trace sink, enviroment [{}] does not exists",
                environment));
        }
    }

    /**
     * @brief Subscribes to all trace sinks for specified environment
     *
     * @param environment
     * @param subscriberOnNext
     */
    void subscribeAllTraceSinks(std::string environment,
                                std::function<void(std::string)> subscriberOnNext)
    {
        if (m_environments.count(environment) > 0)
        {
            auto subscriber =
                rxcpp::make_subscriber<std::string>([=](auto s) { subscriberOnNext(s); });
            m_environments[environment].m_controller.listenOnAllTrace(subscriber);
        }
        else
        {
            throw std::runtime_error(fmt::format(
                "Error subscribing trace sink, enviroment [{}] does not exists",
                environment));
        }
    }
};

} // namespace router

#endif // _ROUTER_H
