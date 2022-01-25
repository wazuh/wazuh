#ifndef _ROUTER_H
#define _ROUTER_H

/**
 * @section Router
 *
 * The Router manages the environments which are ready to be enabled, ie.
 * receive events from the server. Particularily, it can:
 *  - Create a new environment from its Catalog definition by calling the Builder
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
 *
 */
#include <rxcpp/rx.hpp>
#include <string>
#include <vector>

namespace Router
{

/**
 * @brief a route has an environment_name, a filter
 * and a subject of the built environment
 *
 * @tparam F
 */
template <class F> struct route
{
    route(std::string n, std::function<bool(F)> f, std::string e, rxcpp::composite_subscription s)
        : m_name(n), m_from(f), m_to(e), m_subscription(s)
    {
    }
    std::string m_name;
    std::string m_to;
    std::function<bool(F)> m_from;
    rxcpp::composite_subscription m_subscription;
};

/**
 * @brief an environment has a name and an observable
 * of class F events.
 *
 * @tparam F
 */
template <class F> struct environment
{
    environment(std::string n, rxcpp::subjects::subject<F> s) : m_name(n), m_subject(s)
    {
    }
    std::string m_name;
    rxcpp::subjects::subject<F> m_subject;
};

/**
 * @brief a router forwards events as stated by each one of its routes. It
 * allows adding and deleting routes.
 *
 * @tparam F
 */
template <class F> class Router
{
private:
    /**
     * @brief environments available for routing. This collection
     * is used as a cache, because the lifecycle of an environment
     * is tied to the routes.
     *
     */
    std::vector<environment<F>> m_environments;

    /**
     * @brief a route maps an environment name, a filter function and
     * and environment implementation as operations.
     */
    std::vector<route<F>> m_routes;

    /**
     * @brief a router send all events published through all the
     * enabled routes. It is implmented by a rxcpp::observable.
     *
     */
    rxcpp::observable<F> m_router;

    /**
     * @brief a builder function to get the environment
     * observable. This entry point must be initialized on
     * construction.
     *
     */
    std::function<rxcpp::subjects::subject<F>(std::string)> m_build;

public:
    /**
     * @brief Construct a new Router<F> object
     *
     * @param h handler function
     * @param b builder function
     */
    Router<F>(const std::function<void(rxcpp::subscriber<F>)> h,
              std::function<rxcpp::subjects::subject<F>(std::string)> b)
        : m_build(b)
    {
        auto threads = rxcpp::observe_on_event_loop();
        m_router = rxcpp::observable<>::create<F>(h).publish().ref_count().subscribe_on(threads);
    };

    /**
     * @brief Adds a new route to an environment. If the environment does not
     * exists, it will call Builder to create it before creating the route.
     *
     * We can create more than one route per environment.
     *
     * @throws std::invalid_argument when the route name is already registered
     * @param name of the route
     * @param from filter to get events from
     * @param to environment name
     */
    void add(std::string name, std::function<bool(F)> from, std::string to)
    {
        rxcpp::subjects::subject<F> envSub;

        if (std::any_of(std::begin(this->m_routes), std::end(this->m_routes),
                        [name](const auto & r) { return r.m_name == name; }))
            throw std::invalid_argument("Tried to add a route, but it's name is already in use by another route");

        auto res = std::find_if(std::begin(this->m_environments), std::end(this->m_environments),
                                [to](const auto & e) { return e.m_name == to; });

        if (res == std::end(this->m_environments))
        {
            envSub = this->m_build(name);
            this->m_environments.push_back(environment(to, envSub));
        }
        else
        {
            envSub = (*res).m_subject;
        }

        auto r = this->m_router.filter(from);

        auto sub = r.subscribe(envSub.get_subscriber());

        this->m_routes.push_back(route(name, from, to, sub));
    }

    /**
     * @brief removes the route named name
     *
     * @throws std::invalid_argument when the route name is not found
     * @param name
     */
    void remove(std::string name)
    {
        auto it = std::find_if(std::begin(this->m_routes), std::end(this->m_routes),
                               [name](const auto & r) { return r.m_name == name; });

        if (it == std::end(this->m_routes))
        {
            throw std::invalid_argument("Tried to delete a route, but it's name is not in the route table.");
        }

        (*it).m_subscription.unsubscribe();

        auto to = (*it).m_to;
        this->m_routes.erase(it);

        auto s =
            std::any_of(std::begin(this->m_routes), std::end(this->m_routes), [to](const auto & r) { return r.m_to == to; });

        if (!s)
        {
            auto it = std::remove_if(std::begin(this->m_environments), std::end(this->m_environments),
                                     [to](const auto & e) { return e.m_name == to; });
            // remove_if does not re
            this->m_environments.erase(it);
        }
    }

    /**
     * @brief list all routes in the router
     *
     * @return std::vector<route>
     */
    std::vector<route<F>> list()
    {
        return this->m_routes;
    }
};

} // namespace Router

#endif // _ROUTER_H
