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
        : name(n), from(f), to(e), subscription(s)
    {
    }
    std::string name;
    std::string to;
    std::function<bool(F)> from;
    rxcpp::composite_subscription subscription;
};

/**
 * @brief an environment has a name and an observable
 * of class F events.
 *
 * @tparam F
 */
template <class F> struct environment
{
    environment(std::string n, rxcpp::subjects::subject<F> s) : name(n), subject(s)
    {
    }
    std::string name;
    rxcpp::subjects::subject<F> subject;
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
    std::vector<environment<F>> environments;

    /**
     * @brief a route maps an environment name, a filter function and
     * and environment implementation as operations.
     */
    std::vector<route<F>> routes;

    /**
     * @brief a router send all events published through all the
     * enabled routes. It is implmented by a rxcpp::observable.
     *
     */
    rxcpp::observable<F> router;

    /**
     * @brief a builder function to get the environment
     * observable. This entry point must be initialized on
     * construction.
     *
     */
    std::function<rxcpp::subjects::subject<F>(std::string)> build;

public:
    /**
     * @brief Construct a new Router<F> object
     *
     * @param h handler function
     * @param b builder function
     */
    Router<F>(const std::function<void(rxcpp::subscriber<F>)> h,
              std::function<rxcpp::subjects::subject<F>(std::string)> b)
        : build(b)
    {
        auto threads = rxcpp::observe_on_event_loop();
        router = rxcpp::observable<>::create<F>(h).publish().ref_count().subscribe_on(threads);
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

        if (std::any_of(std::begin(this->routes), std::end(this->routes),
                        [name](const auto & r) { return r.name == name; }))
            throw std::invalid_argument("Tried to add a route, but it's name is already in use by another route");

        auto res = std::find_if(std::begin(this->environments), std::end(this->environments),
                                [to](const auto & e) { return e.name == to; });

        if (res == std::end(this->environments))
        {
            envSub = this->build(name);
            this->environments.push_back(environment(to, envSub));
        }
        else
        {
            envSub = (*res).subject;
        }

        auto r = this->router.filter(from);

        auto sub = r.subscribe(envSub.get_subscriber());

        this->routes.push_back(route(name, from, to, sub));
    }

    /**
     * @brief removes the route named name
     *
     * @throws std::invalid_argument when the route name is not found
     * @param name
     */
    void remove(std::string name)
    {
        auto it = std::find_if(std::begin(this->routes), std::end(this->routes),
                               [name](const auto & r) { return r.name == name; });

        if (it == std::end(this->routes))
        {
            throw std::invalid_argument("Tried to delete a route, but it's name is not in the route table.");
        }

        (*it).subscription.unsubscribe();

        auto to = (*it).to;
        this->routes.erase(it);

        auto s =
            std::any_of(std::begin(this->routes), std::end(this->routes), [to](const auto & r) { return r.to == to; });

        if (!s)
        {
            auto it = std::remove_if(std::begin(this->environments), std::end(this->environments),
                                     [to](const auto & e) { return e.name == to; });
            // remove_if does not re
            this->environments.erase(it);
        }
    }

    /**
     * @brief list all routes in the router
     *
     * @return std::vector<route>
     */
    std::vector<route<F>> list()
    {
        return this->routes;
    }
};

} // namespace Router

#endif // _ROUTER_H
