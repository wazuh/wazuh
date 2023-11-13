#ifndef _ROUTER2_ROUTERADMIN_HPP
#define _ROUTER2_ROUTERADMIN_HPP

#include <list>
#include <memory>

#include <bk/icontroller.hpp>
#include <store/istore.hpp>

#include <builder/registry.hpp>

#include <router/types.hpp>

namespace router
{

struct Config
{

    std::size_t m_numThreads;
    std::shared_ptr<store::IStore> m_store;
    std::shared_ptr<builder::internals::Registry<builder::internals::Builder>> m_registry;
    std::shared_ptr<bk::IControllerMaker> m_controllerMaker;

};

class RouterAdmin
{

    // Forwarding declarations
    // std::list<std::shared_ptr<IRouter<T>>> m_routers; ///< The list of routers managed by the admin
    // std::shared_ptr<IBuilder> m_builder;           ///< The builder for the routers

    // Config
    Config m_config;

public:
    ~RouterAdmin() = default;
    RouterAdmin(Config Config)
        : m_config(Config)
    {
    };

    void stop() { return; }
};

} // namespace router

#endif // _ROUTER2_ROUTERADMIN_HPP