#ifndef _ROUTER2_ROUTERADMIN_HPP
#define _ROUTER2_ROUTERADMIN_HPP

#include <list>
#include <memory>

#include <bk/icontroller.hpp>

#include <router/types.hpp>

namespace router
{

template<typename T>
class Router;

struct Config{
    std::size_t m_numThreads;
};

template <typename T>
class RouterAdmin
{

    // Forwarding declarations
    std::list<std::shared_ptr<Router<T>>> m_routers;
    

public:
    
    ~RouterAdmin() = default;
    RouterAdmin(Config Config) : m_routers()
    {

    }

    void stop() {
        return;
    }
};

} // namespace router

#endif // _ROUTER2_ROUTERADMIN_HPP