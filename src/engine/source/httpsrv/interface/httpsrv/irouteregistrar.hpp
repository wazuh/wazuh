// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _HTTPSRV_IROUTEREGISTRAR_HPP
#define _HTTPSRV_IROUTEREGISTRAR_HPP

#include <string>

#include <httpsrv/types.hpp>

namespace httpsrv
{

/**
 * @brief What an API module needs from a server: a place to register its routes.
 *
 * The handlers' registerHandlers() take this instead of a concrete server, so they do not depend on the
 * transport that serves them.
 */
class IRouteRegistrar
{
public:
    virtual ~IRouteRegistrar() = default;

    /**
     * @brief Registers a route. Must be called before the server starts.
     *
     * @param method HTTP method.
     * @param path Exact path, without query string.
     * @param handler Fills the response for one request.
     * @param options Route class and body cap; a server may not support every option.
     */
    virtual void addRoute(Method method, const std::string& path, RouteHandler handler, RouteOptions options = {}) = 0;
};

} // namespace httpsrv

#endif // _HTTPSRV_IROUTEREGISTRAR_HPP
