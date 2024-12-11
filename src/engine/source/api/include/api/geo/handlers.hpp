#ifndef _API_GEO_HANDLERS_HPP
#define _API_GEO_HANDLERS_HPP

#include <api/api.hpp>
#include <geo/imanager.hpp>

namespace api::geo::handlers
{

api::HandlerSync addDbCmd(const std::weak_ptr<::geo::IManager>& geoManager);
api::HandlerSync delDbCmd(const std::weak_ptr<::geo::IManager>& geoManager);
api::HandlerSync listDbCmd(const std::weak_ptr<::geo::IManager>& geoManager);
api::HandlerSync remoteUpsertDbCmd(const std::weak_ptr<::geo::IManager>& geoManager);

/**
 * @brief Register all available Geo commands in the API registry.
 *
 * @param registry API registry.
 * @throw std::runtime_error If the command registration fails for any reason.
 */
inline void registerHandlers(const std::shared_ptr<::geo::IManager>& geoManager, std::shared_ptr<api::Api> api)
{
    try
    {
        api->registerHandler("geo.db/post", Api::convertToHandlerAsync(addDbCmd(geoManager)));
        api->registerHandler("geo.db/delete", Api::convertToHandlerAsync(delDbCmd(geoManager)));
        api->registerHandler("geo.db/list", Api::convertToHandlerAsync(listDbCmd(geoManager)));
        api->registerHandler("geo.db/remoteUpsert", Api::convertToHandlerAsync(remoteUpsertDbCmd(geoManager)));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Geo API commands could not be registered: {}", e.what()));
    }
}

} // namespace api::geo::handlers
#endif // _API_GEO_HANDLERS_HPP
