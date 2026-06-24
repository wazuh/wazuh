#include <api/status/handlers.hpp>

#include <base/logging.hpp>
#include <base/syncStatus.hpp>
#include <eMessages/status.pb.h>

namespace api::status::handlers
{

namespace eStatus = adapter::eEngine::status;
namespace eEngine = ::com::wazuh::api::engine;

adapter::RouteHandler getStatus(const std::shared_ptr<cm::sync::ICMSync>& cmSync,
                                const std::shared_ptr<ioc::sync::IIocSync>& iocSync,
                                const std::shared_ptr<::geo::IManager>& geoManager)
{
    return [weakCmSync = std::weak_ptr(cmSync),
            weakIocSync = std::weak_ptr(iocSync),
            weakGeo = std::weak_ptr(geoManager)](const auto& req, auto& res)
    {
        using ResponseType = eStatus::StatusGet_Response;

        // Lock all providers
        auto cmSyncPtr = weakCmSync.lock();
        auto iocSyncPtr = weakIocSync.lock();
        auto geoPtr = weakGeo.lock();

        if (!cmSyncPtr || !iocSyncPtr || !geoPtr)
        {
            LOG_ERROR("Status handler: one or more providers are unavailable");
            res.status = httplib::StatusCode::InternalServerError_500;
            res.set_content("Internal Server Error", "text/plain");
            return;
        }

        bool ready = true;

        // Build spaces state
        ResponseType eResponse;
        auto* spacesMap = eResponse.mutable_spaces();
        for (const auto& space : cmSyncPtr->getSpacesStatus())
        {
            eStatus::SpaceState protoSpace;
            protoSpace.set_available(space.available);
            protoSpace.set_enabled(space.enabled);
            protoSpace.set_status(base::syncStatusToStr(space.status));
            protoSpace.set_hash(space.hash);
            protoSpace.set_last_successful_update(space.lastSuccessfulUpdate);

            // Readiness check: enabled spaces must be available
            if (space.enabled && !space.available)
            {
                ready = false;
            }

            (*spacesMap)[space.name] = std::move(protoSpace);
        }

        // Build IOC state
        auto* iocMap = eResponse.mutable_ioc();
        for (const auto& iocType : iocSyncPtr->getIocStatus())
        {
            eStatus::ResourceState protoIoc;
            protoIoc.set_available(iocType.available);
            protoIoc.set_status(base::syncStatusToStr(iocType.status));
            protoIoc.set_hash(iocType.hash);
            protoIoc.set_last_successful_update(iocType.lastSuccessfulUpdate);

            // Readiness check: all IOC types must be available
            if (!iocType.available)
            {
                ready = false;
            }

            (*iocMap)[iocType.type] = std::move(protoIoc);
        }

        // Build Geo state
        auto* geoMap = eResponse.mutable_geo();
        for (const auto& geoDB : geoPtr->getGeoStatus())
        {
            eStatus::ResourceState protoGeo;
            protoGeo.set_available(geoDB.available);
            protoGeo.set_status(base::syncStatusToStr(geoDB.status));
            protoGeo.set_hash(geoDB.hash);
            protoGeo.set_last_successful_update(geoDB.lastSuccessfulUpdate);

            // Readiness check: all geo DBs must be available
            if (!geoDB.available)
            {
                ready = false;
            }

            (*geoMap)[geoDB.name] = std::move(protoGeo);
        }

        eResponse.set_ready(ready);
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

} // namespace api::status::handlers
