#include "api/geo/handlers.hpp"

#include <eMessages/eMessage.h>
#include <eMessages/geo.pb.h>
#include <base/json.hpp>

#include <api/adapter.hpp>

namespace
{
template<typename RequestType>
using GeoAndRequest = std::pair<std::shared_ptr<::geo::IManager>, RequestType>; ///< Manager and request pair
/**
 * @brief Get the request from the wazuh request and validate the manager
 *
 * @tparam RequestType
 * @tparam ResponseType
 * @param wRequest The wazuh request to convert
 * @param geoManager weak pointer to the manager to validate
 * @return std::variant<api::wpResponse, RouterAndRequest<RequestType>>
 */
template<typename RequestType, typename ResponseType>
std::variant<api::wpResponse, GeoAndRequest<RequestType>> getRequest(const api::wpRequest& wRequest,
                                                                     const std::weak_ptr<::geo::IManager>& geoManager)
{
    auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);
    // validate the request
    if (std::holds_alternative<api::wpResponse>(res))
    {
        return std::move(std::get<api::wpResponse>(res));
    }

    // validate the manager
    auto manager = geoManager.lock();
    if (!manager)
    {
        return api::adapter::genericError<ResponseType>("Geo Manager is not available");
    }

    return std::make_pair(manager, std::get<RequestType>(res));
}
} // namespace

namespace api::geo::handlers
{
// Using the engine protobuffer namespace
namespace eGeo = ::com::wazuh::api::engine::geo;
namespace eEngine = ::com::wazuh::api::engine;

using api::adapter::genericError;
using api::adapter::genericSuccess;

api::HandlerSync addDbCmd(const std::weak_ptr<::geo::IManager>& geoManager)
{
    return [geoManager](const api::wpRequest& wpRequest) -> api::wpResponse
    {
        using RequestType = eGeo::DbPost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Validate the request
        auto res = getRequest<RequestType, ResponseType>(wpRequest, geoManager);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [manager, request] = std::get<GeoAndRequest<RequestType>>(res);

        // Verify the type is valid
        ::geo::Type type;
        try
        {
            type = ::geo::typeFromName(request.type());
        }
        catch (const std::exception& e)
        {
            return genericError<ResponseType>(fmt::format("{} -> {}", e.what(), ::geo::validTypeNames()));
        }

        // Verify path is not empty
        if (request.path().empty())
        {
            return genericError<ResponseType>("Path is mandatory");
        }

        // Add the database
        auto status = manager->addDb(request.path(), type);

        // Build and return the response
        if (base::isError(status))
        {
            return genericError<ResponseType>(base::getError(status).message);
        }

        return genericSuccess<ResponseType>();
    };
}

api::HandlerSync delDbCmd(const std::weak_ptr<::geo::IManager>& geoManager)
{
    return [geoManager](const api::wpRequest& wpRequest) -> api::wpResponse
    {
        using RequestType = eGeo::DbDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Validate the request
        auto res = getRequest<RequestType, ResponseType>(wpRequest, geoManager);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [manager, request] = std::get<GeoAndRequest<RequestType>>(res);

        // Verify path is not empty
        if (request.path().empty())
        {
            return genericError<ResponseType>("Path is mandatory");
        }

        // Delete the database
        auto status = manager->removeDb(request.path());

        // Build and return the response
        if (base::isError(status))
        {
            return genericError<ResponseType>(base::getError(status).message);
        }

        return genericSuccess<ResponseType>();
    };
}

api::HandlerSync listDbCmd(const std::weak_ptr<::geo::IManager>& geoManager)
{
    return [geoManager](const api::wpRequest& wpRequest) -> api::wpResponse
    {
        using RequestType = eGeo::DbList_Request;
        using ResponseType = eGeo::DbList_Response;

        // Validate the request
        auto res = getRequest<RequestType, ResponseType>(wpRequest, geoManager);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [manager, request] = std::get<GeoAndRequest<RequestType>>(res);

        // Get the databases
        auto dbs = manager->listDbs();

        // Build and return the response
        ResponseType response;
        for (const auto& db : dbs)
        {
            auto* dbResponse = response.add_entries();
            dbResponse->set_name(db.name);
            dbResponse->set_path(db.path);
            dbResponse->set_type(::geo::typeName(db.type));
        }

        response.set_status(eEngine::ReturnStatus::OK);

        return api::adapter::toWazuhResponse(response);
    };
}

api::HandlerSync remoteUpsertDbCmd(const std::weak_ptr<::geo::IManager>& geoManager)
{
    return [geoManager](const api::wpRequest& wpRequest) -> api::wpResponse
    {
        using RequestType = eGeo::DbRemoteUpsert_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Validate the request
        auto res = getRequest<RequestType, ResponseType>(wpRequest, geoManager);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [manager, request] = std::get<GeoAndRequest<RequestType>>(res);

        // Verify the type is valid
        ::geo::Type type;
        try
        {
            type = ::geo::typeFromName(request.type());
        }
        catch (const std::exception& e)
        {
            return genericError<ResponseType>(fmt::format("{} -> {}", e.what(), ::geo::validTypeNames()));
        }

        // Verify path is not empty
        if (request.path().empty())
        {
            return genericError<ResponseType>("Path is mandatory");
        }

        // Verify the dburl is not empty
        if (request.dburl().empty())
        {
            return genericError<ResponseType>("Dburl is mandatory");
        }

        // Verify the hashurl is not empty
        if (request.hashurl().empty())
        {
            return genericError<ResponseType>("Hashurl is mandatory");
        }

        // Add the database
        auto status = manager->remoteUpsertDb(request.path(), type, request.dburl(), request.hashurl());

        // Build and return the response
        if (base::isError(status))
        {
            return genericError<ResponseType>(base::getError(status).message);
        }

        return genericSuccess<ResponseType>();
    };
}
} // namespace api::geo::handlers
