#include <api/geo/handlers.hpp>

#include <eMessages/geo.pb.h>

namespace api::geo::handlers
{
namespace eGeo = adapter::eEngine::geo;
namespace eEngine = adapter::eEngine;

adapter::RouteHandler addDb(const std::shared_ptr<::geo::IManager>& geoManager)
{
    return [weakGeoManager = std::weak_ptr<::geo::IManager> {geoManager}](const auto& req, auto& res)
    {
        using RequestType = eGeo::DbPost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getHandler<ResponseType>(weakGeoManager);
        if (adapter::isError(result))
        {
            res = adapter::getError(result);
            return;
        }

        auto geoManager = adapter::getRes(result);

        auto reqOrError = adapter::parseRequest<RequestType, ResponseType>(req);
        if (adapter::isError(reqOrError))
        {
            res = adapter::getErrorResp(reqOrError);
            return;
        }

        auto protoReq = adapter::getReq<RequestType>(reqOrError);

        // Validate the params request
        auto path = protoReq.path();
        if (path.empty())
        {
            res = adapter::userErrorResponse<ResponseType>("Path cannot be empty");
            return;
        }
        ::geo::Type type;
        try
        {
            type = ::geo::typeFromName(protoReq.type());
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(e.what());
            return;
        }

        // Add the database
        const auto invalid = geoManager->addDb(path, type);
        if (base::isError(invalid))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(invalid).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler delDb(const std::shared_ptr<::geo::IManager>& geoManager)
{
    return [weakGeoManager = std::weak_ptr<::geo::IManager> {geoManager}](const auto& req, auto& res)
    {
        using RequestType = eGeo::DbDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getHandler<ResponseType>(weakGeoManager);
        if (adapter::isError(result))
        {
            res = adapter::getError(result);
            return;
        }

        auto geoManager = adapter::getRes(result);

        auto reqOrError = adapter::parseRequest<RequestType, ResponseType>(req);
        if (adapter::isError(reqOrError))
        {
            res = adapter::getErrorResp(reqOrError);
            return;
        }

        auto protoReq = adapter::getReq<RequestType>(reqOrError);

        // Validate the params request
        auto path = protoReq.path();
        if (path.empty())
        {
            res = adapter::userErrorResponse<ResponseType>("Path cannot be empty");
            return;
        }

        // Delete the database
        const auto invalid = geoManager->removeDb(path);
        if (base::isError(invalid))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(invalid).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler listDb(const std::shared_ptr<::geo::IManager>& geoManager)
{
    return [weakGeoManager = std::weak_ptr<::geo::IManager> {geoManager}](const auto& req, auto& res)
    {
        using RequestType = eGeo::DbList_Request;
        using ResponseType = eGeo::DbList_Response;

        auto result = adapter::getHandler<ResponseType>(weakGeoManager);
        if (adapter::isError(result))
        {
            res = adapter::getError(result);
            return;
        }

        auto geoManager = adapter::getRes(result);

        auto reqOrError = adapter::parseRequest<RequestType, ResponseType>(req);
        if (adapter::isError(reqOrError))
        {
            res = adapter::getErrorResp(reqOrError);
            return;
        }

        auto protoReq = adapter::getReq<RequestType>(reqOrError);

        // Get the databases
        const auto dbs = geoManager->listDbs();
        ResponseType response;

        for (const auto& db : dbs)
        {
            auto* dbResponse = response.add_entries();
            dbResponse->set_name(db.name);
            dbResponse->set_path(db.path);
            dbResponse->set_type(::geo::typeName(db.type));
        }

        response.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(response);
    };
}

adapter::RouteHandler remoteUpsertDb(const std::shared_ptr<::geo::IManager>& geoManager)
{
    return [weakGeoManager = std::weak_ptr<::geo::IManager> {geoManager}](const auto& req, auto& res)
    {
        using RequestType = eGeo::DbRemoteUpsert_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getHandler<ResponseType>(weakGeoManager);
        if (adapter::isError(result))
        {
            res = adapter::getError(result);
            return;
        }

        auto geoManager = adapter::getRes(result);

        auto reqOrError = adapter::parseRequest<RequestType, ResponseType>(req);
        if (adapter::isError(reqOrError))
        {
            res = adapter::getErrorResp(reqOrError);
            return;
        }

        auto protoReq = adapter::getReq<RequestType>(reqOrError);

        // Validate the params request
        ::geo::Type type;
        try
        {
            type = ::geo::typeFromName(protoReq.type());
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(e.what());
            return;
        }

        auto path = protoReq.path();
        if (path.empty())
        {
            res = adapter::userErrorResponse<ResponseType>("Path is mandatory");
            return;
        }

        auto dburl = protoReq.dburl();
        if (dburl.empty())
        {
            res = adapter::userErrorResponse<ResponseType>("Dburl is mandatory");
            return;
        }

        auto hashurl = protoReq.hashurl();
        if (hashurl.empty())
        {
            res = adapter::userErrorResponse<ResponseType>("Hashurl is mandatory");
            return;
        }

        // Add the database
        const auto invalid = geoManager->remoteUpsertDb(path, type, dburl, hashurl);
        if (base::isError(invalid))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(invalid).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}
} // namespace api::geo::handlers
