#include <api/geo/handlers.hpp>

#include <eMessages/geo.pb.h>
#include <google/protobuf/util/json_util.h>

namespace api::geo::handlers
{
namespace eGeo = adapter::eEngine::geo;
namespace eEngine = adapter::eEngine;

adapter::RouteHandler getDb(const std::shared_ptr<::geo::IManager>& geoManager)
{
    return [weakGeoManager = std::weak_ptr<::geo::IManager> {geoManager}](const auto& req, auto& res)
    {
        using RequestType = eGeo::DbGet_Request;
        using ResponseType = eGeo::DbGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::geo::IManager>(req, weakGeoManager);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [geoManager, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto ip = protoReq.ip();
        if (ip.empty())
        {
            res = adapter::userErrorResponse<ResponseType>("IP cannot be empty");
            return;
        }

        // Get all data for the IP from CITY database
        std::string cityJsonStr = "{}";
        const auto cityLocatorResult = geoManager->getLocator(::geo::Type::CITY);
        if (!base::isError(cityLocatorResult))
        {
            auto cityLocator = base::getResponse(cityLocatorResult);
            const auto cityJsonResult = cityLocator->getAll(ip);
            if (!base::isError(cityJsonResult))
            {
                cityJsonStr = base::getResponse(cityJsonResult).str();
            }
        }

        // Get all data for the IP from ASN database
        std::string asnJsonStr = "{}";
        const auto asnLocatorResult = geoManager->getLocator(::geo::Type::ASN);
        if (!base::isError(asnLocatorResult))
        {
            auto asnLocator = base::getResponse(asnLocatorResult);
            const auto asnJsonResult = asnLocator->getAll(ip);
            if (!base::isError(asnJsonResult))
            {
                asnJsonStr = base::getResponse(asnJsonResult).str();
            }
        }

        // Build ECS-compliant response with "geo" and "as" objects
        std::string ecsJsonStr = R"({"geo":)" + cityJsonStr + R"(,"as":)" + asnJsonStr + "}";

        // Convert JSON string to google::protobuf::Struct using eMessageFromJson
        auto structOrErr = eMessage::eMessageFromJson<google::protobuf::Struct>(ecsJsonStr);
        if (std::holds_alternative<base::Error>(structOrErr))
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format("Error converting JSON to protobuf Struct: {}",
                                                                       std::get<base::Error>(structOrErr).message));
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        *eResponse.mutable_data() = std::get<google::protobuf::Struct>(structOrErr);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler listDb(const std::shared_ptr<::geo::IManager>& geoManager)
{
    return [weakGeoManager = std::weak_ptr<::geo::IManager> {geoManager}](const auto& req, auto& res)
    {
        using RequestType = eGeo::DbList_Request;
        using ResponseType = eGeo::DbList_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::geo::IManager>(req, weakGeoManager);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [geoManager, protoReq] = adapter::getRes(result);

        // Get the databases
        const auto dbs = geoManager->listDbs();
        ResponseType response;

        for (const auto& db : dbs)
        {
            auto* dbResponse = response.add_entries();
            dbResponse->set_name(db.name);
            dbResponse->set_path(db.path);
            dbResponse->set_hash(db.hash);
            dbResponse->set_createdat(db.createdAt);
            dbResponse->set_type(::geo::typeName(db.type));
        }

        response.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(response);
    };
}

} // namespace api::geo::handlers
