#include <api/catalog/handlers.hpp>

#include <eMessages/catalog.pb.h>

namespace api::catalog::handlers
{
namespace eCatalog = adapter::eEngine::catalog;
namespace eEngine = adapter::eEngine;

adapter::RouteHandler resourcePost(const std::shared_ptr<ICatalog>& catalog)
{
    return [weakCatalog = std::weak_ptr<ICatalog> {catalog}](const httplib::Request& req, httplib::Response& res)
    {
        using RequestType = eCatalog::ResourcePost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ICatalog>(req, weakCatalog);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [catalog, protoReq] = adapter::getRes(result);

        // Validate the params request
        const auto error = !protoReq.has_type()          ? std::make_optional("Missing /type parameter or is invalid")
                           : !protoReq.has_format()      ? std::make_optional("Missing /format parameter or is invalid")
                           : !protoReq.has_content()     ? std::make_optional("Missing /content parameter")
                           : !protoReq.has_namespaceid() ? std::make_optional("Missing /namespace parameter")
                                                         : std::nullopt;
        if (error)
        {
            res = adapter::userErrorResponse<ResponseType>(error.value());
            return;
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {Resource::typeToStr(protoReq.type())};
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format("Invalid /name parameter: {}", e.what()));
            return;
        }

        // Build target resource
        Resource targetResource;
        try
        {
            targetResource = Resource {name, protoReq.format()};
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(e.what());
            return;
        }

        const auto invalid = catalog->postResource(targetResource, protoReq.namespaceid(), protoReq.content());
        if (invalid)
        {
            res = adapter::userErrorResponse<ResponseType>(invalid.value().message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler resourceGet(const std::shared_ptr<ICatalog>& catalog)
{
    return [weakCatalog = std::weak_ptr<ICatalog> {catalog}](const httplib::Request& req, httplib::Response& res)
    {
        using RequestType = eCatalog::ResourceGet_Request;
        using ResponseType = eCatalog::ResourceGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ICatalog>(req, weakCatalog);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [catalog, protoReq] = adapter::getRes(result);

        // Validate the params request
        const auto error = !protoReq.has_name()          ? std::make_optional("Missing /name parameter")
                           : !protoReq.has_format()      ? std::make_optional("Missing or invalid /format parameter")
                           : !protoReq.has_namespaceid() ? std::make_optional("Missing /namespaceid parameter")
                                                         : std::nullopt;
        if (error)
        {
            res = adapter::userErrorResponse<ResponseType>(error.value());
            return;
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {protoReq.name()};
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format("Invalid /name parameter: {}", e.what()));
            return;
        }

        // Build target resource
        Resource targetResource;
        try
        {
            targetResource = Resource {name, protoReq.format()};
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(e.what());
            return;
        }

        // Call catalog
        auto queryRes = catalog->getResource(targetResource, protoReq.namespaceid());

        if (base::isError(queryRes))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(queryRes).message);
            return;
        }
        const auto& content = base::getResponse<std::string>(queryRes);
        ResponseType eResponse;
        eResponse.set_content(content);
        eResponse.set_status(eEngine::ReturnStatus::OK);

        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler resourceDelete(const std::shared_ptr<ICatalog>& catalog)
{
    return [weakCatalog = std::weak_ptr<ICatalog> {catalog}](const httplib::Request& req, httplib::Response& res)
    {
        using RequestType = eCatalog::ResourceDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ICatalog>(req, weakCatalog);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [catalog, protoReq] = adapter::getRes(result);

        // Validate the params request
        const auto error = !protoReq.has_name()          ? std::make_optional("Missing /name parameter")
                           : !protoReq.has_namespaceid() ? std::make_optional("Missing /namespaceid parameter")
                                                         : std::nullopt;
        if (error)
        {
            res = adapter::userErrorResponse<ResponseType>(error.value());
            return;
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {protoReq.name()};
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format("Invalid /name parameter: {}", e.what()));
            return;
        }

        // Build target resource
        Resource targetResource;
        try
        {
            targetResource = Resource {name, Resource::Format::json};
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(e.what());
            return;
        }

        const auto invalid = catalog->deleteResource(targetResource, protoReq.namespaceid());
        if (invalid)
        {
            res = adapter::userErrorResponse<ResponseType>(invalid.value().message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler resourcePut(const std::shared_ptr<ICatalog>& catalog)
{
    return [weakCatalog = std::weak_ptr<ICatalog> {catalog}](const httplib::Request& req, httplib::Response& res)
    {
        using RequestType = eCatalog::ResourcePut_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ICatalog>(req, weakCatalog);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [catalog, protoReq] = adapter::getRes(result);

        // Validate the params request
        const auto error = !protoReq.has_name()          ? std::make_optional("Missing /name parameter")
                           : !protoReq.has_format()      ? std::make_optional("Missing or invalid /format parameter")
                           : !protoReq.has_content()     ? std::make_optional("Missing /content parameter")
                           : !protoReq.has_namespaceid() ? std::make_optional("Missing /namespaceid parameter")
                                                         : std::nullopt;
        if (error)
        {
            res = adapter::userErrorResponse<ResponseType>(error.value());
            return;
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {protoReq.name()};
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format("Invalid /name parameter: {}", e.what()));
            return;
        }

        // Build target resource
        Resource targetResource;
        try
        {
            targetResource = Resource {name, protoReq.format()};
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(e.what());
            return;
        }

        const auto invalid = catalog->putResource(targetResource, protoReq.content(), protoReq.namespaceid());
        if (invalid)
        {
            res = adapter::userErrorResponse<ResponseType>(invalid.value().message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler resourceValidate(const std::shared_ptr<ICatalog>& catalog)
{
    return [weakCatalog = std::weak_ptr<ICatalog> {catalog}](const httplib::Request& req, httplib::Response& res)
    {
        using RequestType = eCatalog::ResourceValidate_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ICatalog>(req, weakCatalog);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [catalog, protoReq] = adapter::getRes(result);

        // Validate the params request
        const auto error = !protoReq.has_name()          ? std::make_optional("Missing /name parameter")
                           : !protoReq.has_format()      ? std::make_optional("Missing or invalid /format parameter")
                           : !protoReq.has_content()     ? std::make_optional("Missing /content parameter")
                           : !protoReq.has_namespaceid() ? std::make_optional("Missing /namespaceid parameter")
                                                         : std::nullopt;
        if (error)
        {
            res = adapter::userErrorResponse<ResponseType>(error.value());
            return;
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {protoReq.name()};
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format("Invalid /name parameter: {}", e.what()));
            return;
        }

        // Build target resource
        Resource targetResource;
        try
        {
            targetResource = Resource {name, protoReq.format()};
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(e.what());
            return;
        }

        // Call catalog
        auto queryRes = catalog->validateResource(targetResource, protoReq.namespaceid(), protoReq.content());

        if (base::isError(queryRes))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(queryRes).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler getNamespaces(const std::shared_ptr<ICatalog>& catalog)
{
    return [weakCatalog = std::weak_ptr<ICatalog> {catalog}](const httplib::Request& req, httplib::Response& res)
    {
        using RequestType = eCatalog::NamespacesGet_Request;
        using ResponseType = eCatalog::NamespacesGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ICatalog>(req, weakCatalog);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [catalog, protoReq] = adapter::getRes(result);

        // Call catalog
        ResponseType eResponse;
        const auto namespaces = catalog->getAllNamespaces();
        auto eNamespaces = eResponse.mutable_namespaces();
        for (const auto& namespaceid : namespaces)
        {
            eNamespaces->Add()->assign(namespaceid.str());
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

} // namespace api::catalog::handlers
