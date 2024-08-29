
#include "api/catalog/handlers.hpp"

#include <base/json.hpp>
#include <eMessages/catalog.pb.h>
#include <eMessages/eMessage.h>

#include <api/adapter.hpp>

namespace api::catalog::handlers
{

namespace
{

template<typename r_type>
auto checkResourcePermission(const base::Name& name,
                             const std::string& role,
                             const rbac::IRBAC::AuthFn& authFn,
                             const rbac::IRBAC::AuthFn& authSystemFn)
    -> std::optional<decltype(::api::adapter::genericError<r_type>(std::string {}))>
{
    auto isSystemResource = name.parts().size() > 0 && name.parts()[0] == "system";
    auto hasPermission = isSystemResource ? authSystemFn(role) : authFn(role);
    if (hasPermission)
    {
        return std::nullopt;
    }
    return ::api::adapter::genericError<r_type>("Permission denied");
}
} // namespace

namespace eCatalog = ::com::wazuh::api::engine::catalog;
namespace eEngine = ::com::wazuh::api::engine;

api::HandlerSync resourcePost(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac)
{

    auto rbacPtr = rbac.lock();
    if (!rbacPtr)
    {
        throw std::runtime_error {"RBAC instance is not available"};
    }

    auto authFn = rbacPtr->getAuthFn(rbac::Resource::ASSET, rbac::Operation::WRITE);
    auto authSystemFn = rbacPtr->getAuthFn(rbac::Resource::SYSTEM_ASSET, rbac::Operation::WRITE);

    return [catalog, authFn, authSystemFn](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eCatalog::ResourcePost_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        const auto error = !eRequest.has_type()          ? std::make_optional("Missing /type parameter or is invalid")
                           : !eRequest.has_format()      ? std::make_optional("Missing /format parameter or is invalid")
                           : !eRequest.has_content()     ? std::make_optional("Missing /content parameter")
                           : !eRequest.has_namespaceid() ? std::make_optional("Missing /namespace parameter")
                                                         : std::nullopt;
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value());
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {Resource::typeToStr(eRequest.type())};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(std::string {"Invalid /name parameter:"} + e.what());
        }

        // Validate the role
        // {
        //     auto permissionDenied =
        //         checkResourcePermission<ResponseType>(name, eRequest.namespaceid(), authFn, authSystemFn);
        //     if (permissionDenied)
        //     {
        //         return std::move(permissionDenied.value());
        //     }
        // }

        // Build target resource
        catalog::Resource targetResource;
        try
        {
            targetResource = catalog::Resource {name, eRequest.format()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        const auto invalid = catalog->postResource(targetResource, eRequest.namespaceid(), eRequest.content());
        if (invalid)
        {
            return ::api::adapter::genericError<ResponseType>(invalid.value().message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::HandlerSync resourceGet(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac)
{

    auto rbacPtr = rbac.lock();
    if (!rbacPtr)
    {
        throw std::runtime_error {"RBAC instance is not available"};
    }

    auto authFn = rbacPtr->getAuthFn(rbac::Resource::ASSET, rbac::Operation::READ);
    auto authSystemFn = rbacPtr->getAuthFn(rbac::Resource::SYSTEM_ASSET, rbac::Operation::READ);

    return [catalog, authFn, authSystemFn](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eCatalog::ResourceGet_Request;
        using ResponseType = eCatalog::ResourceGet_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        const auto error = !eRequest.has_name()          ? std::make_optional("Missing /name parameter")
                           : !eRequest.has_format()      ? std::make_optional("Missing or invalid /format parameter")
                           : !eRequest.has_namespaceid() ? std::make_optional("Missing /namespaceid parameter")
                                                         : std::nullopt;
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value());
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {eRequest.name()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(std::string {"Invalid /name parameter:"} + e.what());
        }

        // Check permissions
        // {
        //     auto permissionDenied = checkResourcePermission<ResponseType>(name, eRequest.role(), authFn,
        //     authSystemFn); if (permissionDenied)
        //     {
        //         return std::move(permissionDenied.value());
        //     }
        // }

        // Build target resource
        catalog::Resource targetResource;
        try
        {
            targetResource = catalog::Resource {name, eRequest.format()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        // Call catalog
        auto queryRes = catalog->getResource(targetResource, eRequest.namespaceid());

        if (base::isError(queryRes))
        {
            return ::api::adapter::genericError<ResponseType>(base::getError(queryRes).message);
        }
        const auto& content = base::getResponse<std::string>(queryRes);
        ResponseType eResponse;
        eResponse.set_content(content);
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

api::HandlerSync resourceDelete(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac)
{

    auto rbacPtr = rbac.lock();
    if (!rbacPtr)
    {
        throw std::runtime_error {"RBAC instance is not available"};
    }

    auto authFn = rbacPtr->getAuthFn(rbac::Resource::ASSET, rbac::Operation::WRITE);
    auto authSystemFn = rbacPtr->getAuthFn(rbac::Resource::SYSTEM_ASSET, rbac::Operation::WRITE);

    return [catalog, authFn, authSystemFn](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eCatalog::ResourceDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the name
        const auto error = !eRequest.has_name()          ? std::make_optional("Missing /name parameter")
                           : !eRequest.has_namespaceid() ? std::make_optional("Missing /namespaceid parameter")
                                                         : std::nullopt;
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value());
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {eRequest.name()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(fmt::format("Invalid /name parameter: {}", e.what()));
        }

        // Validate the role
        // {
        //     auto permissionDenied = checkResourcePermission<ResponseType>(name, eRequest.namespaceid(), authFn,
        //     authSystemFn); if (permissionDenied)
        //     {
        //         return std::move(permissionDenied.value());
        //     }
        // }

        // Build target resource
        catalog::Resource targetResource;
        try
        {
            targetResource = catalog::Resource {name, catalog::Resource::Format::json};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        auto errorDelete = catalog->deleteResource(targetResource, eRequest.namespaceid());
        if (errorDelete)
        {
            return ::api::adapter::genericError<ResponseType>(errorDelete.value().message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::HandlerSync resourcePut(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac)
{

    auto rbacPtr = rbac.lock();
    if (!rbacPtr)
    {
        throw std::runtime_error {"RBAC instance is not available"};
    }

    auto authFn = rbacPtr->getAuthFn(rbac::Resource::ASSET, rbac::Operation::WRITE);
    auto authSystemFn = rbacPtr->getAuthFn(rbac::Resource::SYSTEM_ASSET, rbac::Operation::WRITE);

    return [catalog, authFn, authSystemFn](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eCatalog::ResourcePut_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        const auto error = !eRequest.has_name()          ? std::make_optional("Missing /name parameter")
                           : !eRequest.has_format()      ? std::make_optional("Missing or invalid /format parameter")
                           : !eRequest.has_content()     ? std::make_optional("Missing /content parameter")
                           : !eRequest.has_namespaceid() ? std::make_optional("Missing /namespaceid parameter")
                                                         : std::nullopt;
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value());
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {eRequest.name()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(std::string {"Invalid /name parameter:"} + e.what());
        }

        // Validate the role
        // {
        //     auto permissionDenied = checkResourcePermission<ResponseType>(name, eRequest.role(), authFn,
        //     authSystemFn); if (permissionDenied)
        //     {
        //         return std::move(permissionDenied.value());
        //     }
        // }

        // Build target resource
        catalog::Resource targetResource;
        try
        {
            targetResource = catalog::Resource {name, eRequest.format()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        const auto invalid = catalog->putResource(targetResource, eRequest.content(), eRequest.namespaceid());
        if (invalid)
        {
            return ::api::adapter::genericError<ResponseType>(invalid.value().message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::HandlerSync resourceValidate(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac)
{

    auto rbacPtr = rbac.lock();
    if (!rbacPtr)
    {
        throw std::runtime_error {"RBAC instance is not available"};
    }

    // TODO: Check if this is the correct permission
    auto authFn = rbacPtr->getAuthFn(rbac::Resource::ASSET, rbac::Operation::READ);
    auto authSystemFn = rbacPtr->getAuthFn(rbac::Resource::SYSTEM_ASSET, rbac::Operation::READ);

    return [catalog, authFn, authSystemFn](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eCatalog::ResourceValidate_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        const auto error = !eRequest.has_name()      ? std::make_optional("Missing /name parameter")
                           : !eRequest.has_format()  ? std::make_optional("Missing or invalid /format parameter")
                           : !eRequest.has_content() ? std::make_optional("Missing /content parameter")
                                                     : std::nullopt;
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value());
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {eRequest.name()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(std::string {"Invalid /name parameter:"} + e.what());
        }

        // Validate the role
        // {
        //     auto permissionDenied = checkResourcePermission<ResponseType>(name, eRequest.namespaceid(), authFn,
        //     authSystemFn); if (permissionDenied)
        //     {
        //         return std::move(permissionDenied.value());
        //     }
        // }

        // Build target resource
        catalog::Resource targetResource;
        try
        {
            targetResource = catalog::Resource {name, eRequest.format()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        const auto invalid = catalog->validateResource(targetResource, eRequest.namespaceid(), eRequest.content());
        if (invalid)
        {
            return ::api::adapter::genericError<ResponseType>(invalid.value().message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::HandlerSync getNamespaces(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac)
{

    auto rbacPtr = rbac.lock();
    if (!rbacPtr)
    {
        throw std::runtime_error {"RBAC instance is not available"};
    }

    // TODO: Check if this is the correct permission
    auto authFn = rbacPtr->getAuthFn(rbac::Resource::ASSET, rbac::Operation::READ);
    auto authSystemFn = rbacPtr->getAuthFn(rbac::Resource::SYSTEM_ASSET, rbac::Operation::READ);

    return [catalog, authFn, authSystemFn](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eCatalog::NamespacesGet_Request;
        using ResponseType = eCatalog::NamespacesGet_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the role
        // {
        //     auto permissionDenied = checkResourcePermission<ResponseType>(name, eRequest.namespaceid(), authFn,
        //     authSystemFn); if (permissionDenied)
        //     {
        //         return std::move(permissionDenied.value());
        //     }
        // }
        ResponseType eResponse;
        const auto namespaces = catalog->getAllNamespaces();
        auto eNamespaces = eResponse.mutable_namespaces();
        for (const auto namespaceid : namespaces)
        {
            eNamespaces->Add()->assign(namespaceid.str());
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);

        // Adapt the response to wazuh api
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

void registerHandlers(std::shared_ptr<Catalog> catalog, std::shared_ptr<api::Api> api)
{
    const bool ok =
        api->registerHandler("catalog.resource/post", Api::convertToHandlerAsync(resourcePost(catalog, api->getRBAC())))
        && api->registerHandler("catalog.resource/get",
                                Api::convertToHandlerAsync(resourceGet(catalog, api->getRBAC())))
        && api->registerHandler("catalog.resource/put",
                                Api::convertToHandlerAsync(resourcePut(catalog, api->getRBAC())))
        && api->registerHandler("catalog.resource/delete",
                                Api::convertToHandlerAsync(resourceDelete(catalog, api->getRBAC())))
        && api->registerHandler("catalog.resource/validate",
                                Api::convertToHandlerAsync(resourceValidate(catalog, api->getRBAC())))
        && api->registerHandler("catalog.namespaces/get",
                                Api::convertToHandlerAsync(getNamespaces(catalog, api->getRBAC())));

    if (!ok)
    {
        throw std::runtime_error("Failed to register catalog handlers");
    }
}
} // namespace api::catalog::handlers
