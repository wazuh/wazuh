#ifndef _RBAC_RBAC_HPP
#define _RBAC_RBAC_HPP

#include <map>
#include <optional>
#include <stdexcept>

#include <fmt/format.h>

#include <base/logging.hpp>
#include <rbac/irbac.hpp>
#include <rbac/model.hpp>
#include <store/istore.hpp>

namespace rbac
{

namespace detail
{
constexpr auto MODEL_NAME = "internal/rbac/model/0";
} // namespace detail

namespace defaultModel
{
constexpr auto ROLE_SYSTEM = "system";
constexpr auto ROLE_USER = "user";
constexpr auto ROLE_WAZUH = "wazuh";
} // namespace defaultModel

class RBAC : public IRBAC
{
private:
    std::map<std::string, Role> m_roles;
    // std::unordered_map<std::string, Subject> m_subjects;

    std::weak_ptr<store::IStoreInternal> m_store;

    base::OptError loadModel()
    {
        const auto store = m_store.lock();
        if (!store)
        {
            throw std::runtime_error("Store expired when loading RBAC model");
        }

        auto model = store->readInternalDoc(detail::MODEL_NAME);
        if (base::isError(model))
        {
            return base::getError(model);
        }

        auto modelJson = base::getResponse<json::Json>(model);

        auto roles = modelJson.getObject();
        if (!roles || roles.value().empty())
        {
            return base::Error {"Expected RBAC model to be an object with at least one role"};
        }

        for (const auto& [roleName, permissionsJson] : roles.value())
        {
            auto role = Role::fromJson(roleName, permissionsJson);
            if (base::isError(role))
            {
                return base::getError(role);
            }
            m_roles[roleName] = std::get<Role>(role);
        }

        return std::nullopt;
    }

    base::OptError saveModel() const
    {
        json::Json modelJson;
        modelJson.setObject();

        for (const auto& [roleName, role] : m_roles)
        {
            auto roleJson = role.toJson();
            modelJson.merge(false, roleJson);
        }

        const auto store = m_store.lock();
        if (!store)
        {
            throw std::runtime_error("Error saving model: Store is expired");
        }

        // Update model if it exists, otherwise create it
        auto error = store->upsertInternalDoc(detail::MODEL_NAME, modelJson);
        if (error)
        {
            return error;
        }

        return std::nullopt;
    }

    void defaultModel()
    {
        auto permissions = std::set<Permission>();

        permissions.insert(Permission(Resource::ASSET, Operation::READ));
        m_roles[defaultModel::ROLE_USER] = Role(defaultModel::ROLE_USER, permissions);

        permissions.insert(Permission(Resource::ASSET, Operation::WRITE));
        m_roles[defaultModel::ROLE_WAZUH] = Role(defaultModel::ROLE_WAZUH, permissions);

        permissions.insert(Permission(Resource::SYSTEM_ASSET, Operation::READ));
        permissions.insert(Permission(Resource::SYSTEM_ASSET, Operation::WRITE));
        m_roles[defaultModel::ROLE_SYSTEM] = Role(defaultModel::ROLE_SYSTEM, permissions);
    }

public:
    RBAC(std::weak_ptr<store::IStoreInternal> store)
        : m_store(store)
    {
        auto error = loadModel();
        if (error)
        {
            LOG_WARNING("Could not load RBAC model, using default model: {}", error->message);
            defaultModel();

            auto saveError = saveModel();
            if (saveError)
            {
                LOG_WARNING("Could not save RBAC model: {}", saveError->message);
            }
        }
    }

    AuthFn getAuthFn(Resource res, Operation op) const override
    {
        auto permission = Permission(res, op);

        return [permission, roles = m_roles](const std::string& roleName)
        {
            auto role = roles.find(roleName);
            if (role == roles.end())
            {
                return false;
            }

            if (role->second.getPermissions().find(permission) == role->second.getPermissions().end())
            {
                return false;
            }

            return true;
        };
    }

    void shutdown() noexcept
    {
        try
        {
            auto error = saveModel();
            if (error)
            {
                LOG_ERROR("Could not save RBAC model: {}", error->message);
            }
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Could not save RBAC model: {}", e.what());
        }
    }
};
} // namespace rbac

#endif // _RBAC_RBAC_HPP
