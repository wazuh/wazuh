#ifndef _RBAC_RBAC_HPP
#define _RBAC_RBAC_HPP

#include <stdexcept>
#include <unordered_map>

#include <fmt/format.h>

#include <rbac/irbac.hpp>
#include <rbac/model.hpp>
#include <store/istore.hpp>

namespace rbac
{

namespace detail
{
constexpr auto MODEL_NAME = "internal/rbac/model/0";
} // namespace detail

class RBAC : public IRBAC
{
private:
    std::unordered_map<std::string, Role> m_roles;
    // std::unordered_map<std::string, Subject> m_subjects;

    std::weak_ptr<store::IStore> m_store;

    void loadModel()
    {
        const auto store = m_store.lock();
        if (!store)
        {
            throw std::runtime_error("Error loading model: Store is expired");
        }

        auto model = store->get(detail::MODEL_NAME);
        if (std::holds_alternative<base::Error>(model))
        {
            throw std::runtime_error(fmt::format("Error loading model: {}", std::get<base::Error>(model).message));
        }

        auto modelJson = std::get<json::Json>(model);

        auto roles = modelJson.getObject();
        if (!roles)
        {
            throw std::runtime_error("Error loading model: Expected object");
        }

        for (const auto& [roleName, permissionsJson] : roles.value())
        {
            m_roles[roleName] = Role::fromJson(roleName, permissionsJson);
        }
    }

    void saveModel() const
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

        auto error = store->update(detail::MODEL_NAME, modelJson);
        if (error)
        {
            throw std::runtime_error(fmt::format("Error saving model: {}", error.value().message));
        }
    }

    void defaultModel()
    {
        auto permissions = std::unordered_set<Permission>();

        permissions.insert(Permission(Resource::ASSET, Operation::READ));
        m_roles["user-consumer"] = Role("user-consumer", permissions);


        permissions.insert(Permission(Resource::ASSET, Operation::WRITE));
        m_roles["user-developer"] = Role("user-developer", permissions);

        permissions.insert(Permission(Resource::SYSTEM_ASSET, Operation::READ));
        permissions.insert(Permission(Resource::SYSTEM_ASSET, Operation::WRITE));
        m_roles["system"] = Role("system", permissions);
    }

public:

    RBAC(std::weak_ptr<store::IStore> store)
        : m_store(store)
    {
        try {
            loadModel();
        } catch (const std::runtime_error& e) {
            LOG_WARNING("Error loading model: {}. Loading default model", e.what());
            defaultModel();
            // saveModel();
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
};
} // namespace rbac

#endif // _RBAC_RBAC_HPP
