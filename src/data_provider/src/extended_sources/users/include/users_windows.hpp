#pragma once

#include "users_windows_utils_wrapper.hpp"

#include "json.hpp"

class UsersProvider
{
    public:
        explicit UsersProvider(
            std::shared_ptr<IUsersHelper> m_usersHelper);
        UsersProvider();

        nlohmann::json collect();
        nlohmann::json collectWithConstraints(const std::set<std::uint32_t>& uids);

    private:
        nlohmann::json genUserJson(const User& user);

        std::shared_ptr<IUsersHelper> m_usersHelper;
};
