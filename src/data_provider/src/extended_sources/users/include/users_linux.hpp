#pragma once

#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <memory>
#include <set>

#include "json.hpp"
#include "ipasswd_wrapper.hpp"
#include "isystem_wrapper.hpp"

class UsersProvider
{
    public:
        explicit UsersProvider(
            std::shared_ptr<IPasswdWrapper> passwdWrapper,
            std::shared_ptr<ISystemWrapper> sysWrapper);
        UsersProvider();

        nlohmann::json collect(bool include_remote = true);
        nlohmann::json collectWithConstraints(const std::set<std::string>& usernames,
                                              const std::set<uid_t>& uids,
                                              bool include_remote);

    private:
        nlohmann::json genUserJson(const struct passwd* pwd, const std::string& include_remote);
        nlohmann::json collectLocalUsers(const std::set<std::string>& usernames,
                                         const std::set<uid_t>& uids);
        nlohmann::json collectRemoteUsers(const std::set<std::string>& usernames,
                                          const std::set<uid_t>& uids);

        std::shared_ptr<ISystemWrapper> m_sysWrapper;
        std::shared_ptr<IPasswdWrapper> m_passwdWrapper;
};
