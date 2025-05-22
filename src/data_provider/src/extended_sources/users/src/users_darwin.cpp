#include <set>
#include <string>
#include <map>
#include <memory>

#include "users_darwin.hpp"
#include "uuid_wrapper.hpp"
#include "passwd_wrapper_darwin.hpp"
#include "open_directory_utils_wrapper.hpp"

UsersProvider::UsersProvider(
    std::shared_ptr<IPasswdWrapperDarwin> passwdWrapper,
    std::shared_ptr<IUUIDWrapper> uuidWrapper,
    std::shared_ptr<IODUtilsWrapper> odWrapper)
    : m_passwdWrapper(std::move(passwdWrapper)),
      m_uuidWrapper(std::move(uuidWrapper)),
      m_odWrapper(std::move(odWrapper)) {}

UsersProvider::UsersProvider()
    : m_passwdWrapper(std::make_shared<PasswdWrapperDarwin>()),
      m_uuidWrapper(std::make_shared<UUIDWrapper>()),
      m_odWrapper(std::make_shared<ODUtilsWrapper>()) {}

nlohmann::json UsersProvider::collect()
{
    return collectWithConstraints({});
}

nlohmann::json UsersProvider::collectWithConstraints(const std::set<uid_t>& uids)
{
    return collectUsers(uids);
}

nlohmann::json UsersProvider::genUserJson(const struct passwd* pwd)
{
    nlohmann::json user;

    if (!pwd) return user;

    user["username"] = pwd->pw_name ? pwd->pw_name : "";
    user["uid"] = pwd->pw_uid;
    user["gid"] = pwd->pw_gid;
    user["uid_signed"] = static_cast<int32_t>(pwd->pw_uid);
    user["gid_signed"] = static_cast<int32_t>(pwd->pw_gid);
    user["description"] = pwd->pw_gecos ? pwd->pw_gecos : "";
    user["directory"] = pwd->pw_dir ? pwd->pw_dir : "";
    user["shell"] = pwd->pw_shell ? pwd->pw_shell : "";

    uuid_t uuid = {0};
    uuid_string_t uuid_string = {0};

    // From the docs: mbr_uid_to_uuid will always succeed and may return a
    // synthesized UUID with the prefix FFFFEEEE-DDDD-CCCC-BBBB-AAAAxxxxxxxx,
    // where 'xxxxxxxx' is a hex conversion of the UID.
    m_uuidWrapper->uidToUUID(pwd->pw_uid, uuid);
    m_uuidWrapper->uuidToString(uuid, uuid_string);
    user["uuid"] = uuid_string;

    return user;
}

nlohmann::json UsersProvider::collectUsers(const std::set<uid_t>& uids)
{
    nlohmann::json users = nlohmann::json::array();

    if (!uids.empty())
    {
        for (const auto& uid : uids)
        {
            struct passwd* pwd = m_passwdWrapper->getpwuid(uid);

            if (!pwd) continue;

            std::map<std::string, bool> userNames;
            std::string pwUsernameStr{pwd->pw_name};
            m_odWrapper->genEntries("dsRecTypeStandard:Users", &pwUsernameStr, userNames);

            nlohmann::json user = genUserJson(pwd);
            user["is_hidden"] = int(userNames[user["username"]]);

            users.push_back(user);
        }

        return users;
    }

    std::map<std::string, bool> userNames;
    m_odWrapper->genEntries("dsRecTypeStandard:Users", nullptr, userNames);

    for (const auto& [username, isHidden] : userNames)
    {
        // opendirectory and getpwnam are documented as having
        // different code paths. Thus we may see cases where
        // genODEntries produces responses that are not in
        // getpwnam. So with a surfeit of caution we populate some of
        // the row here
        nlohmann::json user;

        struct passwd* pwd = m_passwdWrapper->getpwnam(username.c_str());

        if (pwd != nullptr)
        {
            user = genUserJson(pwd);
        }
        else
        {
            user["username"] = username;
        }

        user["is_hidden"] = static_cast<int>(isHidden);

        users.push_back(user);
    }

    return users;
}
