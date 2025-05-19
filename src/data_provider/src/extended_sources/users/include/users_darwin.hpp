#include <map>
#include <memory>
#include <set>
#include <string>

#include "json.hpp"

#include "iuuid_wrapper.hpp"
#include "iopen_directory_utils_wrapper.hpp"
#include "ipasswd_wrapper_darwin.hpp"

class UsersProvider
{
    public:
        explicit UsersProvider(
            std::shared_ptr<IPasswdWrapperDarwin> passwdWrapper,
            std::shared_ptr<IUUIDWrapper> uuidWrapper,
            std::shared_ptr<IODUtilsWrapper> odWrapper);

        UsersProvider();

        nlohmann::json collect();

        nlohmann::json collectWithConstraints(const std::set<uid_t>& uids);

    private:
        nlohmann::json genUserJson(const struct passwd* pwd);

        nlohmann::json collectUsers(const std::set<uid_t>& uids);

        std::shared_ptr<IPasswdWrapperDarwin> m_passwdWrapper;
        std::shared_ptr<IUUIDWrapper> m_uuidWrapper;
        std::shared_ptr<IODUtilsWrapper> m_odWrapper;
};
