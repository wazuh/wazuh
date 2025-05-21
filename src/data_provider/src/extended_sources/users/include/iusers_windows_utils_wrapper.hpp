#pragma once

#include <limits>
#include <set>
#include <string>
#include <vector>

struct User
{
    std::uint32_t generation{0};
    std::uint32_t uid{std::numeric_limits<std::uint32_t>::max()};
    std::uint32_t gid{std::numeric_limits<std::uint32_t>::max()};
    std::string sid;
    std::string username;
    std::string description;
    std::string type;
    std::string directory;

    bool operator==(const User& other) const
    {
        return uid == other.uid && gid == other.gid && sid == other.sid &&
               username == other.username && description == other.description &&
               type == other.type && directory == other.directory;
    }
};

class IUsersHelper
{
    public:
        virtual ~IUsersHelper() = default;

        virtual std::string getUserShell(const std::string& sid) = 0;
        virtual std::vector<User> processLocalAccounts(std::set<std::string>& processed_sids) = 0;
        virtual std::vector<User> processRoamingProfiles(std::set<std::string>& processed_sids) = 0;
};
