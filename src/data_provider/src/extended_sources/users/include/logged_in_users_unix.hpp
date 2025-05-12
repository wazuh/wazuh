#pragma once

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "json.hpp"
#include "iutmpx_wrapper.hpp"

class LoggedInUsersProvider
{
    public:
        explicit LoggedInUsersProvider(std::shared_ptr<IUtmpxWrapper> utmpxWrapper);

        LoggedInUsersProvider();

        nlohmann::json collect();

    private:
        std::shared_ptr<IUtmpxWrapper> m_utmpxWrapper;

        static std::mutex utmpxMutex;
        static const std::map<size_t, std::string> loginTypes;
};
