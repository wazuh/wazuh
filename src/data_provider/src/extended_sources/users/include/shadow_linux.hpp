#pragma once

#include "json.hpp"
#include "ishadow_wrapper.hpp"

class ShadowProvider
{
    public:
        explicit ShadowProvider(std::shared_ptr<IShadowWrapper> shadowWrapper);

        ShadowProvider();

        nlohmann::json collect();

    private:
        std::shared_ptr<IShadowWrapper> m_shadowWrapper;

        // static std::mutex utmpxMutex;
};
