#pragma once

#include "sca.h"
#include <sca_impl.hpp>

#include <functional>
#include <memory>
#include <string>

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

class EXPORTED SCA final
{
    public:
        static SCA& instance()
        {
            static SCA s_instance;
            return s_instance;
        }

        void init();
        void setup(const struct wm_sca_t* sca_config);
        void run();
        void destroy();

        // Sync protocol methods
        bool syncModule(Mode mode, std::chrono::seconds timeout, unsigned int retries, size_t maxEps);
        void persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data);
        bool parseResponseBuffer(const uint8_t* data, size_t length);

    private:
        SCA();
        ~SCA() = default;
        SCA(const SCA&) = delete;
        SCA& operator=(const SCA&) = delete;

        std::unique_ptr<SecurityConfigurationAssessment> m_sca;
};
