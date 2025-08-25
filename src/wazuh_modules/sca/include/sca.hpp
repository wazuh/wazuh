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

    void init(const std::function<void(const modules_log_level_t, const std::string&)> logFunction);
    void setup(const struct wm_sca_t* sca_config);
    void run();
    void destroy();
    void push(const std::string& data);

private:
    SCA();
    ~SCA() = default;
    SCA(const SCA&) = delete;
    SCA& operator=(const SCA&) = delete;

    std::unique_ptr<SecurityConfigurationAssessment> m_sca;
};
